use std::path::Path;

use flate2::{Compression, write::GzEncoder};
use snafu::{ResultExt, Whatever};
use tracing::{Instrument, info, info_span};

use crate::{BrewTarget, package_meta, run_cmd, run_cmd_quiet, sha256_file, target_dir};

const CARGO_NAME: &str = "genmeta";

/// Distribution package name (differs from the cargo crate name).
const PACKAGE_NAME: &str = "gmutils";

/// Download URL prefix for Homebrew archives.
const BREW_DL_URL: &str = "https://download.genmeta.net/homebrew";

fn brew_on_block(triple: &str) -> Result<&'static str, Whatever> {
    match triple {
        "aarch64-apple-darwin" => Ok("on_arm"),
        "x86_64-apple-darwin" => Ok("on_intel"),
        _ => snafu::whatever!("unsupported brew target triple: {triple}"),
    }
}

async fn check_cargo() -> Result<(), Whatever> {
    run_cmd_quiet(tokio::process::Command::new("which").arg("cargo")).await
}

/// Create a tar.gz archive from a staging directory.
fn create_tar_gz(staging: &Path, output: &Path) -> Result<(), Whatever> {
    let file = std::fs::File::create(output)
        .whatever_context(format!("failed to create {}", output.display()))?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = tar::Builder::new(encoder);
    archive
        .append_dir_all(".", staging)
        .whatever_context("failed to append files to tar archive")?;
    archive
        .finish()
        .whatever_context("failed to finalize tar archive")?;
    Ok(())
}

struct ArchiveInfo {
    triple: String,
    archive_name: String,
    sha256: String,
}

fn generate_formula(
    name: &str,
    description: &str,
    version: &str,
    homepage: &str,
    license: &str,
    archives: &[ArchiveInfo],
    content: &str,
) -> Result<String, Whatever> {
    let class_name = {
        let mut chars = name.chars();
        match chars.next() {
            Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            None => String::new(),
        }
    };
    let desc = description.replace('"', "\\\"");

    let mut lines = vec![
        format!("class {class_name} < Formula"),
        format!("  desc \"{desc}\""),
        format!("  version \"{version}\""),
        format!("  homepage \"{homepage}\""),
    ];
    if !license.is_empty() {
        lines.push(format!("  license \"{license}\""));
    }
    lines.push(String::new());

    for info in archives {
        let block = brew_on_block(&info.triple)?;
        lines.extend([
            format!("  {block} do"),
            format!("    url \"{BREW_DL_URL}/{}\"", info.archive_name),
            format!("    sha256 \"{}\"", info.sha256),
            "  end".to_string(),
            String::new(),
        ]);
    }

    lines.push(content.trim_end().to_string());
    lines.push("end".to_string());
    lines.push(String::new());

    Ok(lines.join("\n"))
}

pub async fn run(targets: &[BrewTarget]) -> Result<(), Whatever> {
    info!(target_count = targets.len(), "starting brew dist build");
    let meta = package_meta(CARGO_NAME)?;
    let target_dir = target_dir()?;
    let workspace = std::env::current_dir().whatever_context("failed to get cwd")?;

    let mut tasks = tokio::task::JoinSet::new();
    for &target in targets {
        let version = meta.version.clone();
        let target_dir = target_dir.clone();
        let workspace = workspace.clone();
        let triple = target.triple();
        info!(triple, "queued brew target build");
        let span = info_span!("brew", triple);
        tasks.spawn(
            async move { build_one(triple, &version, &target_dir, &workspace).await }
                .instrument(span),
        );
    }

    let mut archives = Vec::new();
    info!("waiting for brew target builds to finish");
    while let Some(result) = tasks.join_next().await {
        archives.push(result.whatever_context("brew build task panicked")??);
    }

    // Generate aggregated formula
    let content_path = workspace.join("genmeta").join("homebrew_content.rb");
    let content = tokio::fs::read_to_string(&content_path)
        .await
        .whatever_context(format!("failed to read {}", content_path.display()))?;

    let formula = generate_formula(
        PACKAGE_NAME,
        &meta.description,
        &meta.version,
        &meta.homepage,
        &meta.license,
        &archives,
        &content,
    )?;

    let formula_dir = target_dir.join("common").join("brew");
    tokio::fs::create_dir_all(&formula_dir)
        .await
        .whatever_context(format!("failed to create {}", formula_dir.display()))?;
    let formula_path = formula_dir.join(format!("{PACKAGE_NAME}.rb"));
    tokio::fs::write(&formula_path, &formula)
        .await
        .whatever_context(format!("failed to write {}", formula_path.display()))?;
    info!(path = %formula_path.display(), "produced formula");
    info!("finished brew dist build");

    Ok(())
}

async fn build_one(
    triple: &str,
    version: &str,
    target_dir: &Path,
    workspace: &Path,
) -> Result<ArchiveInfo, Whatever> {
    info!(triple, "checking cargo availability");
    check_cargo().await?;

    // Build
    info!(triple, "starting cargo build for brew target");
    run_cmd(tokio::process::Command::new("cargo").args([
        "build",
        "--release",
        "--target",
        triple,
        "--bin",
        CARGO_NAME,
    ]))
    .await
    .whatever_context(format!("cargo build failed for {triple}"))?;
    info!(triple, "cargo build finished for brew target");

    // Stage
    let brew_dir = target_dir.join(triple).join("release").join("brew");
    let staging = brew_dir.join("staging");
    let _ = tokio::fs::remove_dir_all(&staging).await;
    tokio::fs::create_dir_all(&staging)
        .await
        .whatever_context(format!("failed to create {}", staging.display()))?;

    // Copy binaries
    let binary = target_dir.join(triple).join("release").join(CARGO_NAME);
    tokio::fs::copy(&binary, staging.join(CARGO_NAME))
        .await
        .whatever_context(format!("failed to copy {}", binary.display()))?;
    tokio::fs::copy(
        workspace.join("genmeta-ssh.sh"),
        staging.join("genmeta-ssh.sh"),
    )
    .await
    .whatever_context("failed to copy genmeta-ssh.sh")?;

    // Create tar.gz
    let archive_name = format!("{PACKAGE_NAME}-{version}-{triple}.tar.gz");
    let archive_path = brew_dir.join(&archive_name);
    {
        let staging = staging.clone();
        let archive_path = archive_path.clone();
        tokio::task::spawn_blocking(move || create_tar_gz(&staging, &archive_path))
            .await
            .whatever_context("tar task panicked")??;
    }

    // Cleanup staging
    let _ = tokio::fs::remove_dir_all(&staging).await;

    // Hash
    let sha = sha256_file(&archive_path).await?;

    info!(path = %archive_path.display(), "produced archive");
    Ok(ArchiveInfo {
        triple: triple.to_string(),
        archive_name,
        sha256: sha,
    })
}
