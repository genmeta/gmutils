use std::{fs, path::Path};

use flate2::{Compression, write::GzEncoder};
use snafu::{ResultExt, Whatever};
use tracing::info;
use xshell::{Shell, cmd};

use crate::{BrewTarget, package_meta, sha256_file, target_dir};

const CARGO_NAME: &str = "genmeta";

/// Download URL prefix for Homebrew archives.
const BREW_DL_URL: &str = "https://download.genmeta.net/homebrew";

fn brew_on_block(triple: &str) -> Result<&'static str, Whatever> {
    match triple {
        "aarch64-apple-darwin" => Ok("on_arm"),
        "x86_64-apple-darwin" => Ok("on_intel"),
        _ => snafu::whatever!("unsupported brew target triple: {triple}"),
    }
}

fn check_cargo(sh: &Shell) -> Result<(), Whatever> {
    cmd!(sh, "which cargo")
        .quiet()
        .run()
        .whatever_context("cargo not found in PATH")?;
    Ok(())
}

/// Create a tar.gz archive from a staging directory.
fn create_tar_gz(staging: &Path, output: &Path) -> Result<(), Whatever> {
    let file = fs::File::create(output)
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

pub fn run(targets: &[BrewTarget]) -> Result<(), Whatever> {
    let meta = package_meta(CARGO_NAME)?;
    let target_dir = target_dir()?;
    let workspace = std::env::current_dir().whatever_context("failed to get cwd")?;

    let archives: Vec<ArchiveInfo> = std::thread::scope(|s| {
        let handles: Vec<_> = targets
            .iter()
            .map(|&target| {
                let meta_version = &meta.version;
                let target_dir = &target_dir;
                let workspace = &workspace;
                let triple = target.triple();
                s.spawn(move || build_one(triple, meta_version, target_dir, workspace))
            })
            .collect();

        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Result<Vec<_>, _>>()
    })?;

    // Generate aggregated formula
    let content_path = workspace.join("genmeta").join("homebrew_content.rb");
    let content = fs::read_to_string(&content_path)
        .whatever_context(format!("failed to read {}", content_path.display()))?;

    let formula = generate_formula(
        CARGO_NAME,
        &meta.description,
        &meta.version,
        &meta.homepage,
        &meta.license,
        &archives,
        &content,
    )?;

    let formula_dir = target_dir.join("common").join("brew");
    fs::create_dir_all(&formula_dir)
        .whatever_context(format!("failed to create {}", formula_dir.display()))?;
    let formula_path = formula_dir.join(format!("{CARGO_NAME}.rb"));
    fs::write(&formula_path, &formula)
        .whatever_context(format!("failed to write {}", formula_path.display()))?;
    info!(path = %formula_path.display(), "produced formula");

    Ok(())
}

fn build_one(
    triple: &str,
    version: &str,
    target_dir: &std::path::Path,
    workspace: &std::path::Path,
) -> Result<ArchiveInfo, Whatever> {
    let _span = tracing::info_span!("brew", triple).entered();

    let sh = Shell::new().whatever_context("failed to create shell")?;
    check_cargo(&sh)?;

    // Build
    cmd!(
        sh,
        "cargo build --release --target {triple} --bin {CARGO_NAME}"
    )
    .run()
    .whatever_context(format!("cargo build failed for {triple}"))?;

    // Stage
    let brew_dir = target_dir.join(triple).join("release").join("brew");
    let staging = brew_dir.join("staging");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)
        .whatever_context(format!("failed to create {}", staging.display()))?;

    // Copy binaries
    let binary = target_dir.join(triple).join("release").join(CARGO_NAME);
    fs::copy(&binary, staging.join(CARGO_NAME))
        .whatever_context(format!("failed to copy {}", binary.display()))?;
    fs::copy(
        workspace.join("genmeta-ssh.sh"),
        staging.join("genmeta-ssh.sh"),
    )
    .whatever_context("failed to copy genmeta-ssh.sh")?;

    // Create tar.gz
    let archive_name = format!("{CARGO_NAME}-{version}-{triple}.tar.gz");
    let archive_path = brew_dir.join(&archive_name);
    create_tar_gz(&staging, &archive_path)?;

    // Cleanup staging
    let _ = fs::remove_dir_all(&staging);

    // Hash
    let sha = sha256_file(&archive_path)?;

    info!(path = %archive_path.display(), "produced archive");
    Ok(ArchiveInfo {
        triple: triple.to_string(),
        archive_name,
        sha256: sha,
    })
}
