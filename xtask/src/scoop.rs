#![allow(dead_code)]

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use snafu::{OptionExt, ResultExt, Whatever};
use tracing::{Instrument, info, info_span};

use crate::{ScoopTarget, package_meta, run_cmd, run_cmd_quiet, target_dir};

const CARGO_NAME: &str = "genmeta";

/// Distribution package name (differs from the cargo crate name).
const PACKAGE_NAME: &str = "gmutils";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoopArchive {
    pub target: String,
    pub archive_name: String,
    pub path: PathBuf,
}

async fn check_cargo_xwin() -> Result<(), Whatever> {
    run_cmd_quiet(tokio::process::Command::new("which").arg("cargo-xwin")).await
}

/// Create a zip archive from a staging directory.
fn create_zip(staging: &Path, output: &Path) -> Result<(), Whatever> {
    let file = std::fs::File::create(output)
        .whatever_context(format!("failed to create {}", output.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for entry in std::fs::read_dir(staging).whatever_context("failed to read staging dir")? {
        let entry = entry.whatever_context("failed to read dir entry")?;
        let path = entry.path();
        if path.is_file() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .whatever_context("failed to read zip entry file name as utf-8")?
                .to_owned();
            zip.start_file(&name, options)
                .whatever_context(format!("failed to start zip entry {name}"))?;
            let data = std::fs::read(&path)
                .whatever_context(format!("failed to read {}", path.display()))?;
            zip.write_all(&data)
                .whatever_context(format!("failed to write zip entry {name}"))?;
        }
    }

    zip.finish()
        .whatever_context("failed to finalize zip archive")?;
    Ok(())
}

pub async fn run(targets: &[ScoopTarget]) -> Result<Vec<ScoopArchive>, Whatever> {
    info!(target_count = targets.len(), "starting scoop dist build");
    let meta = package_meta(CARGO_NAME)?;
    let target_dir = target_dir()?;
    let workspace = std::env::current_dir().whatever_context("failed to get cwd")?;

    let mut tasks = tokio::task::JoinSet::new();
    for &target in targets {
        let version = meta.version.clone();
        let target_dir = target_dir.clone();
        let workspace = workspace.clone();
        let triple = target.triple();
        info!(triple, "queued scoop target build");
        let span = info_span!("scoop", triple);
        tasks.spawn(
            async move { build_one(triple, &version, &target_dir, &workspace).await }
                .instrument(span),
        );
    }

    info!("waiting for scoop target builds to finish");
    let mut archives = Vec::new();
    while let Some(result) = tasks.join_next().await {
        archives.push(result.whatever_context("scoop build task panicked")??);
    }
    archives.sort_by(|left, right| left.target.cmp(&right.target));
    info!("finished scoop dist build");

    Ok(archives)
}

async fn build_one(
    triple: &str,
    version: &str,
    target_dir: &Path,
    workspace: &Path,
) -> Result<ScoopArchive, Whatever> {
    info!(triple, "checking cargo-xwin availability");
    check_cargo_xwin().await?;

    // Build
    info!(triple, "starting cargo-xwin build for scoop target");
    run_cmd(tokio::process::Command::new("cargo-xwin").args([
        "build",
        "--release",
        "--target",
        triple,
        "--bin",
        CARGO_NAME,
    ]))
    .await
    .whatever_context(format!("cargo xwin build failed for {triple}"))?;
    info!(triple, "cargo-xwin build finished for scoop target");

    // Stage
    let scoop_dir = target_dir.join(triple).join("release").join("scoop");
    let staging = scoop_dir.join("staging");
    let _ = tokio::fs::remove_dir_all(&staging).await;
    tokio::fs::create_dir_all(&staging)
        .await
        .whatever_context(format!("failed to create {}", staging.display()))?;

    // Copy artifacts
    let binary = target_dir
        .join(triple)
        .join("release")
        .join(format!("{CARGO_NAME}.exe"));
    tokio::fs::copy(&binary, staging.join(format!("{CARGO_NAME}.exe")))
        .await
        .whatever_context(format!("failed to copy {}", binary.display()))?;
    tokio::fs::copy(
        workspace.join("genmeta-ssh.bat"),
        staging.join("genmeta-ssh.bat"),
    )
    .await
    .whatever_context("failed to copy genmeta-ssh.bat")?;

    // Create zip
    let archive_name = format!("{PACKAGE_NAME}-{version}-{triple}.zip");
    let archive_path = scoop_dir.join(&archive_name);
    {
        let staging = staging.clone();
        let archive_path = archive_path.clone();
        tokio::task::spawn_blocking(move || create_zip(&staging, &archive_path))
            .await
            .whatever_context("zip task panicked")??;
    }

    // Cleanup staging
    let _ = tokio::fs::remove_dir_all(&staging).await;

    info!(path = %archive_path.display(), "produced archive");
    Ok(ScoopArchive {
        target: triple.to_string(),
        archive_name,
        path: archive_path,
    })
}
