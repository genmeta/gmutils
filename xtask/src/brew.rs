#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use flate2::{Compression, write::GzEncoder};
use snafu::{ResultExt, Whatever};
use tracing::{Instrument, info, info_span};

use crate::{
    BrewTarget, package_meta,
    release_contract::{PackageKind, ReleaseContract, resolve_build_env_from_process},
    run_cmd, run_cmd_quiet, sha256_file, target_dir,
};

const CARGO_NAME: &str = "genmeta";

/// Distribution package name (differs from the cargo crate name).
const PACKAGE_NAME: &str = "gmutils";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrewArchive {
    pub target: String,
    pub archive_name: String,
    pub path: PathBuf,
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

pub async fn run(
    contract: &ReleaseContract,
    targets: &[BrewTarget],
) -> Result<Vec<BrewArchive>, Whatever> {
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
        let build_env = resolve_build_env_from_process(contract, PackageKind::Brew, Some(triple))
            .whatever_context("failed to resolve build environment for brew target")?;
        info!(triple, "queued brew target build");
        let span = info_span!("brew", triple);
        tasks.spawn(
            async move { build_one(triple, &version, &target_dir, &workspace, build_env).await }
                .instrument(span),
        );
    }

    info!("waiting for brew target builds to finish");
    let mut archives = Vec::new();
    while let Some(result) = tasks.join_next().await {
        archives.push(result.whatever_context("brew build task panicked")??);
    }
    archives.sort_by(|left, right| left.target.cmp(&right.target));

    info!("finished brew dist build");
    Ok(archives)
}

async fn build_one(
    triple: &str,
    version: &str,
    target_dir: &Path,
    workspace: &Path,
    build_env: BTreeMap<String, String>,
) -> Result<BrewArchive, Whatever> {
    info!(triple, "checking cargo availability");
    check_cargo().await?;

    // Build
    info!(triple, "starting cargo build for brew target");
    run_cmd(
        tokio::process::Command::new("cargo")
            .envs(&build_env)
            .args([
                "build",
                "--release",
                "--target",
                triple,
                "--bin",
                CARGO_NAME,
            ]),
    )
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

    let sha256 = sha256_file(&archive_path).await?;
    info!(path = %archive_path.display(), sha256, "produced archive");
    Ok(BrewArchive {
        target: triple.to_string(),
        archive_name,
        path: archive_path,
    })
}
