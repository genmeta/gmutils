use std::path::{Path, PathBuf};

use serde::Serialize;
use snafu::{ResultExt, Whatever};
use tracing::info;

use super::{
    artifact::{
        ArtifactEntry, ArtifactRoot, ReleaseManifest, copy_artifact, read_manifest, sha256_file,
        write_manifest,
    },
    paths::{common_paths, promote_staged_outputs, recreate_dir},
};
use crate::{PackageMeta, package_meta, target_dir};

const CARGO_NAME: &str = "genmeta";
const PACKAGE_NAME: &str = "gmutils";
const SCOOP_DL_URL: &str = "https://download.genmeta.net/scoop";
const SUPPORTED_TARGETS: [(&str, &str); 2] = [
    ("x86_64-pc-windows-msvc", "64bit"),
    ("i686-pc-windows-msvc", "32bit"),
];

#[derive(Debug)]
struct ArchiveSource {
    arch_key: String,
    archive_name: String,
    source: PathBuf,
}

#[derive(Debug, Clone)]
struct ArchiveInfo {
    arch_key: String,
    archive_name: String,
    sha256: String,
}

/// Scoop manifest JSON structure.
#[derive(Debug, Serialize)]
struct ScoopManifest {
    version: String,
    description: String,
    license: String,
    homepage: String,
    architecture: serde_json::Map<String, serde_json::Value>,
    bin: Vec<String>,
    checkver: CheckVer,
    autoupdate: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct CheckVer {
    url: String,
    re: String,
}

pub async fn stage() -> Result<(), Whatever> {
    info!("starting scoop stage");
    let meta = package_meta(CARGO_NAME)?;
    let target_dir = target_dir()?;
    let paths = common_paths()?;
    let sources = collect_archives(&target_dir, &meta.version).await?;

    let manifest = read_existing_manifest(&paths.manifest, &meta.version).await?;
    let staging = paths.root.join("scoop.staging");
    recreate_dir(&staging).await?;

    let mut archives = Vec::new();
    for source in sources {
        let destination = staging.join(&source.archive_name);
        copy_artifact(&source.source, &destination).await?;
        let sha256 = sha256_file(&destination).await?;
        info!(path = %destination.display(), "staged scoop archive");
        archives.push(ArchiveInfo {
            arch_key: source.arch_key,
            archive_name: source.archive_name,
            sha256,
        });
    }

    let scoop_manifest = build_manifest(&meta, &archives);
    let manifest_name = format!("{PACKAGE_NAME}.json");
    let scoop_manifest_path = staging.join(&manifest_name);
    let json = serde_json::to_string_pretty(&scoop_manifest)
        .whatever_context("failed to serialize scoop manifest")?;
    tokio::fs::write(&scoop_manifest_path, json + "\n")
        .await
        .whatever_context(format!("failed to write {}", scoop_manifest_path.display()))?;
    let scoop_manifest_sha256 = sha256_file(&scoop_manifest_path).await?;

    let manifest = merge_scoop_manifest(
        manifest,
        &meta.version,
        archives,
        manifest_name,
        scoop_manifest_sha256,
    );
    let manifest_staging = paths.root.join("manifest.toml.staging");
    write_manifest(&manifest_staging, &manifest).await?;

    promote_staged_outputs(
        "scoop",
        &staging,
        &paths.scoop,
        &manifest_staging,
        &paths.manifest,
    )
    .await?;

    info!(path = %paths.scoop.join(format!("{PACKAGE_NAME}.json")).display(), "staged scoop manifest");
    info!("finished scoop stage");
    Ok(())
}

async fn collect_archives(
    target_dir: &Path,
    version: &str,
) -> Result<Vec<ArchiveSource>, Whatever> {
    let mut archives = Vec::new();
    for (triple, arch_key) in SUPPORTED_TARGETS {
        let archive_name = format!("{PACKAGE_NAME}-{version}-{triple}.zip");
        let source = target_dir
            .join(triple)
            .join("release")
            .join("scoop")
            .join(&archive_name);
        if tokio::fs::try_exists(&source)
            .await
            .whatever_context(format!("failed to inspect {}", source.display()))?
        {
            archives.push(ArchiveSource {
                arch_key: arch_key.to_string(),
                archive_name,
                source,
            });
        } else {
            info!(path = %source.display(), "skipping missing scoop archive");
        }
    }

    snafu::ensure_whatever!(
        !archives.is_empty(),
        "no scoop archives found in target directories"
    );
    Ok(archives)
}

fn build_manifest(meta: &PackageMeta, archives: &[ArchiveInfo]) -> ScoopManifest {
    let manifest_name = format!("{PACKAGE_NAME}.json");
    let mut architecture = serde_json::Map::new();
    let mut autoupdate = serde_json::Map::new();

    for archive in archives {
        let url = format!("{SCOOP_DL_URL}/{}", archive.archive_name);
        architecture.insert(
            archive.arch_key.clone(),
            serde_json::json!({
                "url": url,
                "hash": archive.sha256,
            }),
        );
        autoupdate.insert(
            archive.arch_key.clone(),
            serde_json::json!({
                "url": url,
            }),
        );
    }

    ScoopManifest {
        version: meta.version.clone(),
        description: meta.description.clone(),
        license: meta.license.clone(),
        homepage: meta.homepage.clone(),
        architecture,
        bin: vec![format!("{CARGO_NAME}.exe"), "genmeta-ssh.bat".to_string()],
        checkver: CheckVer {
            url: format!("{SCOOP_DL_URL}/{manifest_name}"),
            re: r#""version"\s*:\s*"([^"]+)""#.to_string(),
        },
        autoupdate,
    }
}

async fn read_existing_manifest(path: &Path, version: &str) -> Result<ReleaseManifest, Whatever> {
    if tokio::fs::try_exists(path)
        .await
        .whatever_context(format!("failed to inspect {}", path.display()))?
    {
        read_manifest(path).await
    } else {
        Ok(ReleaseManifest {
            schema_version: 1,
            package: PACKAGE_NAME.to_string(),
            version: version.to_string(),
            artifacts: Vec::new(),
        })
    }
}

fn merge_scoop_manifest(
    mut manifest: ReleaseManifest,
    version: &str,
    archives: Vec<ArchiveInfo>,
    scoop_manifest_path: String,
    scoop_manifest_sha256: String,
) -> ReleaseManifest {
    manifest.package = PACKAGE_NAME.to_string();
    manifest.version = version.to_string();
    manifest
        .artifacts
        .retain(|artifact| artifact.root != ArtifactRoot::Scoop);

    for archive in archives {
        manifest.artifacts.push(ArtifactEntry {
            root: ArtifactRoot::Scoop,
            path: archive.archive_name,
            sha256: archive.sha256,
            immutable: true,
        });
    }

    manifest.artifacts.push(ArtifactEntry {
        root: ArtifactRoot::Scoop,
        path: scoop_manifest_path,
        sha256: scoop_manifest_sha256,
        immutable: false,
    });

    manifest
}

#[cfg(test)]
mod tests {
    use super::{ArchiveInfo, build_manifest, merge_scoop_manifest};
    use crate::{
        PackageMeta,
        release::artifact::{ArtifactEntry, ArtifactRoot, ReleaseManifest},
    };

    #[test]
    fn manifest_uses_architecture_key_and_installs_expected_bins() {
        let meta = PackageMeta {
            version: "0.5.1".to_string(),
            description: "Genmeta CLI tools".to_string(),
            homepage: "https://genmeta.net".to_string(),
            license: "MIT".to_string(),
        };
        let manifest = build_manifest(
            &meta,
            &[
                ArchiveInfo {
                    arch_key: "64bit".to_string(),
                    archive_name: "gmutils-0.5.1-x86_64-pc-windows-msvc.zip".to_string(),
                    sha256: "x64-sha".to_string(),
                },
                ArchiveInfo {
                    arch_key: "32bit".to_string(),
                    archive_name: "gmutils-0.5.1-i686-pc-windows-msvc.zip".to_string(),
                    sha256: "x86-sha".to_string(),
                },
            ],
        );

        let json = serde_json::to_value(&manifest).expect("manifest should serialize");

        assert!(json.get("architecture").is_some());
        assert!(json.get("architectures").is_none());
        assert_eq!(json["bin"][0], "genmeta.exe");
        assert_eq!(json["bin"][1], "genmeta-ssh.bat");
        assert_eq!(json["architecture"]["64bit"]["hash"], "x64-sha");
        assert_eq!(json["architecture"]["32bit"]["hash"], "x86-sha");
    }

    #[test]
    fn manifest_merge_preserves_non_scoop_entries_and_replaces_stale_scoop() {
        let existing = ReleaseManifest {
            schema_version: 1,
            package: "gmutils".to_string(),
            version: "old".to_string(),
            artifacts: vec![
                ArtifactEntry {
                    root: ArtifactRoot::Homebrew,
                    path: "gmutils.rb".to_string(),
                    sha256: "homebrew-sha".to_string(),
                    immutable: false,
                },
                ArtifactEntry {
                    root: ArtifactRoot::Scoop,
                    path: "stale.zip".to_string(),
                    sha256: "stale-sha".to_string(),
                    immutable: true,
                },
            ],
        };

        let merged = merge_scoop_manifest(
            existing,
            "0.5.1",
            vec![ArchiveInfo {
                arch_key: "64bit".to_string(),
                archive_name: "gmutils-0.5.1-x86_64-pc-windows-msvc.zip".to_string(),
                sha256: "x64-sha".to_string(),
            }],
            "gmutils.json".to_string(),
            "manifest-sha".to_string(),
        );

        assert!(
            merged
                .artifacts
                .iter()
                .any(|artifact| artifact.root == ArtifactRoot::Homebrew
                    && artifact.path == "gmutils.rb"
                    && artifact.sha256 == "homebrew-sha")
        );
        assert!(
            !merged
                .artifacts
                .iter()
                .any(|artifact| artifact.path == "stale.zip")
        );
        assert!(
            merged
                .artifacts
                .iter()
                .any(|artifact| artifact.root == ArtifactRoot::Scoop
                    && artifact.path == "gmutils-0.5.1-x86_64-pc-windows-msvc.zip"
                    && artifact.immutable)
        );
        assert!(
            merged
                .artifacts
                .iter()
                .any(|artifact| artifact.root == ArtifactRoot::Scoop
                    && artifact.path == "gmutils.json"
                    && !artifact.immutable)
        );
    }
}
