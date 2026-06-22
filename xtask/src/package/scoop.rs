use std::{collections::BTreeSet, path::Path};

use snafu::{ResultExt, Snafu, Whatever};

use super::{PackageArtifact, PackageManifest, manifest::ArtifactKind, prompt::OverwriteDecision};
use crate::{ScoopTarget, scoop::ScoopArchive};

const PACKAGE_NAME: &str = "gmutils";
const SUPPORTED_SCOOP_TARGETS: &[&str] = &["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"];

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ScoopPackageError {
    #[snafu(display("scoop package must include all supported targets"))]
    MissingSupportedTarget,
    #[snafu(display("scoop archive name must include package version"))]
    ArchiveVersion,
    #[snafu(display("failed to make artifact path target-relative"))]
    TargetRelativePath { source: std::path::StripPrefixError },
    #[snafu(display("artifact path must be valid utf-8"))]
    ArtifactPathUtf8,
}

pub fn validate_complete_scoop_targets(archives: &[ScoopArchive]) -> Result<(), ScoopPackageError> {
    let actual = archives
        .iter()
        .map(|archive| archive.target.as_str())
        .collect::<BTreeSet<_>>();
    let expected = SUPPORTED_SCOOP_TARGETS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    snafu::ensure!(
        actual == expected,
        scoop_package_error::MissingSupportedTargetSnafu
    );
    Ok(())
}

pub fn scoop_manifest_artifacts(
    archives: &[ScoopArchive],
    version: &str,
) -> Result<Vec<PackageArtifact>, ScoopPackageError> {
    validate_complete_scoop_targets(archives)?;
    archives
        .iter()
        .map(|archive| {
            snafu::ensure!(
                archive.archive_name.contains(version),
                scoop_package_error::ArchiveVersionSnafu
            );
            Ok(PackageArtifact {
                target: archive.target.clone(),
                path: target_relative_path(&archive.path)?,
                sha256: String::new(),
                size: 0,
                package_name: None,
                package_version: None,
                architecture: None,
                archive_name: Some(archive.archive_name.clone()),
                features: Vec::new(),
                profile: Some("release".to_string()),
            })
        })
        .collect()
}

fn target_relative_path(path: &Path) -> Result<String, ScoopPackageError> {
    let target_relative = match path.strip_prefix("target") {
        Ok(relative) => relative,
        Err(_) => path,
    };
    target_relative
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or(ScoopPackageError::ArtifactPathUtf8)
}

pub async fn run(
    contract: &crate::release_contract::ReleaseContract,
    targets: &[ScoopTarget],
    overwrite_manifest: bool,
) -> Result<(), Whatever> {
    let archives = crate::scoop::run(contract, targets).await?;
    let meta = crate::package_meta("genmeta")?;
    let target_dir = crate::target_dir()?;
    let manifest_path = target_dir
        .join("common")
        .join("scoop")
        .join("manifest.toml");
    let exists = tokio::fs::try_exists(&manifest_path)
        .await
        .whatever_context(format!("failed to inspect {}", manifest_path.display()))?;
    if super::prompt::confirm_manifest_overwrite(exists, overwrite_manifest)
        .await
        .whatever_context("failed to confirm scoop package manifest overwrite")?
        == OverwriteDecision::Skip
    {
        return Ok(());
    }

    let mut artifacts = scoop_manifest_artifacts(&archives, &meta.version)
        .whatever_context("failed to build scoop package manifest artifacts")?;
    for (artifact, archive) in artifacts.iter_mut().zip(archives.iter()) {
        artifact.path = target_relative_artifact_path(&archive.path, &target_dir)
            .whatever_context("failed to make scoop artifact path target-relative")?;
        artifact.sha256 = crate::sha256_file(&archive.path).await?;
        artifact.size = tokio::fs::metadata(&archive.path)
            .await
            .whatever_context(format!("failed to inspect {}", archive.path.display()))?
            .len();
    }

    let manifest = PackageManifest {
        schema_version: 1,
        kind: ArtifactKind::Scoop,
        package: PACKAGE_NAME.to_string(),
        version: meta.version,
        generated_at: generated_at(),
        git_commit: None,
        git_dirty: false,
        artifacts,
    };
    super::manifest::write_manifest(&manifest_path, &manifest)
        .await
        .whatever_context("failed to write scoop package manifest")?;
    Ok(())
}

fn target_relative_artifact_path(
    path: &Path,
    target_dir: &Path,
) -> Result<String, ScoopPackageError> {
    path.strip_prefix(target_dir)
        .context(scoop_package_error::TargetRelativePathSnafu)?
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or(ScoopPackageError::ArtifactPathUtf8)
}

fn generated_at() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{scoop_manifest_artifacts, validate_complete_scoop_targets};
    use crate::scoop::ScoopArchive;

    #[test]
    fn scoop_requires_all_supported_targets() {
        let archives = vec![ScoopArchive {
            target: "x86_64-pc-windows-msvc".to_string(),
            archive_name: "gmutils-0.5.2-x86_64-pc-windows-msvc.zip".to_string(),
            path: PathBuf::from(
                "target/x86_64-pc-windows-msvc/release/scoop/gmutils-0.5.2-x86_64-pc-windows-msvc.zip",
            ),
        }];

        let error =
            validate_complete_scoop_targets(&archives).expect_err("missing i686 should fail");
        assert_eq!(
            error.to_string(),
            "scoop package must include all supported targets"
        );
    }

    #[test]
    fn scoop_archive_name_must_include_version() {
        let archives = vec![
            ScoopArchive {
                target: "x86_64-pc-windows-msvc".to_string(),
                archive_name: "gmutils-x86_64-pc-windows-msvc.zip".to_string(),
                path: PathBuf::from(
                    "target/x86_64-pc-windows-msvc/release/scoop/gmutils-x86_64-pc-windows-msvc.zip",
                ),
            },
            ScoopArchive {
                target: "i686-pc-windows-msvc".to_string(),
                archive_name: "gmutils-0.5.2-i686-pc-windows-msvc.zip".to_string(),
                path: PathBuf::from(
                    "target/i686-pc-windows-msvc/release/scoop/gmutils-0.5.2-i686-pc-windows-msvc.zip",
                ),
            },
        ];

        let error =
            scoop_manifest_artifacts(&archives, "0.5.2").expect_err("missing version should fail");
        assert_eq!(
            error.to_string(),
            "scoop archive name must include package version"
        );
    }
}
