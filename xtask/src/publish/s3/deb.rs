#![allow(dead_code)]

use std::collections::BTreeSet;

use aws_sdk_s3::Client;
use snafu::{FromString, OptionExt, ResultExt, Snafu, Whatever};
use tracing::info;

use super::{DebPublishTarget, S3Options, plan::PlannedUpload};
use crate::package::manifest::{ArtifactKind, PackageArtifact};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageEntry {
    pub package: String,
    pub version: String,
    pub architecture: String,
    pub stanza: String,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum MergePackageEntriesError {
    #[snafu(display("duplicate local package entry for {package} {architecture}"))]
    DuplicateLocal {
        package: String,
        architecture: String,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum DebPublishError {
    #[snafu(display("deb repository metadata generation is unavailable in this commit"))]
    MetadataUnavailable,
}

pub fn merge_package_entries(
    remote: Vec<PackageEntry>,
    local: Vec<PackageEntry>,
) -> Result<Vec<PackageEntry>, MergePackageEntriesError> {
    let mut local_keys = BTreeSet::new();
    for entry in &local {
        let key = (entry.package.clone(), entry.architecture.clone());
        snafu::ensure!(
            local_keys.insert(key),
            merge_package_entries_error::DuplicateLocalSnafu {
                package: entry.package.clone(),
                architecture: entry.architecture.clone()
            }
        );
    }
    let mut merged = remote
        .into_iter()
        .filter(|entry| !local_keys.contains(&(entry.package.clone(), entry.architecture.clone())))
        .collect::<Vec<_>>();
    merged.extend(local);
    merged.sort_by(|left, right| {
        left.package
            .cmp(&right.package)
            .then_with(|| left.architecture.cmp(&right.architecture))
            .then_with(|| left.version.cmp(&right.version))
    });
    Ok(merged)
}

pub fn apt_upload_order(key: &str) -> u8 {
    if key.contains("/pool/") || key.starts_with("pool/") {
        return 0;
    }
    if key.ends_with("InRelease") {
        return 4;
    }
    if key.ends_with("Release.gpg") {
        return 3;
    }
    2
}

pub async fn run(
    options: &S3Options,
    client: &Client,
    target: DebPublishTarget,
) -> Result<(), Whatever> {
    let loaded = super::load_manifest(ArtifactKind::Deb).await?;
    let mut uploads = plan_payload_uploads(
        client,
        &options.bucket,
        &loaded.target_dir,
        &loaded.manifest.artifacts,
        &target.prefix,
    )
    .await?;
    uploads.sort_by(|left, right| {
        apt_upload_order(&left.key)
            .cmp(&apt_upload_order(&right.key))
            .then_with(|| left.key.cmp(&right.key))
    });

    if options.dry_run {
        for upload in &uploads {
            info!(
                key = %upload.key,
                path = %upload.path.display(),
                suite = %target.suite,
                fingerprint = %target.fingerprint,
                "would upload deb repository artifact"
            );
        }
        return Ok(());
    }

    Err(Whatever::with_source(
        Box::new(DebPublishError::MetadataUnavailable),
        "deb repository metadata generation is unavailable in this commit".to_string(),
    ))
}

async fn plan_payload_uploads(
    client: &Client,
    bucket: &str,
    target_dir: &std::path::Path,
    artifacts: &[PackageArtifact],
    prefix: &super::key::RemotePrefix,
) -> Result<Vec<PlannedUpload>, Whatever> {
    let mut uploads = Vec::new();
    for artifact in artifacts {
        let path = super::artifact_path(target_dir, artifact);
        let actual_sha256 = crate::sha256_file(&path).await?;
        snafu::ensure_whatever!(
            actual_sha256 == artifact.sha256,
            "sha256 mismatch for {}",
            artifact.path
        );
        let archive_name = artifact
            .archive_name
            .as_deref()
            .whatever_context("deb package artifact is missing archive name")?;
        let key = prefix.join(archive_name);
        let remote = super::remote_artifact_state(client, bucket, &key).await?;
        super::plan::verify_immutable_collision(&key, &actual_sha256, remote)
            .whatever_context("remote deb artifact collision")?;
        uploads.push(PlannedUpload {
            path,
            key,
            entry: false,
        });
    }
    Ok(uploads)
}

#[cfg(test)]
mod tests {
    use super::{PackageEntry, apt_upload_order, merge_package_entries};

    #[test]
    fn manifest_arch_replaces_remote_same_arch_and_preserves_others() {
        let remote = vec![
            PackageEntry {
                package: "gmutils".to_string(),
                version: "0.5.1-1".to_string(),
                architecture: "amd64".to_string(),
                stanza: "Package: gmutils\nVersion: 0.5.1-1\nArchitecture: amd64\n".to_string(),
            },
            PackageEntry {
                package: "gmutils".to_string(),
                version: "0.5.1-1".to_string(),
                architecture: "arm64".to_string(),
                stanza: "Package: gmutils\nVersion: 0.5.1-1\nArchitecture: arm64\n".to_string(),
            },
        ];
        let local = vec![PackageEntry {
            package: "gmutils".to_string(),
            version: "0.5.2-1".to_string(),
            architecture: "amd64".to_string(),
            stanza: "Package: gmutils\nVersion: 0.5.2-1\nArchitecture: amd64\n".to_string(),
        }];

        let merged = merge_package_entries(remote, local).expect("merge should pass");

        assert!(
            merged
                .iter()
                .any(|entry| entry.version == "0.5.2-1" && entry.architecture == "amd64")
        );
        assert!(
            merged
                .iter()
                .any(|entry| entry.version == "0.5.1-1" && entry.architecture == "arm64")
        );
    }

    #[test]
    fn apt_upload_order_places_inrelease_last() {
        let mut keys = [
            "apt/dists/stable/InRelease".to_string(),
            "apt/pool/main/g/gmutils/gmutils.deb".to_string(),
            "apt/dists/stable/Release".to_string(),
        ];
        keys.sort_by_key(|key| apt_upload_order(key));
        assert_eq!(
            keys.last().map(String::as_str),
            Some("apt/dists/stable/InRelease")
        );
    }
}
