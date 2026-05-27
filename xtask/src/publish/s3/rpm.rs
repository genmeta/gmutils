#![allow(dead_code)]

use std::collections::BTreeSet;

use aws_sdk_s3::Client;
use snafu::{FromString, OptionExt, ResultExt, Snafu, Whatever};
use tracing::info;

use super::{RpmPublishTarget, S3Options, plan::PlannedUpload};
use crate::package::manifest::{ArtifactKind, PackageArtifact};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmEntry {
    pub package: String,
    pub version: String,
    pub architecture: String,
    pub metadata: String,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum MergeRpmEntriesError {
    #[snafu(display("duplicate local rpm entry for {package} {architecture}"))]
    DuplicateLocal {
        package: String,
        architecture: String,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum RpmPublishError {
    #[snafu(display("rpm repository metadata generation is unavailable in this commit"))]
    MetadataUnavailable,
}

pub fn merge_rpm_entries(
    remote: Vec<RpmEntry>,
    local: Vec<RpmEntry>,
) -> Result<Vec<RpmEntry>, MergeRpmEntriesError> {
    let mut local_keys = BTreeSet::new();
    for entry in &local {
        let key = (entry.package.clone(), entry.architecture.clone());
        snafu::ensure!(
            local_keys.insert(key),
            merge_rpm_entries_error::DuplicateLocalSnafu {
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

pub fn rpm_upload_order(key: &str) -> u8 {
    if key.ends_with(".rpm") {
        return 0;
    }
    if key.ends_with("repodata/repomd.xml") {
        return 4;
    }
    2
}

pub async fn run(
    options: &S3Options,
    client: &Client,
    target: RpmPublishTarget,
) -> Result<(), Whatever> {
    let loaded = super::load_manifest(ArtifactKind::Rpm).await?;
    let mut uploads = plan_payload_uploads(
        client,
        &options.bucket,
        &loaded.target_dir,
        &loaded.manifest.artifacts,
        &target.prefix,
    )
    .await?;
    uploads.sort_by(|left, right| {
        rpm_upload_order(&left.key)
            .cmp(&rpm_upload_order(&right.key))
            .then_with(|| left.key.cmp(&right.key))
    });

    if options.dry_run {
        for upload in &uploads {
            info!(
                key = %upload.key,
                path = %upload.path.display(),
                "would upload rpm repository artifact"
            );
        }
        return Ok(());
    }

    Err(Whatever::with_source(
        Box::new(RpmPublishError::MetadataUnavailable),
        "rpm repository metadata generation is unavailable in this commit".to_string(),
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
            .whatever_context("rpm package artifact is missing archive name")?;
        let key = prefix.join(archive_name);
        let remote = super::remote_artifact_state(client, bucket, &key).await?;
        super::plan::verify_immutable_collision(&key, &actual_sha256, remote)
            .whatever_context("remote rpm artifact collision")?;
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
    use super::{RpmEntry, merge_rpm_entries, rpm_upload_order};

    #[test]
    fn manifest_arch_replaces_remote_same_arch_and_preserves_others() {
        let remote = vec![
            RpmEntry {
                package: "gmutils".to_string(),
                version: "0.5.1-1".to_string(),
                architecture: "x86_64".to_string(),
                metadata: "name=gmutils version=0.5.1-1 arch=x86_64".to_string(),
            },
            RpmEntry {
                package: "gmutils".to_string(),
                version: "0.5.1-1".to_string(),
                architecture: "aarch64".to_string(),
                metadata: "name=gmutils version=0.5.1-1 arch=aarch64".to_string(),
            },
        ];
        let local = vec![RpmEntry {
            package: "gmutils".to_string(),
            version: "0.5.2-1".to_string(),
            architecture: "x86_64".to_string(),
            metadata: "name=gmutils version=0.5.2-1 arch=x86_64".to_string(),
        }];

        let merged = merge_rpm_entries(remote, local).expect("merge should pass");

        assert!(
            merged
                .iter()
                .any(|entry| entry.version == "0.5.2-1" && entry.architecture == "x86_64")
        );
        assert!(
            merged
                .iter()
                .any(|entry| entry.version == "0.5.1-1" && entry.architecture == "aarch64")
        );
    }

    #[test]
    fn rpm_upload_order_places_repomd_last() {
        let mut keys = [
            "rpm/repodata/repomd.xml".to_string(),
            "rpm/gmutils/0.5.2/gmutils.rpm".to_string(),
            "rpm/repodata/primary.xml.gz".to_string(),
        ];
        keys.sort_by_key(|key| rpm_upload_order(key));
        assert_eq!(
            keys.last().map(String::as_str),
            Some("rpm/repodata/repomd.xml")
        );
    }
}
