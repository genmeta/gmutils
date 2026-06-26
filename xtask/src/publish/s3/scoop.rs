use aws_sdk_s3::Client;
use serde::Serialize;
use snafu::{ResultExt, Snafu, Whatever};
use tracing::{info, warn};

use super::{
    ResolvedS3Options, ScoopPublishTarget,
    key::{PublicBaseUrl, PublicBaseUrlError},
    plan::PlannedUpload,
};
use crate::{
    package::manifest::{ArtifactKind, PackageArtifact, PackageManifest},
    release_contract::{self, ResolvedPackageMetadata},
};

const MANIFEST_NAME: &str = "gmutils.json";
const CARGO_NAME: &str = "genmeta";

fn versioned_manifest_name(version: &str) -> String {
    format!("gmutils-{version}.json")
}

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

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RenderScoopError {
    #[snafu(display("scoop json requires scoop package manifest"))]
    WrongKind,
    #[snafu(display("scoop package artifact is missing archive name"))]
    MissingArchiveName { target: String },
    #[snafu(display("unsupported scoop target {target}"))]
    UnsupportedTarget { target: String },
    #[snafu(display("invalid public base url"))]
    PublicBaseUrl { source: PublicBaseUrlError },
    #[snafu(display("failed to serialize scoop json"))]
    Serialize { source: serde_json::Error },
}

pub fn render_scoop_json(
    manifest: &PackageManifest,
    public_base_url: &str,
    metadata: &ResolvedPackageMetadata,
) -> Result<String, RenderScoopError> {
    snafu::ensure!(
        manifest.kind == ArtifactKind::Scoop,
        render_scoop_error::WrongKindSnafu
    );
    let base =
        PublicBaseUrl::parse(public_base_url).context(render_scoop_error::PublicBaseUrlSnafu)?;
    let mut architecture = serde_json::Map::new();
    let mut autoupdate = serde_json::Map::new();
    for artifact in &manifest.artifacts {
        let arch_key = scoop_arch_key(&artifact.target)?;
        let archive_name = archive_name(artifact)?;
        let url = base.join(archive_name);
        architecture.insert(
            arch_key.to_string(),
            serde_json::json!({
                "url": url,
                "hash": artifact.sha256,
            }),
        );
        autoupdate.insert(
            arch_key.to_string(),
            serde_json::json!({
                "url": base.join(archive_name),
            }),
        );
    }

    let scoop_manifest = ScoopManifest {
        version: manifest.version.clone(),
        description: metadata.description.clone(),
        license: metadata.license.clone(),
        homepage: metadata.homepage.clone(),
        architecture,
        bin: vec![format!("{CARGO_NAME}.exe"), "genmeta-ssh.bat".to_string()],
        checkver: CheckVer {
            url: base.join(MANIFEST_NAME),
            re: r#""version"\s*:\s*"([^"]+)""#.to_string(),
        },
        autoupdate,
    };
    serde_json::to_string_pretty(&scoop_manifest)
        .map(|json| json + "\n")
        .context(render_scoop_error::SerializeSnafu)
}

pub async fn run(
    options: &ResolvedS3Options,
    client: &Client,
    target: ScoopPublishTarget,
) -> Result<(), Whatever> {
    let loaded = super::load_manifest(ArtifactKind::Scoop).await?;
    let (mut uploads, manifest) = plan_payload_uploads(
        client,
        &options.bucket,
        &loaded.target_dir,
        &loaded.manifest,
        &target.prefix,
    )
    .await?;
    let metadata = release_contract::resolve_package_metadata(
        &release_contract::load_release_contract()
            .whatever_context("failed to load release contract")?,
    )
    .whatever_context("failed to resolve package metadata")?;
    let json = render_scoop_json(&manifest, target.public_base_url.as_str(), &metadata)
        .whatever_context("failed to render scoop json")?;
    let manifest_dir = loaded.target_dir.join("common").join("scoop");
    let manifest_path = manifest_dir.join(MANIFEST_NAME);
    let versioned_manifest_name = versioned_manifest_name(&manifest.version);
    let versioned_manifest_path = manifest_dir.join(&versioned_manifest_name);
    uploads.push(PlannedUpload {
        path: manifest_path.clone(),
        key: target.prefix.join(MANIFEST_NAME),
        entry: true,
        condition: None,
    });
    uploads.push(PlannedUpload {
        path: versioned_manifest_path.clone(),
        key: target.prefix.join(&versioned_manifest_name),
        entry: true,
        condition: None,
    });
    uploads.sort_by(|left, right| {
        left.entry
            .cmp(&right.entry)
            .then_with(|| left.key.cmp(&right.key))
    });

    tokio::fs::write(&manifest_path, &json)
        .await
        .whatever_context(format!("failed to write {}", manifest_path.display()))?;
    tokio::fs::write(&versioned_manifest_path, json)
        .await
        .whatever_context(format!(
            "failed to write {}",
            versioned_manifest_path.display()
        ))?;

    if options.dry_run {
        for upload in &uploads {
            info!(
                key = %upload.key,
                path = %upload.path.display(),
                "would upload package artifact"
            );
        }
        return Ok(());
    }

    for upload in uploads {
        super::upload_file(
            client,
            &options.bucket,
            &upload.path,
            &upload.key,
            upload.condition,
        )
        .await?;
    }
    Ok(())
}

async fn plan_payload_uploads(
    client: &Client,
    bucket: &str,
    target_dir: &std::path::Path,
    manifest: &PackageManifest,
    prefix: &super::key::RemotePrefix,
) -> Result<(Vec<PlannedUpload>, PackageManifest), Whatever> {
    let mut uploads = Vec::new();
    let mut manifest = manifest.clone();
    for artifact in &mut manifest.artifacts {
        let archive_name = archive_name(artifact)
            .whatever_context("scoop package artifact is missing archive name")?;
        let path = super::artifact_path(target_dir, artifact);
        let actual_sha256 = crate::sha256_file(&path).await?;
        snafu::ensure_whatever!(
            actual_sha256 == artifact.sha256,
            "sha256 mismatch for {}",
            artifact.path
        );
        let key = prefix.join(archive_name);
        let remote = super::remote_artifact_state(client, bucket, &key).await?;
        let plan = super::plan::plan_versioned_immutable_payload(&key, &actual_sha256, remote);
        artifact.sha256 = plan.metadata_sha256().to_string();
        if let Some(condition) = plan.upload_condition() {
            uploads.push(PlannedUpload {
                path,
                key,
                entry: false,
                condition: Some(condition),
            });
        } else if plan.remote_sha256_matches_local() {
            info!(
                key,
                path = %path.display(),
                "remote immutable scoop artifact already has matching sha256"
            );
        } else {
            warn!(
                key,
                path = %path.display(),
                local_sha256 = %actual_sha256,
                remote_sha256 = %plan.metadata_sha256(),
                "remote immutable scoop artifact already exists with different sha256; reusing remote payload for metadata"
            );
        }
    }
    Ok((uploads, manifest))
}

fn archive_name(artifact: &PackageArtifact) -> Result<&str, RenderScoopError> {
    artifact
        .archive_name
        .as_deref()
        .ok_or(RenderScoopError::MissingArchiveName {
            target: artifact.target.clone(),
        })
}

fn scoop_arch_key(target: &str) -> Result<&'static str, RenderScoopError> {
    match target {
        "x86_64-pc-windows-msvc" => Ok("64bit"),
        "i686-pc-windows-msvc" => Ok("32bit"),
        _ => Err(RenderScoopError::UnsupportedTarget {
            target: target.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::render_scoop_json;
    use crate::{
        package::manifest::{ArtifactKind, PackageArtifact, PackageManifest},
        release_contract::ResolvedPackageMetadata,
    };

    #[test]
    fn versioned_manifest_name_uses_package_version() {
        assert_eq!(
            super::versioned_manifest_name("0.6.1"),
            "gmutils-0.6.1.json"
        );
    }

    #[test]
    fn scoop_json_uses_public_base_url() {
        let manifest = PackageManifest {
            schema_version: 1,
            kind: ArtifactKind::Scoop,
            package: "gmutils".to_string(),
            version: "0.5.2".to_string(),
            generated_at: "2026-05-27T00:00:00Z".to_string(),
            git_commit: None,
            git_dirty: false,
            artifacts: vec![PackageArtifact {
                target: "x86_64-pc-windows-msvc".to_string(),
                path:
                    "x86_64-pc-windows-msvc/release/scoop/gmutils-0.5.2-x86_64-pc-windows-msvc.zip"
                        .to_string(),
                sha256: "zip-sha".to_string(),
                size: 1,
                package_name: None,
                package_version: None,
                architecture: None,
                archive_name: Some("gmutils-0.5.2-x86_64-pc-windows-msvc.zip".to_string()),
                features: Vec::new(),
                profile: Some("release".to_string()),
            }],
        };
        let metadata = ResolvedPackageMetadata {
            name: "gmutils".to_string(),
            version: "0.5.2".to_string(),
            description: "Genmeta Binary Utilities".to_string(),
            homepage: "https://www.dhttp.net".to_string(),
            license: "Apache-2.0".to_string(),
            repository: None,
            authors: Vec::new(),
        };

        let json = render_scoop_json(&manifest, "https://download.example/scoop", &metadata)
            .expect("json should render");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(value["version"], "0.5.2");
        assert_eq!(value["license"], "Apache-2.0");
        assert_eq!(value["homepage"], "https://www.dhttp.net");
        assert_eq!(
            value["architecture"]["64bit"]["url"],
            "https://download.example/scoop/gmutils-0.5.2-x86_64-pc-windows-msvc.zip"
        );
        assert_eq!(value["architecture"]["64bit"]["hash"], "zip-sha");
        assert_eq!(
            value["checkver"]["url"],
            "https://download.example/scoop/gmutils.json"
        );
    }
}
