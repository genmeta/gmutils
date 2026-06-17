use aws_sdk_s3::Client;
use serde::Serialize;
use snafu::{ResultExt, Snafu, Whatever};
use tracing::info;

use super::{
    S3Options, ScoopPublishTarget,
    key::{PublicBaseUrl, PublicBaseUrlError},
    plan::PlannedUpload,
};
use crate::package::manifest::{ArtifactKind, PackageArtifact, PackageManifest};

const MANIFEST_NAME: &str = "gmutils.json";
const CARGO_NAME: &str = "genmeta";
const DESCRIPTION: &str = "Genmeta Binary Utilities";
const HOMEPAGE: &str = "https://www.dhttp.net";
const LICENSE: &str = "Apache-2.0";

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
        description: DESCRIPTION.to_string(),
        license: LICENSE.to_string(),
        homepage: HOMEPAGE.to_string(),
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
    options: &S3Options,
    client: &Client,
    target: ScoopPublishTarget,
) -> Result<(), Whatever> {
    let loaded = super::load_manifest(ArtifactKind::Scoop).await?;
    let mut uploads = plan_payload_uploads(
        client,
        &options.bucket,
        &loaded.target_dir,
        &loaded.manifest,
        &target.prefix,
    )
    .await?;
    let json = render_scoop_json(&loaded.manifest, target.public_base_url.as_str())
        .whatever_context("failed to render scoop json")?;
    let manifest_path = loaded
        .target_dir
        .join("common")
        .join("scoop")
        .join(MANIFEST_NAME);
    uploads.push(PlannedUpload {
        path: manifest_path.clone(),
        key: target.prefix.join(MANIFEST_NAME),
        entry: true,
        condition: None,
    });
    uploads.sort_by(|left, right| {
        left.entry
            .cmp(&right.entry)
            .then_with(|| left.key.cmp(&right.key))
    });

    tokio::fs::write(&manifest_path, json)
        .await
        .whatever_context(format!("failed to write {}", manifest_path.display()))?;

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
) -> Result<Vec<PlannedUpload>, Whatever> {
    let mut uploads = Vec::new();
    for artifact in &manifest.artifacts {
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
        let Some(condition) = super::plan::plan_immutable_upload(&key, &actual_sha256, remote)
            .whatever_context("remote scoop artifact collision")?
        else {
            info!(
                key,
                path = %path.display(),
                "remote immutable scoop artifact already has matching sha256"
            );
            continue;
        };
        uploads.push(PlannedUpload {
            path,
            key,
            entry: false,
            condition: Some(condition),
        });
    }
    Ok(uploads)
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
    use crate::package::manifest::{ArtifactKind, PackageArtifact, PackageManifest};

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

        let json = render_scoop_json(&manifest, "https://download.example/scoop/gmutils")
            .expect("json should render");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(value["version"], "0.5.2");
        assert_eq!(value["license"], "Apache-2.0");
        assert_eq!(
            value["architecture"]["64bit"]["url"],
            "https://download.example/scoop/gmutils/gmutils-0.5.2-x86_64-pc-windows-msvc.zip"
        );
        assert_eq!(value["architecture"]["64bit"]["hash"], "zip-sha");
    }
}
