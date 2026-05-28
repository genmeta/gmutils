use aws_sdk_s3::Client;
use snafu::{ResultExt, Snafu, Whatever};
use tracing::info;

use super::{
    BrewPublishTarget, S3Options,
    key::{PublicBaseUrl, PublicBaseUrlError},
    plan::PlannedUpload,
};
use crate::package::manifest::{ArtifactKind, PackageArtifact, PackageManifest};

const PACKAGE_NAME: &str = "gmutils";
const FORMULA_NAME: &str = "gmutils.rb";
const DESCRIPTION: &str = "Genmeta Binary Utilities";
const HOMEPAGE: &str = "www.genmeta.net";
const LICENSE: &str = "Shareware";
const INSTALL_CONTENT: &str = r##"  def install
    bin.install "genmeta"
    bin.install "genmeta-ssh.sh"
  end

  test do
    system "#{bin}/genmeta", "-V"
  end"##;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RenderBrewError {
    #[snafu(display("brew formula requires brew package manifest"))]
    WrongKind,
    #[snafu(display("brew package artifact is missing archive name"))]
    MissingArchiveName { target: String },
    #[snafu(display("unsupported brew target {target}"))]
    UnsupportedTarget { target: String },
    #[snafu(display("invalid public base url"))]
    PublicBaseUrl { source: PublicBaseUrlError },
}

pub fn render_formula(
    manifest: &PackageManifest,
    public_base_url: &str,
) -> Result<String, RenderBrewError> {
    snafu::ensure!(
        manifest.kind == ArtifactKind::Brew,
        render_brew_error::WrongKindSnafu
    );
    let base =
        PublicBaseUrl::parse(public_base_url).context(render_brew_error::PublicBaseUrlSnafu)?;
    let class_name = formula_class_name(PACKAGE_NAME);
    let mut lines = vec![
        format!("class {class_name} < Formula"),
        format!("  desc \"{}\"", escape_formula_string(DESCRIPTION)),
        format!("  version \"{}\"", escape_formula_string(&manifest.version)),
        format!("  homepage \"{}\"", escape_formula_string(HOMEPAGE)),
        format!("  license \"{}\"", escape_formula_string(LICENSE)),
        String::new(),
    ];

    for artifact in &manifest.artifacts {
        let archive_name = archive_name(artifact)?;
        let block = brew_on_block(&artifact.target)?;
        lines.extend([
            format!("  {block} do"),
            format!("    url \"{}\"", base.join(archive_name)),
            format!("    sha256 \"{}\"", artifact.sha256),
            "  end".to_string(),
            String::new(),
        ]);
    }

    lines.push(INSTALL_CONTENT.trim_end().to_string());
    lines.push("end".to_string());
    lines.push(String::new());
    Ok(lines.join("\n"))
}

pub async fn run(
    options: &S3Options,
    client: &Client,
    target: BrewPublishTarget,
) -> Result<(), Whatever> {
    let loaded = super::load_manifest(ArtifactKind::Brew).await?;
    let mut uploads = plan_payload_uploads(
        client,
        &options.bucket,
        &loaded.target_dir,
        &loaded.manifest,
        &target.prefix,
    )
    .await?;
    let formula = render_formula(&loaded.manifest, target.public_base_url.as_str())
        .whatever_context("failed to render brew formula")?;
    let formula_path = loaded
        .target_dir
        .join("common")
        .join("brew")
        .join(FORMULA_NAME);
    uploads.push(PlannedUpload {
        path: formula_path.clone(),
        key: target.prefix.join(FORMULA_NAME),
        entry: true,
    });
    uploads.sort_by(|left, right| {
        left.entry
            .cmp(&right.entry)
            .then_with(|| left.key.cmp(&right.key))
    });

    tokio::fs::write(&formula_path, formula)
        .await
        .whatever_context(format!("failed to write {}", formula_path.display()))?;

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
        super::upload_file(client, &options.bucket, &upload.path, &upload.key).await?;
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
            .whatever_context("brew package artifact is missing archive name")?;
        let path = super::artifact_path(target_dir, artifact);
        let actual_sha256 = crate::sha256_file(&path).await?;
        snafu::ensure_whatever!(
            actual_sha256 == artifact.sha256,
            "sha256 mismatch for {}",
            artifact.path
        );
        let key = prefix.join(archive_name);
        let remote = super::remote_artifact_state(client, bucket, &key).await?;
        super::plan::verify_immutable_collision(&key, &actual_sha256, remote)
            .whatever_context("remote brew artifact collision")?;
        uploads.push(PlannedUpload {
            path,
            key,
            entry: false,
        });
    }
    Ok(uploads)
}

fn archive_name(artifact: &PackageArtifact) -> Result<&str, RenderBrewError> {
    artifact
        .archive_name
        .as_deref()
        .ok_or(RenderBrewError::MissingArchiveName {
            target: artifact.target.clone(),
        })
}

fn brew_on_block(target: &str) -> Result<&'static str, RenderBrewError> {
    match target {
        "aarch64-apple-darwin" => Ok("on_arm"),
        "x86_64-apple-darwin" => Ok("on_intel"),
        _ => Err(RenderBrewError::UnsupportedTarget {
            target: target.to_string(),
        }),
    }
}

fn formula_class_name(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

fn escape_formula_string(value: &str) -> String {
    value.replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::render_formula;
    use crate::package::manifest::{ArtifactKind, PackageArtifact, PackageManifest};

    #[test]
    fn formula_uses_public_base_url() {
        let manifest = PackageManifest {
            schema_version: 1,
            kind: ArtifactKind::Brew,
            package: "gmutils".to_string(),
            version: "0.5.2".to_string(),
            generated_at: "2026-05-27T00:00:00Z".to_string(),
            git_commit: None,
            git_dirty: false,
            artifacts: vec![PackageArtifact {
                target: "aarch64-apple-darwin".to_string(),
                path: "aarch64-apple-darwin/release/brew/gmutils-0.5.2-aarch64-apple-darwin.tar.gz"
                    .to_string(),
                sha256: "arm-sha".to_string(),
                size: 1,
                package_name: None,
                package_version: None,
                architecture: None,
                archive_name: Some("gmutils-0.5.2-aarch64-apple-darwin.tar.gz".to_string()),
                features: Vec::new(),
                profile: Some("release".to_string()),
            }],
        };

        let formula = render_formula(&manifest, "https://download.example/brew/gmutils")
            .expect("formula should render");

        assert!(formula.contains("url \"https://download.example/brew/gmutils/gmutils-0.5.2-aarch64-apple-darwin.tar.gz\""));
        assert!(formula.contains("sha256 \"arm-sha\""));
    }
}
