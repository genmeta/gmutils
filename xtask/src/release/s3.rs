use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use aws_credential_types::Credentials;
use aws_sdk_s3::{
    Client, config::Region, error::SdkError, operation::get_object::GetObjectError,
    primitives::ByteStream,
};
use clap::{Args, CommandFactory, Parser, Subcommand, error::ErrorKind};
use sha2::Digest;
use snafu::{OptionExt, ResultExt, Whatever};
use tracing::info;
use walkdir::WalkDir;

use super::{
    PublishRoot, S3Options,
    artifact::{ReleaseManifest, read_manifest, relative_path, sha256_file},
    grouped,
    paths::common_paths,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedUpload {
    path: PathBuf,
    key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3TargetPlan {
    pub root: PublishRoot,
    pub prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteArtifactState {
    Missing,
    Present { sha256: String },
}

#[derive(Debug, Parser)]
struct TargetCli {
    #[command(subcommand)]
    target: TargetFormat,
}

#[derive(Debug, Subcommand)]
enum TargetFormat {
    /// Verify Homebrew artifacts under the homebrew prefix
    Homebrew,
    /// Verify Scoop artifacts under the scoop prefix
    Scoop,
    /// Verify APT artifacts under an explicit prefix
    Apt {
        #[command(flatten)]
        options: PrefixOptions,
    },
    /// Verify RPM artifacts under an explicit prefix
    Rpm {
        #[command(flatten)]
        options: PrefixOptions,
    },
}

#[derive(Debug, Clone, Args)]
struct PrefixOptions {
    /// Remote prefix for this target
    #[arg(long)]
    prefix: String,
}

pub async fn publish(options: S3Options) -> Result<(), Whatever> {
    let common = common_paths()?.root;
    let uploads = plan_uploads(&common, &options.roots, options.apt_prefix.as_deref())?;
    if options.dry_run {
        for upload in uploads {
            info!(
                "would upload {} -> s3://{}/{}",
                upload.path.display(),
                options.bucket,
                upload.key
            );
        }
        return Ok(());
    }

    let client = client(&options).await?;
    for upload in uploads {
        client
            .put_object()
            .bucket(&options.bucket)
            .key(&upload.key)
            .body(
                ByteStream::from_path(&upload.path)
                    .await
                    .whatever_context("failed to read upload body")?,
            )
            .send()
            .await
            .whatever_context(format!("failed to upload {}", upload.key))?;
        info!(key = %upload.key, "uploaded staged artifact");
    }
    Ok(())
}

pub async fn verify_remote(options: S3Options, targets: Vec<OsString>) -> Result<(), Whatever> {
    let plans = parse_target_plans(&targets).unwrap_or_else(|error| {
        error.exit();
    });
    let common = common_paths()?.root;
    let manifest = read_manifest(&common.join("manifest.toml")).await?;
    let client = client(&options).await?;

    verify_remote_artifacts(&client, &options.bucket, &common, &manifest, &plans).await
}

async fn verify_remote_artifacts(
    client: &Client,
    bucket: &str,
    common: &Path,
    manifest: &ReleaseManifest,
    plans: &[S3TargetPlan],
) -> Result<(), Whatever> {
    for plan in plans {
        let artifact_root = plan.root.artifact_root();
        for artifact in manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.root == artifact_root && artifact.immutable)
        {
            let path = common.join(artifact.root.directory()).join(&artifact.path);
            snafu::ensure_whatever!(
                tokio::fs::try_exists(&path)
                    .await
                    .whatever_context(format!("failed to inspect {}", path.display()))?,
                "artifact {} is missing",
                artifact.path
            );
            let actual = sha256_file(&path).await?;
            snafu::ensure_whatever!(
                actual == artifact.sha256,
                "sha256 mismatch for {}",
                artifact.path
            );

            let key = join_key(&plan.prefix, &artifact.path);
            let remote = remote_artifact_state(client, bucket, &key).await?;
            verify_immutable_collision(&key, &actual, remote)?;
        }
    }
    Ok(())
}

async fn remote_artifact_state(
    client: &Client,
    bucket: &str,
    key: &str,
) -> Result<RemoteArtifactState, Whatever> {
    let output = match client.get_object().bucket(bucket).key(key).send().await {
        Ok(output) => output,
        Err(error) if is_missing_object_error(&error) => return Ok(RemoteArtifactState::Missing),
        Err(error) => {
            snafu::whatever!("failed to fetch remote artifact {key}: {error}");
        }
    };
    let body = output
        .body
        .collect()
        .await
        .whatever_context(format!("failed to read remote artifact {key}"))?;
    Ok(RemoteArtifactState::Present {
        sha256: sha256_bytes(body.into_bytes().as_ref()),
    })
}

fn is_missing_object_error(error: &SdkError<GetObjectError, impl std::fmt::Debug>) -> bool {
    if let Some(service) = error.as_service_error() {
        if service.is_no_such_key() {
            return true;
        }
        let code = service.meta().code();
        if matches!(code, Some("NoSuchKey" | "NotFound")) {
            return true;
        }
    }
    format!("{error:?}").contains("StatusCode(404)")
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn verify_immutable_collision(
    artifact_path: &str,
    local_sha256: &str,
    remote: RemoteArtifactState,
) -> Result<(), Whatever> {
    match remote {
        RemoteArtifactState::Missing => Ok(()),
        RemoteArtifactState::Present { sha256 } if sha256 == local_sha256 => Ok(()),
        RemoteArtifactState::Present { sha256 } => {
            snafu::whatever!(
                "remote immutable artifact {artifact_path} already exists with different sha256 {sha256}"
            )
        }
    }
}

async fn read_secret(path: &Path) -> Result<String, Whatever> {
    let value = tokio::fs::read_to_string(path)
        .await
        .whatever_context(format!("failed to read {}", path.display()))?;
    Ok(value.trim().to_string())
}

async fn client(options: &S3Options) -> Result<Client, Whatever> {
    let access_key_id = read_secret(&options.access_key_id_file).await?;
    let secret_access_key = read_secret(&options.secret_access_key_file).await?;
    let credentials = Credentials::new(
        access_key_id,
        secret_access_key,
        None,
        None,
        "xtask-release",
    );
    let s3_config = aws_sdk_s3::config::Builder::new()
        .region(Region::new("auto"))
        .endpoint_url(options.endpoint_url.clone())
        .credentials_provider(credentials)
        .force_path_style(true)
        .build();
    Ok(Client::from_conf(s3_config))
}

fn plan_uploads(
    common: &Path,
    roots: &[PublishRoot],
    apt_prefix: Option<&str>,
) -> Result<Vec<PlannedUpload>, Whatever> {
    let mut uploads = Vec::new();
    let explicit_roots = !roots.is_empty();
    for root in selected_roots(roots) {
        let directory = root_directory(common, root);
        if !directory.exists() {
            snafu::ensure_whatever!(
                !explicit_roots,
                "requested publish root {root} is missing at {}",
                directory.display()
            );
            continue;
        }
        uploads.extend(plan_root_uploads(common, root, apt_prefix)?);
    }
    snafu::ensure_whatever!(!uploads.is_empty(), "no staged artifacts found to publish");
    uploads.sort_by(|left, right| {
        upload_order(left)
            .cmp(&upload_order(right))
            .then_with(|| left.key.cmp(&right.key))
    });
    Ok(uploads)
}

fn selected_roots(roots: &[PublishRoot]) -> Vec<PublishRoot> {
    if roots.is_empty() {
        vec![PublishRoot::Homebrew, PublishRoot::Scoop, PublishRoot::Apt]
    } else {
        roots.to_vec()
    }
}

fn plan_root_uploads(
    common: &Path,
    root: PublishRoot,
    apt_prefix: Option<&str>,
) -> Result<Vec<PlannedUpload>, Whatever> {
    let (directory, key_prefix) = match root {
        PublishRoot::Homebrew => (common.join("homebrew"), "homebrew".to_string()),
        PublishRoot::Scoop => (common.join("scoop"), "scoop".to_string()),
        PublishRoot::Apt => (common.join("apt"), require_apt_prefix(apt_prefix)?),
        PublishRoot::Rpm => (common.join("rpm"), "rpm".to_string()),
    };

    let mut uploads = Vec::new();
    for entry in WalkDir::new(&directory) {
        let entry = entry.whatever_context(format!("failed to walk {}", directory.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = relative_path(&directory, entry.path())?;
        let key = join_key(&key_prefix, &relative);
        uploads.push(PlannedUpload {
            path: entry.path().to_path_buf(),
            key,
        });
    }
    Ok(uploads)
}

fn root_directory(common: &Path, root: PublishRoot) -> PathBuf {
    common.join(root.directory())
}

fn require_apt_prefix(apt_prefix: Option<&str>) -> Result<String, Whatever> {
    let prefix = apt_prefix.whatever_context("apt prefix is required when publishing apt root")?;
    let prefix = trim_slashes(prefix);
    snafu::ensure_whatever!(!prefix.is_empty(), "apt prefix must not be empty");
    Ok(prefix)
}

fn trim_slashes(value: &str) -> String {
    value.trim_matches('/').to_string()
}

fn join_key(prefix: &str, relative: &str) -> String {
    if prefix.is_empty() {
        relative.to_string()
    } else {
        format!("{prefix}/{relative}")
    }
}

pub fn parse_target_plans(tokens: &[OsString]) -> Result<Vec<S3TargetPlan>, clap::Error> {
    let sections = grouped::parse_grouped_targets(tokens, &["homebrew", "scoop", "apt", "rpm"])
        .map_err(|error| target_error(ErrorKind::ValueValidation, error))?;
    if sections.is_empty() {
        return Err(target_error(
            ErrorKind::MissingRequiredArgument,
            "at least one s3 target is required",
        ));
    }

    sections
        .into_iter()
        .map(|section| parse_target_plan(&section.name, section.args))
        .collect()
}

fn parse_target_plan(section_name: &str, args: Vec<OsString>) -> Result<S3TargetPlan, clap::Error> {
    let mut argv = vec![
        OsString::from("xtask verify remote s3"),
        section_name.to_owned().into(),
    ];
    argv.extend(args);
    TargetCli::try_parse_from(argv).and_then(|cli| target_format_to_plan(section_name, cli.target))
}

fn target_format_to_plan(
    section_name: &str,
    target: TargetFormat,
) -> Result<S3TargetPlan, clap::Error> {
    match target {
        TargetFormat::Homebrew => Ok(S3TargetPlan {
            root: PublishRoot::Homebrew,
            prefix: "homebrew".to_string(),
        }),
        TargetFormat::Scoop => Ok(S3TargetPlan {
            root: PublishRoot::Scoop,
            prefix: "scoop".to_string(),
        }),
        TargetFormat::Apt { options } => Ok(S3TargetPlan {
            root: PublishRoot::Apt,
            prefix: validate_target_prefix(section_name, options.prefix)?,
        }),
        TargetFormat::Rpm { options } => Ok(S3TargetPlan {
            root: PublishRoot::Rpm,
            prefix: validate_target_prefix(section_name, options.prefix)?,
        }),
    }
}

fn validate_target_prefix(section_name: &str, prefix: String) -> Result<String, clap::Error> {
    let prefix = trim_slashes(&prefix);
    if prefix.is_empty() {
        return Err(target_section_error(
            section_name,
            ErrorKind::ValueValidation,
            "prefix must not be empty",
        ));
    }
    Ok(prefix)
}

fn target_error(kind: ErrorKind, message: impl std::fmt::Display) -> clap::Error {
    TargetCli::command()
        .bin_name("xtask verify remote s3")
        .error(kind, message)
}

fn target_section_error(
    section_name: &str,
    kind: ErrorKind,
    message: impl std::fmt::Display,
) -> clap::Error {
    let mut command = TargetCli::command().bin_name("xtask verify remote s3");
    command.build();
    match command.find_subcommand_mut(section_name) {
        Some(subcommand) => subcommand.error(kind, message),
        None => command.error(kind, message),
    }
}

fn upload_order(upload: &PlannedUpload) -> u8 {
    let key = upload.key.as_str();
    if key.contains("/pool/") || key.starts_with("pool/") {
        return 0;
    }
    if key.ends_with(".tar.gz")
        || key.ends_with(".zip")
        || key.ends_with(".deb")
        || key.ends_with(".rpm")
    {
        return 1;
    }
    if key.ends_with("InRelease") {
        return 4;
    }
    if key.ends_with(".json") || key.ends_with(".rb") {
        return 3;
    }
    2
}

#[cfg(test)]
mod tests {
    use super::{
        PlannedUpload, RemoteArtifactState, parse_target_plans, plan_uploads, upload_order,
        verify_immutable_collision,
    };
    use crate::release::PublishRoot;

    #[test]
    fn apt_pool_file_maps_under_explicit_apt_prefix() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let common = temp.path().join("common");
        let deb = common.join("apt").join("pool/main/g/gmutils/file.deb");
        std::fs::create_dir_all(deb.parent().expect("deb should have a parent"))
            .expect("deb parent should be created");
        std::fs::write(&deb, "deb").expect("deb should be written");

        let uploads = plan_uploads(&common, &[PublishRoot::Apt], Some("releases/apt"))
            .expect("uploads should plan");

        assert!(
            uploads
                .iter()
                .any(|upload| upload.key == "releases/apt/pool/main/g/gmutils/file.deb")
        );
    }

    #[test]
    fn inrelease_sorts_after_release_gpg() {
        let release_gpg = PlannedUpload {
            path: "Release.gpg".into(),
            key: "apt/stable/dists/stable/Release.gpg".to_string(),
        };
        let in_release = PlannedUpload {
            path: "InRelease".into(),
            key: "apt/stable/dists/stable/InRelease".to_string(),
        };

        assert!(upload_order(&release_gpg) < upload_order(&in_release));
    }

    #[test]
    fn explicit_homebrew_root_excludes_scoop_and_apt_roots() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let common = temp.path().join("common");
        for path in [
            common.join("homebrew/gmutils.rb"),
            common.join("scoop/gmutils.json"),
            common.join("apt/dists/stable/InRelease"),
        ] {
            std::fs::create_dir_all(path.parent().expect("path should have a parent"))
                .expect("parent should be created");
            std::fs::write(path, "artifact").expect("artifact should be written");
        }

        let uploads =
            plan_uploads(&common, &[PublishRoot::Homebrew], None).expect("uploads should plan");

        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].key, "homebrew/gmutils.rb");
    }

    #[test]
    fn explicit_missing_root_fails() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let common = temp.path().join("common");

        let error = plan_uploads(&common, &[PublishRoot::Homebrew], None)
            .expect_err("missing explicit root should fail");

        assert!(
            error
                .to_string()
                .starts_with("requested publish root homebrew is missing at")
        );
    }

    #[test]
    fn empty_publish_plan_fails() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let common = temp.path().join("common");

        let error = plan_uploads(&common, &[], None).expect_err("empty plan should fail");

        assert_eq!(error.to_string(), "no staged artifacts found to publish");
    }

    #[test]
    fn apt_root_requires_explicit_apt_prefix() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let common = temp.path().join("common");
        let release = common.join("apt/dists/stable/InRelease");
        std::fs::create_dir_all(release.parent().expect("release should have a parent"))
            .expect("release parent should be created");
        std::fs::write(release, "release").expect("release should be written");

        let error = plan_uploads(&common, &[PublishRoot::Apt], None)
            .expect_err("apt root without prefix should fail");

        assert_eq!(
            error.to_string(),
            "apt prefix is required when publishing apt root"
        );
    }

    #[test]
    fn s3_targets_parse_prefixes_per_target() {
        let targets = [
            "homebrew",
            "scoop",
            "apt",
            "--prefix",
            "/download/apt/",
            "rpm",
            "--prefix",
            "download/rpm",
        ]
        .map(std::ffi::OsString::from);

        let plans = parse_target_plans(&targets).expect("s3 targets should parse");

        assert_eq!(plans.len(), 4);
        assert_eq!(plans[0].root, PublishRoot::Homebrew);
        assert_eq!(plans[0].prefix, "homebrew");
        assert_eq!(plans[1].root, PublishRoot::Scoop);
        assert_eq!(plans[1].prefix, "scoop");
        assert_eq!(plans[2].root, PublishRoot::Apt);
        assert_eq!(plans[2].prefix, "download/apt");
        assert_eq!(plans[3].root, PublishRoot::Rpm);
        assert_eq!(plans[3].prefix, "download/rpm");
    }

    #[test]
    fn s3_targets_apt_requires_prefix() {
        let error = parse_target_plans(&[std::ffi::OsString::from("apt")])
            .expect_err("apt target without prefix should fail");

        assert!(error.to_string().contains("--prefix"));
        assert!(
            error
                .to_string()
                .contains("Usage: xtask verify remote s3 apt")
        );
    }

    #[test]
    fn s3_targets_rpm_requires_prefix() {
        let error = parse_target_plans(&[std::ffi::OsString::from("rpm")])
            .expect_err("rpm target without prefix should fail");

        assert!(error.to_string().contains("--prefix"));
        assert!(
            error
                .to_string()
                .contains("Usage: xtask verify remote s3 rpm")
        );
    }

    #[test]
    fn immutable_collision_missing_passes() {
        verify_immutable_collision("homebrew/file.tar.gz", "abc", RemoteArtifactState::Missing)
            .expect("missing remote artifact should pass");
    }

    #[test]
    fn immutable_collision_same_hash_passes() {
        verify_immutable_collision(
            "homebrew/file.tar.gz",
            "abc",
            RemoteArtifactState::Present {
                sha256: "abc".to_string(),
            },
        )
        .expect("matching remote artifact should pass");
    }

    #[test]
    fn immutable_collision_different_hash_fails() {
        let error = verify_immutable_collision(
            "homebrew/file.tar.gz",
            "abc",
            RemoteArtifactState::Present {
                sha256: "def".to_string(),
            },
        )
        .expect_err("different remote artifact should fail");

        assert_eq!(
            error.to_string(),
            "remote immutable artifact homebrew/file.tar.gz already exists with different sha256 def"
        );
    }
}
