use std::path::{Path, PathBuf};

use snafu::{ResultExt, Whatever};
use tracing::info;

use crate::{
    package_meta,
    release::{
        artifact::{
            ArtifactEntry, ArtifactRoot, ReleaseManifest, copy_artifact, read_manifest,
            sha256_file, write_manifest,
        },
        paths::{common_paths, promote_staged_outputs, recreate_dir},
    },
    target_dir,
};

const CARGO_NAME: &str = "genmeta";
const PACKAGE_NAME: &str = "gmutils";
const BREW_DL_URL: &str = "https://download.genmeta.net/homebrew";
const SUPPORTED_TRIPLES: [&str; 2] = ["aarch64-apple-darwin", "x86_64-apple-darwin"];

#[derive(Debug, Clone)]
struct ArchiveInfo {
    triple: String,
    archive_name: String,
    sha256: String,
}

#[derive(Debug)]
struct ArchiveSource {
    triple: String,
    archive_name: String,
    source: PathBuf,
}

#[derive(Debug)]
struct HomebrewInputs {
    archives: Vec<ArchiveSource>,
    content: String,
}

fn brew_on_block(triple: &str) -> Result<&'static str, Whatever> {
    match triple {
        "aarch64-apple-darwin" => Ok("on_arm"),
        "x86_64-apple-darwin" => Ok("on_intel"),
        _ => snafu::whatever!("unsupported brew target triple: {triple}"),
    }
}

fn generate_formula(
    name: &str,
    description: &str,
    version: &str,
    homepage: &str,
    license: &str,
    archives: &[ArchiveInfo],
    content: &str,
) -> Result<String, Whatever> {
    let class_name = {
        let mut chars = name.chars();
        match chars.next() {
            Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            None => String::new(),
        }
    };
    let desc = description.replace('"', "\\\"");
    let homepage = homepage.replace('"', "\\\"");
    let license = license.replace('"', "\\\"");

    let mut lines = vec![
        format!("class {class_name} < Formula"),
        format!("  desc \"{desc}\""),
        format!("  version \"{version}\""),
        format!("  homepage \"{homepage}\""),
    ];
    if !license.is_empty() {
        lines.push(format!("  license \"{license}\""));
    }
    lines.push(String::new());

    for info in archives {
        let block = brew_on_block(&info.triple)?;
        lines.extend([
            format!("  {block} do"),
            format!("    url \"{BREW_DL_URL}/{}\"", info.archive_name),
            format!("    sha256 \"{}\"", info.sha256),
            "  end".to_string(),
            String::new(),
        ]);
    }

    lines.push(content.trim_end().to_string());
    lines.push("end".to_string());
    lines.push(String::new());

    Ok(lines.join("\n"))
}

pub async fn stage() -> Result<(), Whatever> {
    info!("starting homebrew stage");
    let meta = package_meta(CARGO_NAME)?;
    let workspace_root = workspace_root()?;
    let target_dir = target_dir()?;
    let paths = common_paths()?;
    let inputs = validate_homebrew_inputs(&target_dir, &workspace_root, &meta.version).await?;

    let manifest = read_existing_manifest(&paths.manifest, &meta.version).await?;
    let staging = paths.root.join("homebrew.staging");
    recreate_dir(&staging).await?;

    let mut archives = Vec::new();
    for archive in inputs.archives {
        let destination = staging.join(&archive.archive_name);
        copy_artifact(&archive.source, &destination).await?;
        let sha256 = sha256_file(&destination).await?;
        info!(path = %destination.display(), "staged homebrew archive");
        archives.push(ArchiveInfo {
            triple: archive.triple,
            archive_name: archive.archive_name,
            sha256,
        });
    }

    let formula = generate_formula(
        PACKAGE_NAME,
        &meta.description,
        &meta.version,
        &meta.homepage,
        &meta.license,
        &archives,
        &inputs.content,
    )?;
    let formula_path = staging.join(format!("{PACKAGE_NAME}.rb"));
    tokio::fs::write(&formula_path, formula)
        .await
        .whatever_context(format!("failed to write {}", formula_path.display()))?;
    let formula_sha256 = sha256_file(&formula_path).await?;

    let manifest = merge_homebrew_manifest(
        manifest,
        &meta.version,
        archives,
        format!("{PACKAGE_NAME}.rb"),
        formula_sha256,
    );
    let manifest_staging = paths.root.join("manifest.toml.staging");
    write_manifest(&manifest_staging, &manifest).await?;

    promote_staged_outputs(
        "homebrew",
        &staging,
        &paths.homebrew,
        &manifest_staging,
        &paths.manifest,
    )
    .await?;
    info!(path = %paths.homebrew.join(format!("{PACKAGE_NAME}.rb")).display(), "staged homebrew formula");

    info!("finished homebrew stage");
    Ok(())
}

fn workspace_root() -> Result<PathBuf, Whatever> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .whatever_context("failed to read cargo metadata")?;
    Ok(metadata.workspace_root.into_std_path_buf())
}

async fn validate_homebrew_inputs(
    target_dir: &Path,
    workspace_root: &Path,
    version: &str,
) -> Result<HomebrewInputs, Whatever> {
    let mut archives = Vec::new();
    for triple in SUPPORTED_TRIPLES {
        let archive_name = format!("{PACKAGE_NAME}-{version}-{triple}.tar.gz");
        let source = target_dir
            .join(triple)
            .join("release")
            .join("brew")
            .join(&archive_name);
        if tokio::fs::try_exists(&source)
            .await
            .whatever_context(format!("failed to inspect {}", source.display()))?
        {
            archives.push(ArchiveSource {
                triple: triple.to_string(),
                archive_name,
                source,
            });
        } else {
            info!(path = %source.display(), "skipping missing homebrew archive");
        }
    }

    snafu::ensure_whatever!(
        !archives.is_empty(),
        "no homebrew archives found in target directories"
    );

    let content_path = workspace_root.join(CARGO_NAME).join("homebrew_content.rb");
    let content = tokio::fs::read_to_string(&content_path)
        .await
        .whatever_context(format!("failed to read {}", content_path.display()))?;

    Ok(HomebrewInputs { archives, content })
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

fn merge_homebrew_manifest(
    mut manifest: ReleaseManifest,
    version: &str,
    archives: Vec<ArchiveInfo>,
    formula_path: String,
    formula_sha256: String,
) -> ReleaseManifest {
    manifest.package = PACKAGE_NAME.to_string();
    manifest.version = version.to_string();
    manifest
        .artifacts
        .retain(|artifact| artifact.root != ArtifactRoot::Homebrew);

    for archive in archives {
        manifest.artifacts.push(ArtifactEntry {
            root: ArtifactRoot::Homebrew,
            path: archive.archive_name,
            sha256: archive.sha256,
            immutable: true,
        });
    }

    manifest.artifacts.push(ArtifactEntry {
        root: ArtifactRoot::Homebrew,
        path: formula_path,
        sha256: formula_sha256,
        immutable: false,
    });

    manifest
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{ArchiveInfo, generate_formula, merge_homebrew_manifest, validate_homebrew_inputs};
    use crate::release::{
        artifact::{ArtifactEntry, ArtifactRoot, ReleaseManifest, write_manifest},
        paths::promote_staged_outputs,
    };

    #[test]
    fn formula_uses_arch_blocks_archives_and_install_content() {
        let formula = generate_formula(
            "gmutils",
            "Genmeta CLI tools",
            "0.5.1",
            "https://genmeta.net",
            "MIT",
            &[
                ArchiveInfo {
                    triple: "aarch64-apple-darwin".to_string(),
                    archive_name: "gmutils-0.5.1-aarch64-apple-darwin.tar.gz".to_string(),
                    sha256: "arm-sha".to_string(),
                },
                ArchiveInfo {
                    triple: "x86_64-apple-darwin".to_string(),
                    archive_name: "gmutils-0.5.1-x86_64-apple-darwin.tar.gz".to_string(),
                    sha256: "intel-sha".to_string(),
                },
            ],
            r#"  def install
    bin.install "genmeta"
  end"#,
        )
        .expect("formula should generate");

        assert!(formula.contains("on_arm do"));
        assert!(formula.contains("on_intel do"));
        assert!(formula.contains("gmutils-0.5.1-aarch64-apple-darwin.tar.gz"));
        assert!(formula.contains("gmutils-0.5.1-x86_64-apple-darwin.tar.gz"));
        assert!(formula.contains("bin.install \"genmeta\""));
    }

    #[test]
    fn manifest_merge_preserves_non_homebrew_entries_and_replaces_stale_homebrew() {
        let existing = ReleaseManifest {
            schema_version: 1,
            package: "gmutils".to_string(),
            version: "old".to_string(),
            artifacts: vec![
                ArtifactEntry {
                    root: ArtifactRoot::Scoop,
                    path: "gmutils.json".to_string(),
                    sha256: "scoop-sha".to_string(),
                    immutable: false,
                },
                ArtifactEntry {
                    root: ArtifactRoot::Homebrew,
                    path: "stale.tar.gz".to_string(),
                    sha256: "stale-sha".to_string(),
                    immutable: true,
                },
            ],
        };

        let merged = merge_homebrew_manifest(
            existing,
            "0.5.1",
            vec![ArchiveInfo {
                triple: "aarch64-apple-darwin".to_string(),
                archive_name: "gmutils-0.5.1-aarch64-apple-darwin.tar.gz".to_string(),
                sha256: "arm-sha".to_string(),
            }],
            "gmutils.rb".to_string(),
            "formula-sha".to_string(),
        );

        assert!(
            merged
                .artifacts
                .iter()
                .any(|artifact| artifact.root == ArtifactRoot::Scoop
                    && artifact.path == "gmutils.json"
                    && artifact.sha256 == "scoop-sha")
        );
        assert!(
            !merged
                .artifacts
                .iter()
                .any(|artifact| artifact.path == "stale.tar.gz")
        );
        assert!(
            merged
                .artifacts
                .iter()
                .any(|artifact| artifact.root == ArtifactRoot::Homebrew
                    && artifact.path == "gmutils-0.5.1-aarch64-apple-darwin.tar.gz"
                    && artifact.immutable)
        );
        assert!(
            merged
                .artifacts
                .iter()
                .any(|artifact| artifact.root == ArtifactRoot::Homebrew
                    && artifact.path == "gmutils.rb"
                    && !artifact.immutable)
        );
    }

    #[tokio::test]
    async fn promotion_failure_restores_previous_homebrew_and_manifest() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let common = temp.path().join("common");
        let homebrew = common.join("homebrew");
        let manifest = common.join("manifest.toml");
        let homebrew_staging = common.join("homebrew.staging");
        let missing_manifest_staging = common.join("manifest.toml.staging");

        tokio::fs::create_dir_all(&homebrew)
            .await
            .expect("homebrew dir should be created");
        tokio::fs::write(homebrew.join("sentinel.txt"), "old-homebrew")
            .await
            .expect("old homebrew sentinel should be written");
        tokio::fs::write(&manifest, "old-manifest")
            .await
            .expect("old manifest should be written");
        tokio::fs::create_dir_all(&homebrew_staging)
            .await
            .expect("staging dir should be created");
        tokio::fs::write(homebrew_staging.join("sentinel.txt"), "new-homebrew")
            .await
            .expect("new homebrew sentinel should be written");

        let error = promote_staged_outputs(
            "homebrew",
            &homebrew_staging,
            &homebrew,
            &missing_manifest_staging,
            &manifest,
        )
        .await
        .expect_err("missing manifest staging should fail promotion");

        assert!(
            error
                .to_string()
                .starts_with("failed to promote homebrew staged outputs")
        );
        assert_eq!(
            tokio::fs::read_to_string(homebrew.join("sentinel.txt"))
                .await
                .expect("old homebrew should be restored"),
            "old-homebrew"
        );
        assert_eq!(
            tokio::fs::read_to_string(&manifest)
                .await
                .expect("old manifest should be restored"),
            "old-manifest"
        );
    }

    #[tokio::test]
    async fn input_validation_failure_does_not_mutate_prior_homebrew_state() {
        let temp = tempfile::tempdir().expect("temp dir should be created");
        let target_dir = temp.path().join("target");
        let workspace_root = temp.path().join("workspace");
        let homebrew_dir = target_dir.join("common").join("homebrew");
        tokio::fs::create_dir_all(&homebrew_dir)
            .await
            .expect("homebrew dir should be created");
        let sentinel = homebrew_dir.join("sentinel.txt");
        tokio::fs::write(&sentinel, "keep")
            .await
            .expect("sentinel should be written");
        let manifest_path = target_dir.join("common").join("manifest.toml");
        write_manifest(
            &manifest_path,
            &ReleaseManifest {
                schema_version: 1,
                package: "gmutils".to_string(),
                version: "0.5.0".to_string(),
                artifacts: vec![ArtifactEntry {
                    root: ArtifactRoot::Scoop,
                    path: "gmutils.json".to_string(),
                    sha256: "scoop-sha".to_string(),
                    immutable: false,
                }],
            },
        )
        .await
        .expect("manifest should be written");
        let manifest_before = tokio::fs::read_to_string(&manifest_path)
            .await
            .expect("manifest should be readable");

        let error = validate_homebrew_inputs(&target_dir, &workspace_root, "0.5.1")
            .await
            .expect_err("missing archives should fail validation");

        assert!(error.to_string().starts_with("no homebrew archives found"));
        assert_eq!(
            tokio::fs::read_to_string(&sentinel)
                .await
                .expect("sentinel should remain"),
            "keep"
        );
        assert_eq!(
            tokio::fs::read_to_string(&manifest_path)
                .await
                .expect("manifest should remain"),
            manifest_before
        );
        assert!(!Path::new(&workspace_root.join("genmeta").join("homebrew_content.rb")).exists());
    }
}
