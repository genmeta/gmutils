mod brew;
mod container;
mod deb;
mod grouped;
mod package;
mod publish;
mod release_contract;
mod rpm;
mod scoop;
mod template;
mod version_cmp;

use std::{io::IsTerminal, path::PathBuf, process::Stdio};

use clap::{Parser, Subcommand, ValueEnum};
use snafu::{OptionExt, ResultExt, Whatever};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Parser)]
#[command(name = "xtask", about = "Build & packaging tasks for gmutils")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build package artifacts and write target/common manifests
    Package {
        /// Replace target/common/<kind>/manifest.toml without prompting
        #[arg(long)]
        overwrite_manifest: bool,
        /// Grouped package targets: deb/rpm/brew/scoop followed by target-local options
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        targets: Vec<std::ffi::OsString>,
    },
    /// Publish package manifests to a backend
    Publish {
        #[command(subcommand)]
        command: publish::PublishCommand,
    },
}

/// Supported target triples for .deb builds.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DebTarget {
    /// x86_64-unknown-linux-gnu
    #[value(name = "x86_64-unknown-linux-gnu")]
    X86_64,
    /// aarch64-unknown-linux-gnu
    #[value(name = "aarch64-unknown-linux-gnu")]
    Aarch64,
    /// armv7-unknown-linux-gnueabihf
    #[value(name = "armv7-unknown-linux-gnueabihf")]
    Armv7,
    /// i686-unknown-linux-gnu
    #[value(name = "i686-unknown-linux-gnu")]
    I686,
}

impl DebTarget {
    pub fn triple(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-unknown-linux-gnu",
            Self::Aarch64 => "aarch64-unknown-linux-gnu",
            Self::Armv7 => "armv7-unknown-linux-gnueabihf",
            Self::I686 => "i686-unknown-linux-gnu",
        }
    }
}

/// Supported target triples for .rpm builds.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RpmTarget {
    /// x86_64-unknown-linux-gnu -> x86_64
    #[value(name = "x86_64-unknown-linux-gnu")]
    X86_64,
    /// aarch64-unknown-linux-gnu -> aarch64
    #[value(name = "aarch64-unknown-linux-gnu")]
    Aarch64,
    /// armv7-unknown-linux-gnueabihf -> armv7hl
    #[value(name = "armv7-unknown-linux-gnueabihf")]
    Armv7,
    /// i686-unknown-linux-gnu -> i686
    #[value(name = "i686-unknown-linux-gnu")]
    I686,
}

impl RpmTarget {
    pub fn triple(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-unknown-linux-gnu",
            Self::Aarch64 => "aarch64-unknown-linux-gnu",
            Self::Armv7 => "armv7-unknown-linux-gnueabihf",
            Self::I686 => "i686-unknown-linux-gnu",
        }
    }

    /// RPM architecture name (matches rpmbuild --target= value).
    pub fn rpm_arch(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Armv7 => "armv7hl",
            Self::I686 => "i686",
        }
    }
}

/// Supported target triples for Homebrew builds.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum BrewTarget {
    /// aarch64-apple-darwin
    #[value(name = "aarch64-apple-darwin")]
    Aarch64,
    /// x86_64-apple-darwin
    #[value(name = "x86_64-apple-darwin")]
    X86_64,
}

impl BrewTarget {
    pub fn triple(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64-apple-darwin",
            Self::X86_64 => "x86_64-apple-darwin",
        }
    }
}

/// Supported target triples for Scoop builds.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ScoopTarget {
    /// x86_64-pc-windows-msvc
    #[value(name = "x86_64-pc-windows-msvc")]
    X86_64,
    /// i686-pc-windows-msvc
    #[value(name = "i686-pc-windows-msvc")]
    I686,
}

impl ScoopTarget {
    pub fn triple(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-pc-windows-msvc",
            Self::I686 => "i686-pc-windows-msvc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildProfile {
    Release,
    Debug,
}

impl BuildProfile {
    #[allow(dead_code)]
    fn from_debug(debug: bool) -> Self {
        if debug { Self::Debug } else { Self::Release }
    }

    pub fn cargo_profile_args(self) -> Vec<&'static str> {
        match self {
            Self::Release => vec!["--release"],
            Self::Debug => Vec::new(),
        }
    }

    pub fn target_dir_name(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Debug => "debug",
        }
    }
}

/// Resolve the workspace target directory via cargo_metadata.
fn target_dir() -> Result<PathBuf, Whatever> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .exec()
        .whatever_context("failed to read cargo metadata")?;
    Ok(metadata.target_directory.into_std_path_buf())
}

/// Package version from cargo_metadata.
fn package_version(name: &str) -> Result<String, Whatever> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .whatever_context("failed to read cargo metadata")?;
    let pkg = metadata
        .packages
        .iter()
        .find(|p| p.name == name)
        .whatever_context(format!("package {name} not found in workspace"))?;
    Ok(pkg.version.to_string())
}

/// Package metadata.
struct PackageMeta {
    version: String,
}

fn package_meta(name: &str) -> Result<PackageMeta, Whatever> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .whatever_context("failed to read cargo metadata")?;
    let pkg = metadata
        .packages
        .iter()
        .find(|p| p.name == name)
        .whatever_context(format!("package {name} not found in workspace"))?;
    Ok(PackageMeta {
        version: pkg.version.to_string(),
    })
}

/// Compute SHA-256 hex digest of a file.
async fn sha256_file(path: &std::path::Path) -> Result<String, Whatever> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        use std::io::Read;

        use sha2::Digest;

        let mut file = std::fs::File::open(&path)
            .whatever_context(format!("failed to open {}", path.display()))?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0; 8192];
        loop {
            let read = file
                .read(&mut buffer)
                .whatever_context(format!("failed to read {}", path.display()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hex_lower(hasher.finalize().as_ref()))
    })
    .await
    .whatever_context("sha256 task panicked")?
}

/// Run an external command, checking its exit status.
pub async fn run_cmd(cmd: &mut tokio::process::Command) -> Result<(), Whatever> {
    let status = cmd
        .status()
        .await
        .whatever_context("failed to spawn process")?;
    snafu::ensure_whatever!(status.success(), "command exited with {status}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser, error::ErrorKind};

    use super::{BuildProfile, Cli, Command, publish};

    const RELEASE_WORKFLOW: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../.github/workflows/release.yml"
    ));

    fn subcommand_names(command: &clap::Command) -> Vec<&str> {
        command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect()
    }

    #[test]
    fn release_profile_uses_release_cargo_flag_and_dir() {
        assert_eq!(BuildProfile::Release.cargo_profile_args(), ["--release"]);
        assert_eq!(BuildProfile::Release.target_dir_name(), "release");
    }

    #[test]
    fn debug_profile_omits_release_cargo_flag_and_uses_debug_dir() {
        assert!(BuildProfile::Debug.cargo_profile_args().is_empty());
        assert_eq!(BuildProfile::Debug.target_dir_name(), "debug");
    }

    #[test]
    fn release_pipeline_subcommands_are_package_and_publish() {
        let command = Cli::command();
        let names = subcommand_names(&command);

        assert!(names.contains(&"package"));
        assert!(names.contains(&"publish"));
        assert!(!names.contains(&"dist"));
        assert!(!names.contains(&"stage"));
        assert!(!names.contains(&"verify"));
    }

    #[test]
    fn package_accepts_grouped_targets_and_overwrite_flag() {
        let cli = Cli::try_parse_from([
            "xtask",
            "package",
            "--overwrite-manifest",
            "deb",
            "--target",
            "x86_64-unknown-linux-gnu",
            "rpm",
            "--target",
            "aarch64-unknown-linux-gnu",
        ])
        .expect("package command should parse");

        match cli.command {
            Command::Package {
                overwrite_manifest,
                targets,
            } => {
                assert!(overwrite_manifest);
                assert_eq!(
                    targets,
                    [
                        "deb",
                        "--target",
                        "x86_64-unknown-linux-gnu",
                        "rpm",
                        "--target",
                        "aarch64-unknown-linux-gnu",
                    ]
                    .map(std::ffi::OsString::from)
                );
            }
            _ => panic!("expected package command"),
        }
    }

    #[test]
    fn publish_s3_accepts_grouped_targets() {
        let cli = Cli::try_parse_from(["xtask", "publish", "s3", "--dry-run", "deb", "brew"])
            .expect("publish command should parse");

        match cli.command {
            Command::Publish { command } => match command {
                publish::PublishCommand::S3 { options, targets } => {
                    assert!(options.dry_run);
                    assert_eq!(targets[0], std::ffi::OsString::from("deb"));
                    assert_eq!(targets[1], std::ffi::OsString::from("brew"));
                }
            },
            _ => panic!("expected publish command"),
        }
    }

    #[test]
    fn old_release_commands_are_rejected() {
        for command in ["dist", "stage", "verify"] {
            let error =
                Cli::try_parse_from(["xtask", command]).expect_err("old command should fail");
            assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
        }
    }

    #[test]
    fn release_workflow_publish_commands_are_tag_mode_safe() {
        assert!(!RELEASE_WORKFLOW.contains("publish_args=()"));
        assert!(!RELEASE_WORKFLOW.contains("\"${publish_args[@]}\""));
        assert!(RELEASE_WORKFLOW.contains("DHTTP_ROOT_CA: ${{ vars.DHTTP_ROOT_CA }}"));
        assert!(!RELEASE_WORKFLOW.contains("keychain/root.crt"));
        assert!(!RELEASE_WORKFLOW.contains("DHTTP_ROOT_CA: ${{ github.workspace }}"));
        assert!(!RELEASE_WORKFLOW.contains("--endpoint-url"));
        assert!(!RELEASE_WORKFLOW.contains("--bucket"));
        assert!(!RELEASE_WORKFLOW.contains("--prefix"));
        assert!(!RELEASE_WORKFLOW.contains("--public-base-url"));
        assert!(RELEASE_WORKFLOW.contains("\"${publish_cmd[@]}\" deb"));
        assert!(RELEASE_WORKFLOW.contains("\"${publish_cmd[@]}\" rpm"));
        assert!(RELEASE_WORKFLOW.contains("\"${publish_cmd[@]}\" scoop"));
        assert!(RELEASE_WORKFLOW.contains("\"${publish_cmd[@]}\" brew"));
        assert_eq!(
            RELEASE_WORKFLOW
                .matches("publish_cmd=(cargo xtask publish s3)")
                .count(),
            4
        );
    }

    #[test]
    fn release_workflow_uploads_product_assets_to_github_release() {
        assert!(RELEASE_WORKFLOW.contains("contents: write"));
        assert!(RELEASE_WORKFLOW.contains("  github-release:"));
        assert_eq!(RELEASE_WORKFLOW.matches("needs: github-release").count(), 4);
        assert_eq!(
            RELEASE_WORKFLOW
                .matches("gh release upload \"$GITHUB_REF_NAME\"")
                .count(),
            4
        );
        assert_eq!(
            RELEASE_WORKFLOW
                .matches("gh release create \"$GITHUB_REF_NAME\"")
                .count(),
            1
        );
        assert!(RELEASE_WORKFLOW.contains("git for-each-ref \"$tag_ref\" --format='%(contents)'"));
        assert!(RELEASE_WORKFLOW.contains("## Authentication and provenance"));
        assert!(RELEASE_WORKFLOW.contains("--notes-file \"$notes_file\""));
        assert!(!RELEASE_WORKFLOW.contains("--notes-from-tag               ||"));
        assert!(RELEASE_WORKFLOW.contains("assets=(target/*/release/deb/*.deb)"));
        assert!(RELEASE_WORKFLOW.contains("assets=(target/*/release/rpm/*.rpm)"));
        assert!(
            RELEASE_WORKFLOW
                .contains("assets=(target/*/release/scoop/*.zip target/common/scoop/*.json)")
        );
        assert!(
            RELEASE_WORKFLOW
                .contains("assets=(target/*/release/brew/*.tar.gz target/common/brew/*.rb)")
        );
    }

    #[test]
    fn release_workflow_homebrew_tap_updates_root_formula() {
        assert!(RELEASE_WORKFLOW.contains("id: homebrew_destination"));
        assert!(!RELEASE_WORKFLOW.contains("download.genmeta.net"));
        assert!(RELEASE_WORKFLOW.contains("tomllib.loads(Path(\"xtask/release.toml\")"));
        assert!(RELEASE_WORKFLOW.contains("formula_dest=\"$tap_dir/$FORMULA_NAME\""));
        assert!(RELEASE_WORKFLOW.contains("git status --porcelain -- \"$FORMULA_NAME\""));
        assert!(RELEASE_WORKFLOW.contains("git add \"$FORMULA_NAME\""));
        assert!(!RELEASE_WORKFLOW.contains("Formula/$FORMULA_NAME"));
    }

    #[test]
    fn public_package_manifests_declare_apache_2_license() {
        let workspace_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask manifest should be under workspace");
        let root_manifest_path = workspace_dir.join("Cargo.toml");
        let root_manifest = std::fs::read_to_string(&root_manifest_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", root_manifest_path.display()));
        assert!(root_manifest.contains("license = \"Apache-2.0\""));

        for manifest in [
            "genmeta/Cargo.toml",
            "genmeta-access/Cargo.toml",
            "genmeta-curl/Cargo.toml",
            "genmeta-discover/Cargo.toml",
            "genmeta-doctor/Cargo.toml",
            "genmeta-identity/Cargo.toml",
            "genmeta-nat/Cargo.toml",
            "genmeta-nslookup/Cargo.toml",
            "genmeta-proxy/Cargo.toml",
            "genmeta-ssh/Cargo.toml",
        ] {
            let manifest_path = workspace_dir.join(manifest);
            let contents = std::fs::read_to_string(&manifest_path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", manifest_path.display()));
            assert!(
                contents.contains("license.workspace = true"),
                "{manifest} should inherit workspace Apache-2.0 license"
            );
        }
    }

    #[test]
    fn debian_package_metadata_declares_apache_2_license() {
        let copyright_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("deb")
            .join("copyright");
        let contents = std::fs::read_to_string(&copyright_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", copyright_path.display()));
        assert!(contents.contains("License: Apache-2.0"));
    }
}

/// Run an external command quietly, suppressing stdout/stderr.
pub async fn run_cmd_quiet(cmd: &mut tokio::process::Command) -> Result<(), Whatever> {
    let status = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .whatever_context("failed to spawn process")?;
    snafu::ensure_whatever!(status.success(), "command exited with {status}");
    Ok(())
}

fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (stderr, guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    guard
}

#[snafu::report]
#[tokio::main]
async fn main() -> Result<(), Whatever> {
    let _guard = init_tracing();

    let cli = Cli::parse();
    match cli.command {
        Command::Package {
            overwrite_manifest,
            targets,
        } => {
            package::run(package::PackageOptions {
                overwrite_manifest,
                targets,
            })
            .await?
        }
        Command::Publish { command } => publish::run(command).await?,
    }
    Ok(())
}
