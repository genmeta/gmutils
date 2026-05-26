mod brew;
mod container;
mod deb;
mod release;
mod rpm;
mod scoop;

use std::{io::IsTerminal, path::PathBuf, process::Stdio};

use clap::{Parser, Subcommand, ValueEnum};
use snafu::{OptionExt, ResultExt, Whatever};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "xtask", about = "Build & packaging tasks for gmutils")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Distribution packaging
    Dist {
        /// Grouped dist targets: deb/rpm/homebrew/scoop followed by target-local options
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        targets: Vec<std::ffi::OsString>,
    },
    /// Assemble publishable artifacts under target/common
    Stage {
        #[command(subcommand)]
        format: release::StageFormat,
    },
    /// Validate target/common before publishing
    Verify {
        #[command(flatten)]
        options: release::VerifyOptions,
    },
    /// Publish staged artifacts
    Publish {
        #[command(subcommand)]
        target: release::PublishTarget,
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

#[derive(Subcommand)]
enum DistFormat {
    /// Build .deb packages (via Docker container + cargo-zigbuild)
    Deb {
        /// Target triples to build for
        #[arg(long = "target", required = true)]
        targets: Vec<DebTarget>,
        /// Build debug-profile binaries instead of release-profile binaries
        #[arg(long)]
        debug: bool,
        /// Sibling crate directories to bind-mount into the build container
        /// at `/{basename}`, matching `path = "../{basename}"` in Cargo.toml.
        /// Repeatable. Each path must exist and be a directory.
        #[arg(long = "sibling")]
        siblings: Vec<PathBuf>,
    },
    /// Build .rpm packages (via Fedora Docker container + cargo-zigbuild + rpmbuild)
    Rpm {
        /// Target triples to build for
        #[arg(long = "target", required = true)]
        targets: Vec<RpmTarget>,
        /// Sibling crate directories to bind-mount into the build container.
        #[arg(long = "sibling")]
        siblings: Vec<PathBuf>,
    },
    /// Build Homebrew archives
    Homebrew {
        /// Target triples to build for
        #[arg(long = "target", required = true)]
        targets: Vec<BrewTarget>,
    },
    /// Build Scoop archives
    Scoop {
        /// Target triples to build for
        #[arg(long = "target", required = true)]
        targets: Vec<ScoopTarget>,
    },
}

#[derive(Parser)]
struct DistCli {
    #[command(subcommand)]
    format: DistFormat,
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

/// Package metadata (version, description, homepage, license).
struct PackageMeta {
    version: String,
    description: String,
    homepage: String,
    license: String,
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
        description: pkg.description.clone().unwrap_or_default(),
        homepage: pkg.homepage.clone().unwrap_or_default(),
        license: pkg.license.clone().unwrap_or_default(),
    })
}

/// Compute SHA-256 hex digest of a file.
async fn sha256_file(path: &std::path::Path) -> Result<String, Whatever> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        use sha2::Digest;
        let mut file = std::fs::File::open(&path)
            .whatever_context(format!("failed to open {}", path.display()))?;
        let mut hasher = sha2::Sha256::new();
        std::io::copy(&mut file, &mut hasher)
            .whatever_context(format!("failed to read {}", path.display()))?;
        Ok(format!("{:x}", hasher.finalize()))
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
    use clap::{CommandFactory, Parser, ValueEnum, error::ErrorKind};

    use super::{BuildProfile, Cli, Command, parse_dist_format, release::PublishRoot};

    fn subcommand<'a>(command: &'a clap::Command, name: &str) -> &'a clap::Command {
        command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == name)
            .expect("subcommand should be registered")
    }

    fn subcommand_names(command: &clap::Command) -> Vec<&str> {
        command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect()
    }

    fn argument_longs(command: &clap::Command) -> Vec<&str> {
        command
            .get_arguments()
            .filter_map(clap::Arg::get_long)
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
    fn release_pipeline_subcommands_are_registered() {
        let command = Cli::command();
        let names = subcommand_names(&command);

        assert!(names.contains(&"stage"));
        assert!(names.contains(&"verify"));
        assert!(names.contains(&"publish"));
        assert!(!names.contains(&"tap"));
    }

    #[test]
    fn release_pipeline_uses_homebrew_and_apt_command_names() {
        let command = Cli::command();
        let stage_names = subcommand_names(subcommand(&command, "stage"));

        assert!(stage_names.contains(&"apt"));
        assert!(!stage_names.contains(&"ppa"));
    }

    #[test]
    fn dist_accepts_grouped_targets_as_trailing_args() {
        let cli = Cli::try_parse_from([
            "xtask",
            "dist",
            "deb",
            "--target",
            "x86_64-unknown-linux-gnu",
            "rpm",
            "--target",
            "aarch64-unknown-linux-gnu",
            "homebrew",
            "--target",
            "x86_64-apple-darwin",
        ])
        .expect("grouped dist targets should parse at outer level");

        match cli.command {
            Command::Dist { targets } => {
                assert_eq!(
                    targets,
                    [
                        "deb",
                        "--target",
                        "x86_64-unknown-linux-gnu",
                        "rpm",
                        "--target",
                        "aarch64-unknown-linux-gnu",
                        "homebrew",
                        "--target",
                        "x86_64-apple-darwin",
                    ]
                    .map(std::ffi::OsString::from)
                );
            }
            _ => panic!("expected dist command"),
        }
    }

    #[test]
    fn dist_help_mentions_grouped_targets() {
        let help = subcommand(&Cli::command(), "dist")
            .clone()
            .render_long_help()
            .to_string();

        assert!(help.contains("Grouped dist targets: deb/rpm/homebrew/scoop"));
    }

    #[test]
    fn dist_target_local_help_remains_clap_display_help() {
        let error = match parse_dist_format("deb", [std::ffi::OsString::from("--help")]) {
            Ok(_) => panic!("target-local help should be reported as clap display help"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        assert!(error.to_string().contains("Build .deb packages"));
        assert!(error.to_string().contains("Usage: xtask dist deb"));
    }

    #[test]
    fn dist_target_local_parse_errors_use_clap_usage() {
        let error = match parse_dist_format("deb", [std::ffi::OsString::from("--bogus")]) {
            Ok(_) => panic!("invalid target-local options should be reported as clap errors"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        assert!(error.to_string().contains("Usage: xtask dist deb"));
        assert!(
            !error
                .to_string()
                .contains("failed to parse dist deb options")
        );
    }

    #[test]
    fn release_publish_uses_root_and_nested_tap_command_names() {
        let command = Cli::command();
        let publish = subcommand(&command, "publish");
        let publish_names = subcommand_names(publish);
        let s3_options = argument_longs(subcommand(publish, "s3"));

        assert!(publish_names.contains(&"tap"));
        assert!(s3_options.contains(&"root"));
        assert!(!s3_options.contains(&"only"));
    }

    #[test]
    fn publish_roots_are_registered() {
        let names = PublishRoot::value_variants()
            .iter()
            .map(|root| {
                root.to_possible_value()
                    .expect("publish root should have a possible value")
                    .get_name()
                    .to_string()
            })
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["homebrew", "scoop", "apt"]);
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

fn parse_dist_format<I, T>(section_name: &str, args: I) -> Result<DistFormat, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString>,
{
    let mut argv = vec![
        std::ffi::OsString::from("xtask dist"),
        section_name.to_owned().into(),
    ];
    argv.extend(args.into_iter().map(Into::into));
    DistCli::try_parse_from(argv).map(|cli| cli.format)
}

async fn run_dist_sections(tokens: Vec<std::ffi::OsString>) -> Result<(), Whatever> {
    let sections =
        release::grouped::parse_grouped_targets(&tokens, &["deb", "rpm", "homebrew", "scoop"])?;

    for section in sections {
        let format = parse_dist_format(&section.name, section.args).unwrap_or_else(|error| {
            error.exit();
        });
        match format {
            DistFormat::Deb {
                targets,
                debug,
                siblings,
            } => deb::run(&targets, BuildProfile::from_debug(debug), &siblings).await?,
            DistFormat::Rpm { targets, siblings } => rpm::run(&targets, &siblings).await?,
            DistFormat::Homebrew { targets } => brew::run(&targets).await?,
            DistFormat::Scoop { targets } => scoop::run(&targets).await?,
        }
    }

    Ok(())
}

#[snafu::report]
#[tokio::main]
async fn main() -> Result<(), Whatever> {
    let _guard = init_tracing();

    let cli = Cli::parse();
    match cli.command {
        Command::Dist { targets } => run_dist_sections(targets).await?,
        Command::Stage { format } => release::stage(format).await?,
        Command::Verify { options } => release::verify(options).await?,
        Command::Publish { target } => release::publish(target).await?,
    }
    Ok(())
}
