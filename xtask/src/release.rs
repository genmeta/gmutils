pub mod apt;
pub mod artifact;
pub mod grouped;
pub mod homebrew;
pub mod paths;
pub mod rpm;
pub mod s3;
pub mod scoop;
pub mod tap;
pub mod verify;

use std::{ffi::OsString, path::PathBuf};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use snafu::Whatever;

#[derive(Debug, Subcommand)]
pub enum StageFormat {
    /// Stage Homebrew formulae and archives
    Homebrew,
    /// Stage Scoop manifests and archives
    Scoop,
    /// Stage APT repository packages and metadata
    Apt {
        #[command(flatten)]
        options: AptOptions,
    },
    /// Stage RPM packages
    Rpm,
}

#[derive(Debug, Parser)]
struct StageCli {
    #[command(subcommand)]
    format: StageFormat,
}

#[derive(Debug)]
pub enum StageSection {
    Homebrew,
    Scoop,
    Apt(AptOptions),
    Rpm,
}

#[derive(Debug, Clone, Args)]
pub struct AptOptions {
    /// APT suite name
    #[arg(long)]
    pub suite: String,
    /// Package components to stage
    #[arg(long = "component", default_values_t = default_components())]
    pub components: Vec<String>,
    /// ASCII-armored GPG private key file used to sign Release metadata
    #[arg(long)]
    pub key_file: PathBuf,
    /// Expected full signing key fingerprint
    #[arg(long)]
    pub fingerprint: String,
    /// Optional file containing the GPG key passphrase
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct VerifyOptions {}

#[derive(Debug, Subcommand)]
pub enum PublishTarget {
    /// Publish staged artifacts to S3
    S3 {
        #[command(flatten)]
        options: S3Options,
    },
    /// Publish Homebrew formulae to a tap checkout
    Tap {
        #[command(flatten)]
        options: TapOptions,
    },
}

#[derive(Debug, Clone, Args)]
pub struct S3Options {
    /// S3 endpoint URL
    #[arg(long)]
    pub endpoint_url: String,
    /// S3 bucket name
    #[arg(long)]
    pub bucket: String,
    /// File containing AWS access key id
    #[arg(long)]
    pub access_key_id_file: PathBuf,
    /// File containing AWS secret access key
    #[arg(long)]
    pub secret_access_key_file: PathBuf,
    /// Upload selected staged roots: homebrew, scoop, apt
    #[arg(long = "root", value_enum, value_delimiter = ',')]
    pub roots: Vec<PublishRoot>,
    /// Remote prefix for APT repository files
    #[arg(long)]
    pub apt_prefix: Option<String>,
    /// Print planned uploads without writing to S3
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct TapOptions {
    /// Homebrew tap repository checkout path
    pub repo: PathBuf,
    /// Commit changes after copying formulae
    #[arg(long)]
    pub commit: bool,
    /// Push the tap repository after committing
    #[arg(long)]
    pub push: bool,
    /// Print planned tap updates without mutating the repository
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PublishRoot {
    /// target/common/homebrew
    Homebrew,
    /// target/common/scoop
    Scoop,
    /// target/common/apt
    Apt,
}

impl std::fmt::Display for PublishRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Homebrew => formatter.write_str("homebrew"),
            Self::Scoop => formatter.write_str("scoop"),
            Self::Apt => formatter.write_str("apt"),
        }
    }
}

fn parse_stage_format<I, T>(section_name: &str, args: I) -> Result<StageSection, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut argv = vec![
        OsString::from("xtask stage"),
        section_name.to_owned().into(),
    ];
    argv.extend(args.into_iter().map(Into::into));
    StageCli::try_parse_from(argv).map(|cli| match cli.format {
        StageFormat::Homebrew => StageSection::Homebrew,
        StageFormat::Scoop => StageSection::Scoop,
        StageFormat::Apt { options } => StageSection::Apt(options),
        StageFormat::Rpm => StageSection::Rpm,
    })
}

pub fn parse_stage_sections(tokens: &[OsString]) -> Result<Vec<StageSection>, clap::Error> {
    let sections = grouped::parse_grouped_targets(tokens, &["homebrew", "scoop", "apt", "rpm"])
        .map_err(|error| StageCli::command().error(ErrorKind::ValueValidation, error))?;

    sections
        .into_iter()
        .map(|section| parse_stage_format(&section.name, section.args))
        .collect()
}

pub async fn stage_sections(tokens: Vec<OsString>) -> Result<(), Whatever> {
    let sections = parse_stage_sections(&tokens).unwrap_or_else(|error| {
        error.exit();
    });

    for section in sections {
        match section {
            StageSection::Homebrew => homebrew::stage().await?,
            StageSection::Scoop => scoop::stage().await?,
            StageSection::Apt(options) => apt::stage(options).await?,
            StageSection::Rpm => rpm::stage().await?,
        }
    }

    Ok(())
}

pub async fn verify(options: VerifyOptions) -> Result<(), Whatever> {
    verify::run(options).await
}

pub async fn publish(target: PublishTarget) -> Result<(), Whatever> {
    match target {
        PublishTarget::S3 { options } => s3::publish(options).await,
        PublishTarget::Tap { options } => tap::publish(options).await,
    }
}

fn default_components() -> Vec<String> {
    vec!["main".to_owned()]
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use clap::error::ErrorKind;

    use super::{StageSection, parse_stage_sections};

    fn os(value: &str) -> OsString {
        OsString::from(value)
    }

    #[test]
    fn stage_sections_parse_later_apt_error_before_execution() {
        let tokens = [os("homebrew"), os("apt"), os("--bogus"), os("rpm")];

        let error = match parse_stage_sections(&tokens) {
            Ok(_) => panic!("later target-local parse error should stop grouped stage parsing"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        assert!(error.to_string().contains("Usage: xtask stage apt"));
    }

    #[test]
    fn stage_sections_parse_later_apt_help_before_execution() {
        let tokens = [os("homebrew"), os("apt"), os("--help"), os("rpm")];

        let error = match parse_stage_sections(&tokens) {
            Ok(_) => panic!("later target-local help should stop grouped stage parsing"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        assert!(error.to_string().contains("Stage APT repository"));
        assert!(error.to_string().contains("Usage: xtask stage apt"));
    }

    #[test]
    fn stage_sections_reject_no_option_target_arguments() {
        let tokens = [os("rpm"), os("--prefix"), os("download")];

        let error = match parse_stage_sections(&tokens) {
            Ok(_) => panic!("rpm does not accept target-local options"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        assert!(error.to_string().contains("Usage: xtask stage rpm"));
    }

    #[test]
    fn stage_sections_preserve_user_order() {
        let tokens = [
            os("rpm"),
            os("homebrew"),
            os("apt"),
            os("--suite"),
            os("stable"),
            os("--key-file"),
            os("key.asc"),
            os("--fingerprint"),
            os("00112233445566778899AABBCCDDEEFF00112233"),
        ];

        let sections = parse_stage_sections(&tokens).expect("stage sections should parse");

        assert!(matches!(sections[0], StageSection::Rpm));
        assert!(matches!(sections[1], StageSection::Homebrew));
        assert!(matches!(sections[2], StageSection::Apt(_)));
    }
}
