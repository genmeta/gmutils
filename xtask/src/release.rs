pub mod artifact;
pub mod homebrew;
pub mod paths;
pub mod ppa;
pub mod s3;
pub mod scoop;
pub mod tap;
pub mod verify;

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use snafu::Whatever;

#[derive(Debug, Subcommand)]
pub enum StageFormat {
    /// Stage Homebrew formulae and archives
    Homebrew,
    /// Stage Scoop manifests and archives
    Scoop,
    /// Stage Ubuntu PPA source artifacts
    Ppa {
        #[command(flatten)]
        options: PpaOptions,
    },
}

#[derive(Debug, Clone, Args)]
pub struct PpaOptions {
    /// Package components to stage
    #[arg(long = "component", default_values_t = default_components())]
    pub components: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct VerifyOptions {
    /// Staged artifact root to validate
    #[arg(long, value_enum, default_value_t = PublishRoot::Common)]
    pub root: PublishRoot,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum RemoteKind {
    /// Amazon S3 compatible remote
    S3,
}

#[derive(Debug, Subcommand)]
pub enum PublishTarget {
    /// Publish staged artifacts to S3
    S3 {
        #[command(flatten)]
        options: S3Options,
    },
}

#[derive(Debug, Clone, Args)]
pub struct S3Options {
    /// S3 bucket name
    #[arg(long)]
    pub bucket: String,
    /// Prefix inside the bucket
    #[arg(long, default_value = "")]
    pub prefix: String,
    /// AWS region name
    #[arg(long)]
    pub region: Option<String>,
    /// Custom S3 endpoint URL
    #[arg(long)]
    pub endpoint_url: Option<String>,
    /// AWS profile to use
    #[arg(long)]
    pub profile: Option<String>,
    /// AWS access key id
    #[arg(long)]
    pub access_key_id: Option<String>,
    /// AWS secret access key
    #[arg(long)]
    pub secret_access_key: Option<String>,
    /// Staged artifact root to publish
    #[arg(long, value_enum, default_value_t = PublishRoot::Common)]
    pub root: PublishRoot,
    /// Remote provider kind
    #[arg(long, value_enum, default_value_t = RemoteKind::S3)]
    pub remote: RemoteKind,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum PublishRoot {
    /// target/common
    Common,
}

impl std::fmt::Display for PublishRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Common => formatter.write_str("common"),
        }
    }
}

impl std::fmt::Display for RemoteKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::S3 => formatter.write_str("s3"),
        }
    }
}

pub async fn stage(format: StageFormat) -> Result<(), Whatever> {
    match format {
        StageFormat::Homebrew => homebrew::stage().await,
        StageFormat::Scoop => scoop::stage().await,
        StageFormat::Ppa { options } => ppa::stage(options).await,
    }
}

pub async fn verify(options: VerifyOptions) -> Result<(), Whatever> {
    verify::run(options).await
}

pub async fn publish(target: PublishTarget) -> Result<(), Whatever> {
    match target {
        PublishTarget::S3 { options } => s3::publish(options).await,
    }
}

pub async fn tap(repo: PathBuf, commit: bool, push: bool) -> Result<(), Whatever> {
    tap::update(repo, commit, push).await
}

fn default_components() -> Vec<String> {
    vec!["main".to_owned()]
}
