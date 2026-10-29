pub use flow::site::run_listen;

pub mod flow;
pub mod prompt;
pub mod validator;

mod certificate_log;
mod developer;
use std::io::IsTerminal;

use clap::Parser;
pub use developer::Developer;
use dhttp_home::{
    DhttpHome, HomeScope, LoadDhttpHomeError,
    identity::{
        settings::{DhttpSettingsFile, LoadDhttpSettingsError, SaveDhttpSettingsError},
        ssl::{
            ListIdentityProfilesError, LoadCertsError, LoadIdentityError, LoadKeyError,
            ResolveIdentityProfileError,
        },
    },
};
use dhttp_identity::name::DhttpName as Name;
pub use flow::install::Error as InstallError;
use indicatif::ProgressStyle;
use snafu::{ResultExt, Snafu, Whatever, whatever};
use tokio::io;
use tracing_indicatif::{
    IndicatifLayer,
    filter::{IndicatifFilter, hide_indicatif_span_fields},
};
use tracing_subscriber::{
    filter::LevelFilter, fmt::format::DefaultFields, prelude::*, util::SubscriberInitExt,
};

use crate::{
    DHTTP_CA_SERVICE,
    cert_server::{self, CertServer},
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    Prompt { source: prompt::Error },
    #[snafu(transparent)]
    CertServer { source: cert_server::Error },
    #[snafu(transparent)]
    LoadDefaultConfig { source: LoadDhttpSettingsError },
    #[snafu(transparent)]
    SaveDefaultConfig { source: SaveDhttpSettingsError },
    #[snafu(display("failed to create dhttp home directory at {}", path.display()))]
    CreateDhttpHomeDir {
        path: std::path::PathBuf,
        source: io::Error,
    },
    #[snafu(transparent)]
    ListIdentities { source: ListIdentityProfilesError },
    #[snafu(transparent)]
    ResolveIdentityProfile { source: ResolveIdentityProfileError },
    #[snafu(transparent)]
    LoadCert { source: LoadCertsError },
    #[snafu(transparent)]
    LoadKey { source: LoadKeyError },
    #[snafu(transparent)]
    LoadIdentity { source: LoadIdentityError },
    #[snafu(transparent)]
    ParseIdentityTarget {
        source: flow::target::ParseIdentityTargetError,
    },
    #[snafu(transparent)]
    ParseIdentityKind {
        source: flow::kind::ParseIdentityKindError,
    },
    #[snafu(transparent)]
    LocalIdentity {
        source: crate::local_identity::Error,
    },
    #[snafu(transparent)]
    Install { source: InstallError },
    #[snafu(transparent)]
    Site { source: flow::site::Error },
    #[snafu(display("identity was installed, but server configuration failed: {source}"))]
    InstalledServerConfiguration { source: flow::site::Error },
    #[snafu(display("identity was installed, but server activation was not confirmed: {source}"))]
    ServerActivationPrompt { source: prompt::Error },

    #[snafu(display("failed to generate private key"))]
    GenerateKey {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to generate CSR"))]
    GenerateCsr {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to encode CSR to PEM"))]
    EncodeCsr {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to load dhttp home"))]
    LoadDhttpHome { source: LoadDhttpHomeError },

    #[snafu(transparent)]
    Whatever { source: Whatever },
}

impl snafu::FromString for Error {
    type Source = <Whatever as snafu::FromString>::Source;

    fn without_source(message: String) -> Self {
        Whatever::without_source(message).into()
    }

    fn with_source(source: Self::Source, message: String) -> Self {
        Whatever::with_source(source, message).into()
    }
}

#[tracing::instrument()]
async fn load_current_settings(dhttp_home: &DhttpHome) -> Result<Option<DhttpSettingsFile>, Error> {
    match dhttp_home.load_settings().await {
        Ok(default_config) => Ok(Some(default_config)),
        Err(LoadDhttpSettingsError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(Error::from(error)),
    }
}

#[tracing::instrument]
async fn save_settings(default_config: &DhttpSettingsFile) -> Result<(), Error> {
    if let Some(parent) = default_config.path().parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context(CreateDhttpHomeDirSnafu {
                path: parent.to_path_buf(),
            })?;
    }

    flow::progress::run(flow::progress::SAVE_DEFAULT, default_config.save()).await?;
    Ok(())
}

async fn resolve_default_target_name(dhttp_home: &DhttpHome) -> Result<Name<'static>, Error> {
    match load_current_settings(dhttp_home)
        .await?
        .and_then(|config| config.settings().default_identity_name().cloned())
    {
        Some(name) => Ok(name),
        None => {
            whatever!(
                "No default identity configured. Use `genmeta identity default <name>` to set one."
            );
        }
    }
}

fn parse_identity_name(identity: &str) -> Result<Name<'static>, Error> {
    Ok(flow::target::IdentityTarget::parse(identity)?.into_dhttp_name())
}

/// Apply identity
#[derive(Parser, Debug, Clone)]
pub struct Apply {
    #[arg(value_name = "IDENTITY")]
    pub name: Option<String>,
    #[arg(short, long)]
    pub force: bool,
    #[arg(long)]
    pub device_name: Option<String>,
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(long, value_name = "VERIFY_CODE", hide = true)]
    pub verify_code: Option<String>,
}

/// Renew identities
#[derive(Parser, Debug, Clone)]
pub struct Renew {
    #[arg(value_name = "IDENTITY", conflicts_with = "all")]
    pub name: Option<String>,
    /// Renew all local identities in the selected home
    #[arg(long)]
    pub all: bool,
    #[arg(short, long)]
    pub force: bool,
    #[arg(long)]
    pub device_name: Option<String>,
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(long, value_name = "VERIFY_CODE", hide = true)]
    pub verify_code: Option<String>,
}

/// Set default identity
#[derive(Parser, Debug, Clone)]
pub struct Default {
    #[arg(value_name = "IDENTITY", conflicts_with = "verbose")]
    pub name: Option<String>,
    #[arg(short, long)]
    pub verbose: bool,
    #[arg(short, long, requires = "name", conflicts_with = "verbose")]
    pub force: bool,
}

impl Default {
    pub async fn run(
        &self,
        dhttp_home: &DhttpHome,
        home_scope: HomeScope,
        cert_server: &CertServer,
    ) -> Result<(), Error> {
        flow::default_identity::run(self, dhttp_home, home_scope, cert_server).await
    }
}

/// List all local identities
#[derive(Parser, Debug, Clone)]
pub struct List {
    /// Show certificate details for each identity
    #[arg(short, long)]
    pub verbose: bool,
}

impl List {
    pub async fn run(
        &self,
        dhttp_home: &DhttpHome,
        _cert_server: &CertServer,
    ) -> Result<(), Error> {
        let default_config = load_current_settings(dhttp_home).await?;
        let default_name = default_config
            .as_ref()
            .and_then(|c| c.settings().default_identity_name().cloned());
        let inventory = flow::local::load_inventory(
            dhttp_home,
            default_name.as_ref().map(|name| name.borrow()),
        )
        .await?;
        if inventory.groups.is_empty() {
            flow::transcript::print_line("No identities found here");
        } else {
            let ansi = std::io::stdout().is_terminal();
            let rendered = if self.verbose {
                flow::output::render_verbose_inventory(
                    &inventory,
                    flow::local::now_unix_timestamp(),
                    ansi,
                )
            } else {
                flow::output::render_inventory(&inventory, ansi)
            };
            flow::transcript::print_block(&rendered);
        }
        Ok(())
    }
}

/// Show details for an identity
#[derive(Parser, Debug, Clone)]
pub struct Info {
    /// Identity name (defaults to current default)
    #[arg(value_name = "IDENTITY")]
    pub name: Option<String>,
}

impl Info {
    pub async fn run(
        &self,
        dhttp_home: &DhttpHome,
        _cert_server: &CertServer,
    ) -> Result<(), Error> {
        let default_name = load_current_settings(dhttp_home)
            .await?
            .and_then(|config| config.settings().default_identity_name().cloned());
        let name: Name<'static> = match self.name.as_ref() {
            Some(n) => parse_identity_name(n)?,
            None => match default_name.clone() {
                Some(n) => n,
                None => {
                    whatever!(
                        "No default identity configured. Use `genmeta identity default <name>` to set one."
                    );
                }
            },
        };
        let Some(summary) = flow::local::try_load_summary_exact(
            dhttp_home,
            name.borrow(),
            default_name.as_ref().map(|default| default.borrow()),
        )
        .await?
        else {
            whatever!(
                "{} is not saved here.\n\nTo inspect it here, apply {} here first.",
                name.as_partial(),
                name.as_partial(),
            );
        };
        flow::transcript::print_block(&flow::output::format_info(
            &summary,
            flow::local::now_unix_timestamp(),
            std::io::stdout().is_terminal(),
        ));

        Ok(())
    }
}

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Cli {
    /// Enable debug logs
    #[arg(long, global = true)]
    pub verb: bool,

    #[arg(
        short = 'g',
        long,
        global = true,
        help = "use the global dhttp home instead of the default user home"
    )]
    pub global: bool,

    #[command(subcommand)]
    pub options: Options,
}

impl Cli {
    pub fn home_scope(&self) -> HomeScope {
        if self.global {
            HomeScope::Global
        } else {
            HomeScope::User
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(about)]
pub enum Options {
    #[command(visible_alias = "create")]
    Apply(Apply),
    Renew(Renew),
    /// Manage independent annual code-signing subscriptions and credentials
    Developer(Developer),
    Default(Default),
    Info(Info),
    List(List),
    Version {},
}

impl Options {
    pub fn writes_home(&self) -> bool {
        matches!(
            self,
            Self::Apply(_) | Self::Renew(_) | Self::Default(_) | Self::Developer(_)
        )
    }

    pub async fn run(
        &self,
        dhttp_home: &DhttpHome,
        home_scope: HomeScope,
        cert_server: &CertServer,
    ) -> Result<(), Error> {
        match self {
            Options::Apply(cmd) => flow::run_apply(cmd, dhttp_home, home_scope, cert_server).await,
            Options::Renew(cmd) => flow::run_renew(cmd, dhttp_home, home_scope, cert_server).await,
            Options::Developer(cmd) => cmd.run(dhttp_home, cert_server).await,
            Options::Default(cmd) => {
                flow::run_default(cmd, dhttp_home, home_scope, cert_server).await
            }
            Options::Info(cmd) => flow::run_info(cmd, dhttp_home, cert_server).await,
            Options::List(cmd) => flow::run_list(cmd, dhttp_home, cert_server).await,
            Options::Version {} => {
                flow::transcript::print_line(env!("CARGO_PKG_VERSION"));
                Ok(())
            }
        }
    }
}

fn init_tracing(verb: bool) {
    let indicatif_layer = IndicatifLayer::new()
        .with_span_field_formatter(hide_indicatif_span_fields(DefaultFields::new()))
        .with_progress_style(
            ProgressStyle::with_template("{span_child_prefix}{spinner} {msg}")
                .expect("BUG: static progress bar template is valid"),
        );
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(indicatif_layer.get_stderr_writer())
                .with_filter(if verb {
                    LevelFilter::DEBUG
                } else {
                    LevelFilter::OFF
                }),
        )
        .with(indicatif_layer.with_filter(IndicatifFilter::new(false)))
        .init();
}

fn cert_server_base_url() -> &'static str {
    DHTTP_CA_SERVICE
}

pub async fn run(options: Cli) -> Result<(), Error> {
    init_tracing(options.verb);

    let home_scope = options.home_scope();
    let dhttp_home = DhttpHome::load(home_scope).context(LoadDhttpHomeSnafu)?;

    if options.global && options.options.writes_home() {
        tracing::warn!(
            path = %dhttp_home.as_path().display(),
            "using the global dhttp home; this operation may require elevated privileges"
        );
    }

    _ = rustls::crypto::ring::default_provider().install_default();
    let cert_server = CertServer::new(cert_server_base_url())?;

    options
        .options
        .run(&dhttp_home, home_scope, &cert_server)
        .await
}

#[cfg(test)]
#[path = "../tests/unit/cli.rs"]
mod tests;
