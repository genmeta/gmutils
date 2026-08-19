pub mod flow;
pub mod prompt;
pub mod validator;

mod certificate_log;
use std::io::IsTerminal;

use clap::Parser;
#[cfg(test)]
use dhttp::certificate::CertificateChainKey;
use dhttp::{
    home::{
        DhttpHome, HomeScope, LoadDhttpHomeError,
        identity::{
            settings::{DhttpSettingsFile, LoadDhttpSettingsError, SaveDhttpSettingsError},
            ssl::{
                ListIdentityProfilesError, LoadCertsError, LoadIdentityError, LoadKeyError,
                ResolveIdentityProfileError,
            },
        },
    },
    name::DhttpName as Name,
};
pub use flow::{install::Error as InstallError, welcome::WelcomeServiceError};
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
    WelcomeService { source: WelcomeServiceError },
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

#[cfg(test)]
fn certificate_chain_key_from_identity(
    identity: &dhttp::identity::Identity,
) -> Result<Option<CertificateChainKey>, Error> {
    match identity.dhttp_subject_key_identifier() {
        Ok(ski) => Ok(Some(ski.chain().clone())),
        Err(_) => Ok(None),
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

/// Change an identity server configuration
#[derive(Parser, Debug, Clone)]
pub struct SiteCommand {
    /// Identity whose server configuration should be changed
    #[arg(long, value_name = "IDENTITY")]
    pub id: String,
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
#[command(version, about, disable_help_flag = true, disable_version_flag = true)]
pub struct Cli {
    #[arg(
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
#[command(about, disable_help_flag = true, disable_version_flag = true)]
pub enum Options {
    Apply(Apply),
    Renew(Renew),
    Default(Default),
    #[command(about = "Enable an identity server configuration")]
    Ensite(SiteCommand),
    #[command(about = "Disable an identity server configuration")]
    Dissite(SiteCommand),
    Info(Info),
    List(List),
    Version {},
}

impl Options {
    pub fn writes_home(&self) -> bool {
        matches!(
            self,
            Self::Apply(_) | Self::Renew(_) | Self::Default(_) | Self::Ensite(_) | Self::Dissite(_)
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
            Options::Default(cmd) => {
                flow::run_default(cmd, dhttp_home, home_scope, cert_server).await
            }
            Options::Ensite(cmd) => flow::run_ensite(cmd, dhttp_home).await,
            Options::Dissite(cmd) => flow::run_dissite(cmd, dhttp_home).await,
            Options::Info(cmd) => flow::run_info(cmd, dhttp_home, cert_server).await,
            Options::List(cmd) => flow::run_list(cmd, dhttp_home, cert_server).await,
            Options::Version {} => {
                flow::transcript::print_line(env!("CARGO_PKG_VERSION"));
                Ok(())
            }
        }
    }
}

fn init_tracing() {
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
                .with_filter(LevelFilter::OFF),
        )
        .with(indicatif_layer.with_filter(IndicatifFilter::new(false)))
        .init();
}

fn cert_server_base_url() -> &'static str {
    DHTTP_CA_SERVICE
}

pub async fn run(options: Cli) -> Result<(), Error> {
    init_tracing();

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
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use clap::{CommandFactory, Parser};
    use dhttp::{
        home::{DhttpHome, HomeScope},
        identity::Identity,
        name::{DhttpName, Name},
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::{
        Apply, Cli, Default, Info, Options, cert_server_base_url,
        certificate_chain_key_from_identity,
    };
    use crate::DHTTP_CA_SERVICE;

    fn unique_test_home_path(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "genmeta-identity-cli-{test_name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn cert_server_base_url_uses_compile_time_bootstrap_url() {
        let url = cert_server_base_url();
        assert_eq!(url, DHTTP_CA_SERVICE);
    }

    #[test]
    fn removed_public_options_do_not_parse_or_appear_in_help() {
        let help = Cli::command().render_long_help().to_string();
        for removed in [
            "--auth",
            "--send-code",
            "--replace-local",
            "--allow-nonready",
            "--register-if-missing",
        ] {
            assert!(
                !help.contains(removed),
                "{removed} leaked into help:\n{help}"
            );
        }

        for argv in [
            vec!["genmeta", "apply", "alice.smith", "--auth", "email"],
            vec!["genmeta", "apply", "alice.smith", "--send-code"],
            vec!["genmeta", "apply", "alice.smith", "--replace-local"],
            vec!["genmeta", "default", "alice.smith", "--allow-nonready"],
        ] {
            assert!(Options::try_parse_from(argv).is_err());
        }
    }

    #[test]
    fn force_is_scoped_to_apply_renew_and_named_default() {
        assert!(Options::try_parse_from(["genmeta", "apply", "alice.smith", "--force"]).is_ok());
        assert!(Options::try_parse_from(["genmeta", "renew", "alice.smith", "-f"]).is_ok());
        assert!(Options::try_parse_from(["genmeta", "default", "alice.smith", "--force"]).is_ok());
        assert!(Options::try_parse_from(["genmeta", "default", "-v", "--force"]).is_err());
    }

    #[test]
    fn hidden_verify_code_still_parses_without_help_exposure() {
        let help = Apply::command().render_long_help().to_string();
        assert!(!help.contains("--verify-code"), "{help}");
        assert!(
            Options::try_parse_from([
                "genmeta",
                "apply",
                "alice.smith",
                "--email",
                "alice@example.test",
                "--verify-code",
                "000000",
            ])
            .is_ok()
        );
    }

    #[test]
    fn apply_rejects_removed_kind_option() {
        let help = Apply::command().render_long_help().to_string();
        assert!(!help.contains("--kind"), "{help}");
        for value in ["primary", "secondary"] {
            let error =
                Options::try_parse_from(["genmeta", "apply", "alice.smith", "--kind", value])
                    .unwrap_err();
            assert!(error.to_string().contains("--kind"), "{error}");
        }
    }

    #[test]
    fn site_commands_require_id() {
        assert!(Options::try_parse_from(["genmeta", "ensite", "--id", "alice.smith"]).is_ok());
        assert!(Options::try_parse_from(["genmeta", "dissite", "--id", "alice.smith"]).is_ok());
        assert!(
            Cli::try_parse_from(["genmeta", "--global", "ensite", "--id", "alice.smith"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["genmeta", "dissite", "--global", "--id", "alice.smith"]).is_ok()
        );
        assert!(Options::try_parse_from(["genmeta", "ensite"]).is_err());
        assert!(Options::try_parse_from(["genmeta", "dissite"]).is_err());
        assert!(Options::try_parse_from(["genmeta", "ensite", "alice.smith"]).is_err());
        assert!(Options::try_parse_from(["genmeta", "dissite", "alice.smith"]).is_err());

        let command = Options::command();
        assert_eq!(
            command
                .find_subcommand("ensite")
                .and_then(clap::Command::get_about)
                .map(ToString::to_string)
                .as_deref(),
            Some("Enable an identity server configuration")
        );
        assert_eq!(
            command
                .find_subcommand("dissite")
                .and_then(clap::Command::get_about)
                .map(ToString::to_string)
                .as_deref(),
            Some("Disable an identity server configuration")
        );
    }

    fn local_identity_with_dhttp_ski() -> Identity {
        Identity::new(
            Name::try_from("client.example.com.dhttp.net").unwrap(),
            vec![CertificateDer::from(
                include_bytes!("../tests/fixtures/valid.der").to_vec(),
            )],
            PrivateKeyDer::Pkcs8(b"dummy".to_vec().into()),
        )
    }

    fn dummy_cert_server() -> crate::cert_server::CertServer {
        _ = rustls::crypto::ring::default_provider().install_default();
        crate::cert_server::CertServer::new("https://license.genmeta.net").unwrap()
    }

    #[test]
    fn certificate_chain_key_from_identity_reads_dhttp_ski() {
        let identity = local_identity_with_dhttp_ski();
        let chain_key = certificate_chain_key_from_identity(&identity)
            .unwrap()
            .unwrap();

        assert_eq!(chain_key.usage().kind_flag(), "0");
        assert_eq!(chain_key.sequence().get(), 0);
    }

    #[test]
    fn apply_does_not_expose_register_if_missing() {
        let help = Apply::command().render_long_help().to_string();
        assert!(!help.contains("register-if-missing"), "{help}");

        let error = Options::try_parse_from([
            "genmeta",
            "apply",
            "phone.alice.smith",
            "--register-if-missing",
        ])
        .unwrap_err();
        assert!(error.to_string().contains("unexpected argument"));
    }

    #[test]
    fn create_subcommand_is_removed() {
        let error = Options::try_parse_from(["genmeta", "create", "alice.smith"])
            .expect_err("create must no longer parse");
        assert!(error.to_string().contains("unrecognized subcommand"));
    }

    #[test]
    fn renew_uses_optional_positional_identity_without_default_flag() {
        assert!(Options::try_parse_from(["genmeta", "renew"]).is_ok());
        assert!(Options::try_parse_from(["genmeta", "renew", "alice.smith"]).is_ok());
        assert!(Options::try_parse_from(["genmeta", "renew", "--all"]).is_ok());
        assert!(Options::try_parse_from(["genmeta", "renew", "alice.smith", "--all"]).is_err());
        assert!(Options::try_parse_from(["genmeta", "renew", "--default"]).is_err());
    }

    #[test]
    fn default_verbose_is_query_only() {
        assert!(Options::try_parse_from(["genmeta", "default", "-v"]).is_ok());
        assert!(Options::try_parse_from(["genmeta", "default", "--verbose"]).is_ok());
        assert!(Options::try_parse_from(["genmeta", "default", "alice.smith", "-v"]).is_err());
    }

    #[test]
    fn helper_style_read_and_write_subcommands_are_rejected() {
        for command in ["read", "write"] {
            let error = Options::try_parse_from(["genmeta", command]).unwrap_err();
            let rendered = error.to_string();
            assert!(rendered.contains(command), "{rendered}");
        }
    }

    #[test]
    fn renew_rejects_kind_and_sequence_flags() {
        for (flag, value) in [("--kind", "primary"), ("--sequence", "1")] {
            let error = Options::try_parse_from(["genmeta", "renew", "alice.smith", flag, value])
                .unwrap_err();
            let rendered = error.to_string();
            assert!(rendered.contains(flag), "{rendered}");
        }
    }

    #[test]
    fn apply_rejects_sequence_flag() {
        let error = Options::try_parse_from(["genmeta", "apply", "alice.smith", "--sequence", "1"])
            .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("--sequence"), "{rendered}");
    }

    #[test]
    fn apply_and_renew_reject_default_flag() {
        let apply_error = Options::try_parse_from(["genmeta", "apply", "--default"]).unwrap_err();
        assert!(apply_error.to_string().contains("--default"));

        assert!(Options::try_parse_from(["genmeta", "renew", "--default"]).is_err());
    }

    #[tokio::test]
    async fn save_settings_creates_missing_home_directory() {
        let home_path = unique_test_home_path("save-settings");
        let dhttp_home = DhttpHome::new(home_path.clone());
        let mut settings = dhttp_home.new_settings();
        settings
            .settings_mut()
            .set_default_identity_name(DhttpName::try_from("alice.smith").unwrap());

        super::save_settings(&settings).await.unwrap();

        assert!(home_path.join("settings.toml").exists());
    }

    #[tokio::test]
    async fn info_reports_unsaved_identity_with_business_message() {
        let home_path = unique_test_home_path("info-unsaved");
        let dhttp_home = DhttpHome::new(home_path);
        let command = Info {
            name: Some("alice.smith".to_string()),
        };

        let error = command
            .run(&dhttp_home, &dummy_cert_server())
            .await
            .unwrap_err();
        let rendered = error.to_string();

        assert!(
            rendered.contains("alice.smith is not saved here"),
            "{rendered}"
        );
        assert!(
            rendered.contains("apply alice.smith here first"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn default_reports_unsaved_identity_non_interactively() {
        for force in [false, true] {
            let home_path = unique_test_home_path("default-unsaved");
            let dhttp_home = DhttpHome::new(home_path);
            let command = Default {
                name: Some("alice.smith".to_string()),
                verbose: false,
                force,
            };

            let error = command
                .run(&dhttp_home, HomeScope::User, &dummy_cert_server())
                .await
                .unwrap_err();

            assert_eq!(
                error.to_string(),
                "Failed to set default identity: alice.smith not found!"
            );
        }
    }

    #[tokio::test]
    async fn default_named_saved_identity_sets_default_non_interactively() {
        let home_path = unique_test_home_path("default-saved-noninteractive");
        let dhttp_home = DhttpHome::new(home_path.clone());
        let name = DhttpName::try_from("alice.smith").unwrap();
        let profile = dhttp_home.identity_profile(name.borrow());
        tokio::fs::create_dir_all(profile.path()).await.unwrap();

        let command = Default {
            name: Some("alice.smith".to_string()),
            verbose: false,
            force: true,
        };

        command
            .run(&dhttp_home, HomeScope::User, &dummy_cert_server())
            .await
            .unwrap();

        let settings = dhttp_home.load_settings().await.unwrap();
        assert_eq!(
            settings
                .settings()
                .default_identity_name()
                .map(|name| name.as_partial()),
            Some("alice.smith")
        );

        tokio::fs::remove_dir_all(home_path).await.unwrap();
    }

    #[test]
    fn cli_accepts_global_before_and_after_subcommand() {
        let before = Cli::try_parse_from(["genmeta", "--global", "list"]).unwrap();
        let after = Cli::try_parse_from(["genmeta", "list", "--global"]).unwrap();

        assert_eq!(before.home_scope(), dhttp::home::HomeScope::Global);
        assert_eq!(after.home_scope(), dhttp::home::HomeScope::Global);
    }

    #[test]
    fn cli_accepts_scheduled_all_renewal_for_both_scopes() {
        let user = Cli::try_parse_from(["genmeta-identity", "renew", "--all"]);
        let global = Cli::try_parse_from(["genmeta-identity", "--global", "renew", "--all"]);

        assert!(user.is_ok(), "{user:?}");
        assert!(global.is_ok(), "{global:?}");
    }

    #[test]
    fn write_commands_are_marked_for_global_warning() {
        for argv in [
            ["genmeta", "apply", "alice.smith"].as_slice(),
            ["genmeta", "renew", "alice.smith"].as_slice(),
            ["genmeta", "default", "alice.smith"].as_slice(),
            ["genmeta", "ensite", "--id", "alice.smith"].as_slice(),
            ["genmeta", "dissite", "--id", "alice.smith"].as_slice(),
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert!(cli.options.writes_home());
        }

        let info = Cli::try_parse_from(["genmeta", "info", "alice.smith"]).unwrap();
        assert!(!info.options.writes_home());
    }
}
