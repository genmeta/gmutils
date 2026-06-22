pub mod flow;
pub mod prompt;
pub mod validator;

use std::{io::IsTerminal, ops::Deref};

use clap::Parser;
use dhttp::{
    certificate::CertificateChainKey,
    home::{
        DhttpHome,
        identity::{
            settings::{DhttpSettingsFile, LoadDhttpSettingsError, SaveDhttpSettingsError},
            ssl::{
                ListIdentityProfilesError, LoadCertsError, LoadIdentityError, LoadKeyError,
                ResolveIdentityProfileError, SaveIdentityError,
            },
        },
    },
    name::DhttpName as Name,
};
use indicatif::ProgressStyle;
use rankey::EncodePem;
use snafu::{ResultExt, Snafu, Whatever, whatever};
use tokio::io;
use tracing_indicatif::{IndicatifLayer, span_ext::IndicatifSpanExt};
use tracing_subscriber::{
    EnvFilter, filter::LevelFilter, prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
};

use crate::{
    CERT_SERVER_BASE_URL,
    cert_server::{self, CertServer},
    cli::prompt::InquireResultExt,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    Prompt { source: prompt::Error },
    #[snafu(transparent)]
    CertServer { source: cert_server::Error },
    #[snafu(transparent)]
    SaveIdentity { source: SaveIdentityError },
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

    #[snafu(transparent)]
    LocateDhttpHome {
        source: dhttp::home::LocateDhttpHomeError,
    },

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

fn certificate_chain_key_from_identity(
    identity: &dhttp::identity::Identity,
) -> Result<Option<CertificateChainKey>, Error> {
    match identity.dhttp_subject_key_identifier() {
        Ok(ski) => Ok(Some(ski.chain().clone())),
        Err(_) => Ok(None),
    }
}

fn generate_private_key_and_csr(
    name: &Name<'_>,
) -> Result<(impl Deref<Target = String> + use<>, String), Error> {
    tracing::Span::current().pb_set_message(&format!("Generating private key for {name}..."));
    let key_pem = rankey::generate_secp384r1_key()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        .context(GenerateKeySnafu)?;
    tracing::Span::current().pb_set_message(&format!(
        "Generating Certificate Signing Request (CSR) for {name}..."
    ));
    let csr = rankey::generate_csr(&key_pem, "CN", name.as_full(), &[name.as_full()])
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        .context(GenerateCsrSnafu)?;
    let csr_pem = csr
        .to_pem(rankey::LineEnding::LF)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        .context(EncodeCsrSnafu)?;
    tracing::Span::current().pb_set_message(&format!(
        "Successfully generated private key and CSR for {name}."
    ));
    Ok((key_pem, csr_pem))
}

async fn save_identity(
    dhttp_home: &DhttpHome,
    name: &Name<'_>,
    key_pem: &[u8],
    cert_pem: &[u8],
) -> Result<(), Error> {
    let identity_dir = dhttp_home.join_identity_name(name.borrow());
    tracing::Span::current().pb_set_message(&format!(
        "Saving identity for {name} to {}...",
        identity_dir.display()
    ));
    dhttp_home
        .identity_profile(name.borrow())
        .save_identity(cert_pem, key_pem)
        .await?;
    tracing::Span::current().pb_set_finish_message(&format!(
        "Identity for {name} successfully saved to {}",
        identity_dir.display()
    ));
    Ok(())
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

#[tracing::instrument()]
async fn save_settings(default_config: &DhttpSettingsFile) -> Result<(), Error> {
    if let Some(parent) = default_config.path().parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context(CreateDhttpHomeDirSnafu {
                path: parent.to_path_buf(),
            })?;
    }

    let path = default_config.path().display();
    tracing::Span::current().pb_set_message(&format!("Saving default configuration to {path}..."));
    default_config.save().await?;
    tracing::Span::current()
        .pb_set_finish_message(&format!("Default configuration saved to {path}."));
    Ok(())
}

async fn resolve_default_target_name(dhttp_home: &DhttpHome) -> Result<Name<'static>, Error> {
    match load_current_settings(dhttp_home)
        .await?
        .and_then(|config| config.settings().default_identity_name().cloned())
    {
        Some(name) => Ok(name),
        None => whatever!(
            "No default identity configured. Use `genmeta identity default <name>` to set one."
        ),
    }
}

async fn ensure_replace_local_allowed(
    dhttp_home: &DhttpHome,
    name: Name<'_>,
    replace_local: bool,
) -> Result<(), Error> {
    if !dhttp_home
        .identity_profile_exists_exactly(name.clone())
        .await
    {
        return Ok(());
    }
    if replace_local {
        return Ok(());
    }

    let message = format!(
        "Replace the local identity saved at {}?",
        dhttp_home.join_identity_name(name.clone()).display()
    );
    let confirmed =
        prompt::sync(move || inquire::Confirm::new(&message).with_default(false).prompt())
            .await
            .require_interactive("--replace-local")?;
    if confirmed {
        Ok(())
    } else {
        whatever!("local identity was not replaced")
    }
}

async fn acquire_verify_code(
    cert_server: &CertServer,
    email: &str,
    provided: Option<String>,
) -> Result<String, Error> {
    match flow::email::EmailVerificationAction::from_verify_code(provided) {
        flow::email::EmailVerificationAction::ReuseProvidedCode(code) => Ok(code),
        flow::email::EmailVerificationAction::SendAndPrompt => {
            flow::progress::run_with_spinner(
                "Sending verification code...",
                cert_server.send_email_verification(email),
            )
            .await?;
            prompt::prompt_verify_code()
                .await
                .require_interactive("--verify-code")
                .map_err(Error::from)
        }
    }
}

fn parse_identity_name(identity: &str) -> Result<Name<'static>, Error> {
    Ok(flow::target::IdentityTarget::parse(identity)?.into_dhttp_name())
}

async fn login_with_email(
    cert_server: &CertServer,
    domain: Option<&Name<'_>>,
    email: Option<String>,
    verify_code: Option<String>,
) -> Result<String, Error> {
    let email = match email {
        Some(email) => email,
        None => prompt::prompt_email()
            .await
            .require_interactive("--email")?,
    };
    let verify_code = acquire_verify_code(cert_server, &email, verify_code).await?;
    if let Some(domain) = domain {
        Ok(flow::progress::run_with_spinner(
            "Verifying with email...",
            cert_server.domain_login(domain.as_full(), &email, &verify_code),
        )
        .await?
        .access_token)
    } else {
        Ok(flow::progress::run_with_spinner(
            "Verifying with email...",
            cert_server.login(&email, &verify_code),
        )
        .await?
        .access_token)
    }
}

/// Create a new identity
#[derive(Parser, Debug, Clone)]
pub struct Create {
    #[arg(value_name = "IDENTITY")]
    pub name: Option<String>,
    #[arg(long)]
    pub kind: Option<String>,
    #[arg(long)]
    pub replace_local: bool,
    #[arg(long)]
    pub device_name: Option<String>,
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(long, conflicts_with = "verify_code")]
    pub send_code: bool,
    #[arg(long, value_name = "VERIFY_CODE", hide = true)]
    pub verify_code: Option<String>,
    #[arg(long, value_enum)]
    pub auth: Option<crate::auth::AuthMethod>,
}

/// Apply identity
#[derive(Parser, Debug, Clone)]
pub struct Apply {
    #[arg(value_name = "IDENTITY")]
    pub name: Option<String>,
    #[arg(long)]
    pub kind: Option<String>,
    #[arg(long)]
    pub replace_local: bool,
    #[arg(long)]
    pub device_name: Option<String>,
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(long, conflicts_with = "verify_code")]
    pub send_code: bool,
    #[arg(long, value_name = "VERIFY_CODE", hide = true)]
    pub verify_code: Option<String>,
    #[arg(long, value_enum)]
    pub auth: Option<crate::auth::AuthMethod>,
}

/// Renew identities
#[derive(Parser, Debug, Clone)]
pub struct Renew {
    #[arg(value_name = "IDENTITY")]
    pub name: Option<String>,
    #[arg(long = "default", conflicts_with = "name")]
    pub use_default: bool,
    #[arg(long)]
    pub device_name: Option<String>,
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(long, conflicts_with = "verify_code")]
    pub send_code: bool,
    #[arg(long, value_name = "VERIFY_CODE", hide = true)]
    pub verify_code: Option<String>,
    #[arg(long, value_enum)]
    pub auth: Option<crate::auth::AuthMethod>,
}

/// Set default identity
#[derive(Parser, Debug, Clone)]
pub struct Default {
    #[arg(value_name = "IDENTITY")]
    pub name: Option<String>,
    #[arg(long)]
    pub allow_nonready: bool,
}

impl Default {
    pub async fn run(&self, dhttp_home: &DhttpHome, cert_server: &CertServer) -> Result<(), Error> {
        flow::default_identity::run(self, dhttp_home, cert_server).await
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
            flow::transcript::print_line("No local identities found");
        } else {
            flow::transcript::print_block(&flow::output::render_inventory(
                &inventory,
                std::io::stdout().is_terminal(),
            ));
            if self.verbose {
                tracing::debug!("verbose identity list details are not implemented yet");
            }
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
                None => whatever!(
                    "No default identity configured. Use `genmeta identity default <name>` to set one."
                ),
            },
        };
        let Some(summary) = flow::local::try_load_summary(
            dhttp_home,
            name.borrow(),
            default_name.as_ref().map(|default| default.borrow()),
        )
        .await?
        else {
            whatever!(
                "{} is not saved on this device.\n\nTo inspect it locally, apply {} to this device first.",
                name.as_partial(),
                name.as_partial(),
            );
        };
        flow::transcript::print_block(&flow::output::format_info(
            &summary,
            std::io::stdout().is_terminal(),
        ));

        Ok(())
    }
}
#[derive(Parser, Debug, Clone)]
#[command(about, disable_help_flag = true, disable_version_flag = true)]
pub enum Options {
    Create(Create),
    Apply(Apply),
    Renew(Renew),
    Default(Default),
    Info(Info),
    List(List),
    Version {},
}

impl Options {
    pub async fn run(&self, dhttp_home: &DhttpHome, cert_server: &CertServer) -> Result<(), Error> {
        match self {
            Options::Create(cmd) => flow::run_create(cmd, dhttp_home, cert_server).await,
            Options::Apply(cmd) => flow::run_apply(cmd, dhttp_home, cert_server).await,
            Options::Renew(cmd) => flow::run_renew(cmd, dhttp_home, cert_server).await,
            Options::Default(cmd) => flow::run_default(cmd, dhttp_home, cert_server).await,
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
    let indicatif_layer = IndicatifLayer::new().with_progress_style(
        ProgressStyle::with_template("{span_child_prefix}{spinner} {msg}")
            .expect("BUG: static progress bar template is valid"),
    );
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(indicatif_layer.get_stderr_writer()),
        )
        .with(indicatif_layer)
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive(
                    "netlink_packet_route=error"
                        .parse()
                        .expect("BUG: static tracing directive is valid"),
                ),
        )
        .init();
}

fn cert_server_base_url() -> &'static str {
    CERT_SERVER_BASE_URL
}

pub async fn run(options: Options) -> Result<(), Error> {
    init_tracing();

    let dhttp_home = DhttpHome::load_from_environment()?;

    _ = rustls::crypto::ring::default_provider().install_default();
    let cert_server = CertServer::new(cert_server_base_url())?;

    options.run(&dhttp_home, &cert_server).await
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use clap::{CommandFactory, Parser};
    use dhttp::{home::DhttpHome, identity::Identity, name::DhttpName, name::Name};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::{
        Create, Default, Info, Options, cert_server_base_url, certificate_chain_key_from_identity,
    };
    use crate::CERT_SERVER_BASE_URL;

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
        assert_eq!(url, CERT_SERVER_BASE_URL);
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

        assert_eq!(
            chain_key.kind(),
            dhttp::certificate::CertificateChainKind::Primary
        );
        assert_eq!(chain_key.sequence().get(), 0);
        assert_eq!(chain_key.to_string(), "primary:0");
    }

    #[test]
    fn create_rejects_auth_auto() {
        let error = Options::try_parse_from([
            "genmeta",
            "create",
            "alice.smith",
            "--kind",
            "primary",
            "--auth",
            "auto",
        ])
        .unwrap_err();

        let rendered = error.to_string();
        assert!(rendered.contains("--auth"), "{rendered}");
        assert!(rendered.contains("auto"), "{rendered}");
    }

    #[test]
    fn verify_code_is_hidden_from_help_but_still_parses() {
        let mut command = Create::command();
        let help = command.render_long_help().to_string();
        assert!(!help.contains("--verify-code"), "{help}");

        assert!(
            Options::try_parse_from([
                "genmeta",
                "create",
                "alice.smith",
                "--kind",
                "primary",
                "--auth",
                "email",
                "--email",
                "user@example.com",
                "--verify-code",
                "000000",
            ])
            .is_ok()
        );
    }

    #[test]
    fn default_accepts_allow_nonready() {
        assert!(
            Options::try_parse_from(["genmeta", "default", "alice.smith", "--allow-nonready",])
                .is_ok()
        );
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
    fn create_and_apply_reject_sequence_flag() {
        for command in ["create", "apply"] {
            let error = Options::try_parse_from([
                "genmeta",
                command,
                "alice.smith",
                "--kind",
                "primary",
                "--sequence",
                "1",
            ])
            .unwrap_err();
            let rendered = error.to_string();
            assert!(rendered.contains("--sequence"), "{rendered}");
        }
    }

    #[test]
    fn create_and_apply_accept_replace_local_flag() {
        for command in ["create", "apply"] {
            assert!(
                Options::try_parse_from([
                    "genmeta",
                    command,
                    "alice.smith",
                    "--kind",
                    "primary",
                    "--replace-local",
                ])
                .is_ok()
            );
        }
    }

    #[test]
    fn apply_rejects_default_flag_while_renew_keeps_it() {
        let apply_error =
            Options::try_parse_from(["genmeta", "apply", "--default", "--kind", "primary"])
                .unwrap_err();
        assert!(apply_error.to_string().contains("--default"));

        assert!(Options::try_parse_from(["genmeta", "renew", "--default"]).is_ok());
    }

    #[test]
    fn send_code_is_available_and_mutually_exclusive_with_verify_code() {
        assert!(
            Options::try_parse_from([
                "genmeta",
                "create",
                "alice.smith",
                "--kind",
                "primary",
                "--auth",
                "email",
                "--email",
                "user@example.com",
                "--send-code",
            ])
            .is_ok()
        );

        let error = Options::try_parse_from([
            "genmeta",
            "create",
            "alice.smith",
            "--kind",
            "primary",
            "--auth",
            "email",
            "--email",
            "user@example.com",
            "--send-code",
            "--verify-code",
            "000000",
        ])
        .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("--send-code"), "{rendered}");
        assert!(rendered.contains("--verify-code"), "{rendered}");
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

        let error = command.run(&dhttp_home, &dummy_cert_server()).await.unwrap_err();
        let rendered = error.to_string();

        assert!(
            rendered.contains("alice.smith is not saved on this device"),
            "{rendered}"
        );
        assert!(
            rendered.contains("apply alice.smith to this device first"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn default_reports_unsaved_identity_non_interactively() {
        let home_path = unique_test_home_path("default-unsaved");
        let dhttp_home = DhttpHome::new(home_path);
        let command = Default {
            name: Some("alice.smith".to_string()),
            allow_nonready: false,
        };

        let error = command
            .run(&dhttp_home, &dummy_cert_server())
            .await
            .unwrap_err();
        let rendered = error.to_string();

        assert!(
            rendered.contains("alice.smith is not saved on this device"),
            "{rendered}"
        );
    }
}
