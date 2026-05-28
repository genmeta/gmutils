pub mod prompt;
pub mod validator;

use std::{borrow::Cow, fmt::Debug, io::IsTerminal, ops::Deref};

use clap::Parser;
use dhttp_home::{
    DhttpHome,
    identity::{
        settings::{DhttpSettingsFile, LoadDhttpSettingsError, SaveDhttpSettingsError},
        ssl::{
            ListIdentityProfilesError, LoadCertsError, LoadIdentityError,
            ResolveIdentityProfileError, SaveIdentityError,
        },
    },
};
use dhttp_identity::name::DhttpName as Name;
use futures::TryStreamExt;
use indicatif::ProgressStyle;
use rankey::EncodePem;
use snafu::{ResultExt, Snafu, Whatever, whatever};
use tokio::io;
use tracing::{Instrument, info_span};
use tracing_indicatif::{IndicatifLayer, span_ext::IndicatifSpanExt};
use tracing_subscriber::{
    EnvFilter, filter::LevelFilter, prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
};

use crate::{
    DEFAULT_CERT_SERVER_BASE_URL, REGISTERABLE_SUFFIXES,
    cert_server::{
        self, CertServer, LoginResponse, RegisterResponse, RenewResponse, ResignResponse,
    },
    cli::prompt::{
        InquireResultExt, prompt_available_email, prompt_available_name,
        prompt_confirm_set_as_default_name, prompt_login_catpcha, prompt_register_catpcha,
        prompt_select_default_identity, prompt_select_identities, prompt_suffix,
    },
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
    #[snafu(transparent)]
    ListIdentities { source: ListIdentityProfilesError },
    #[snafu(transparent)]
    LoadIdentity { source: LoadIdentityError },
    #[snafu(transparent)]
    ResolveIdentityProfile { source: ResolveIdentityProfileError },
    #[snafu(transparent)]
    LoadCert { source: LoadCertsError },

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
        source: dhttp_home::LocateDhttpHomeError,
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

#[tracing::instrument(skip(cert_server))]
async fn acquire_captcha(cert_server: &CertServer, email: &str) -> Result<(), Error> {
    tracing::Span::current().pb_set_message(&format!("Requesting captcha for {email}..."));
    cert_server.send_captcha(email).await?;
    tracing::Span::current()
        .pb_set_finish_message(&format!("Captcha successfully sent to {email}."));
    Ok(())
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
fn display_cert_info(cert_der: &[u8], indent: &str) -> Result<(), Error> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .whatever_context::<_, Error>("failed to parse certificate")?;
    println!("{}Serial:     {}", indent, cert.serial);
    println!("{}Subject:    {}", indent, cert.subject());
    println!("{}Not Before: {}", indent, cert.validity().not_before);
    println!("{}Not After:  {}", indent, cert.validity().not_after);
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        let dns_names: Vec<_> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                x509_parser::prelude::GeneralName::DNSName(n) => Some(*n),
                _ => None,
            })
            .collect();
        if !dns_names.is_empty() {
            println!("{}SANs:       {}", indent, dns_names.join(", "));
        }
    }
    if let Ok(Some(ku)) = cert.key_usage() {
        let flags: Vec<&str> = [
            ku.value.digital_signature().then_some("digital_signature"),
            ku.value.non_repudiation().then_some("non_repudiation"),
            ku.value.key_encipherment().then_some("key_encipherment"),
            ku.value.data_encipherment().then_some("data_encipherment"),
            ku.value.key_agreement().then_some("key_agreement"),
            ku.value.key_cert_sign().then_some("key_cert_sign"),
            ku.value.crl_sign().then_some("crl_sign"),
            ku.value.encipher_only().then_some("encipher_only"),
            ku.value.decipher_only().then_some("decipher_only"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !flags.is_empty() {
            println!("{}Key Usage:  {}", indent, flags.join(", "));
        }
    }
    if let Ok(Some(eku)) = cert.extended_key_usage() {
        let purposes: Vec<&str> = [
            eku.value.any.then_some("any"),
            eku.value.server_auth.then_some("server_auth"),
            eku.value.client_auth.then_some("client_auth"),
            eku.value.code_signing.then_some("code_signing"),
            eku.value.email_protection.then_some("email_protection"),
            eku.value.time_stamping.then_some("time_stamping"),
            eku.value.ocsp_signing.then_some("ocsp_signing"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !purposes.is_empty() {
            println!("{}EKU:        {}", indent, purposes.join(", "));
        }
    }
    Ok(())
}

#[tracing::instrument(skip(cert_server))]
async fn resign_identity(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    access_token: &str,
    name: &Name<'_>,
) -> Result<(), Error> {
    let (key_pem, csr_pem) = generate_private_key_and_csr(name)?;

    tracing::Span::current().pb_set_message(&format!("Re-signing certificate for {name}..."));
    let ResignResponse { cert_pem } = cert_server
        .resign_cert(access_token, name.as_full(), &csr_pem)
        .await?;

    save_identity(dhttp_home, name, key_pem.as_bytes(), &cert_pem).await?;

    Ok(())
}

#[tracing::instrument(skip(cert_server))]
async fn resign_identities(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    access_token: &str,
    names: &[Name<'_>],
) -> Result<(), Error> {
    tracing::Span::current().pb_set_style(
        &ProgressStyle::with_template("{span_child_prefix}{spinner} {msg} {pos}/{len}")
            .expect("BUG: static progress bar template is valid"),
    );
    tracing::Span::current().pb_set_length(names.len() as u64);
    tracing::Span::current().pb_set_message("Re-signing certificates for selected identities...");
    for name in names {
        resign_identity(dhttp_home, cert_server, access_token, name).await?;
        tracing::Span::current().pb_inc(1);
    }
    tracing::Span::current()
        .pb_set_finish_message("All selected identities have been successfully re-signed.");
    Ok(())
}

#[tracing::instrument(skip(cert_server))]
async fn renew_identity(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    access_token: &str,
    name: &Name<'_>,
) -> Result<(), Error> {
    let (key_pem, csr_pem) = generate_private_key_and_csr(name)?;

    tracing::Span::current().pb_set_message(&format!("Renewing certificate for {name}..."));
    let RenewResponse { cert_pem } = cert_server
        .renew_cert(access_token, name.as_full(), &csr_pem)
        .await?;

    save_identity(dhttp_home, name, key_pem.as_bytes(), &cert_pem).await?;

    Ok(())
}

#[tracing::instrument(skip(cert_server))]
async fn renew_identities(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    access_token: &str,
    names: &[Name<'_>],
) -> Result<(), Error> {
    tracing::Span::current().pb_set_style(
        &ProgressStyle::with_template("{span_child_prefix}{spinner} {msg} {pos}/{len}")
            .expect("BUG: static progress bar template is valid"),
    );
    tracing::Span::current().pb_set_length(names.len() as u64);
    tracing::Span::current().pb_set_message("Renewing certificates for selected identities...");
    for name in names {
        renew_identity(dhttp_home, cert_server, access_token, name).await?;
        tracing::Span::current().pb_inc(1);
    }
    tracing::Span::current()
        .pb_set_finish_message("All selected identities have been successfully renewed.");
    Ok(())
}

#[tracing::instrument()]
async fn load_current_settings(dhttp_home: &DhttpHome) -> Result<Option<DhttpSettingsFile>, Error> {
    let path = dhttp_home.settings_path();
    tracing::Span::current().pb_set_message(&format!(
        "Loading default configuration from {}...",
        path.display()
    ));
    let (message, result) = match dhttp_home.load_settings().await {
        Ok(default_config) => ("Default configuration loaded.", Ok(Some(default_config))),
        Err(LoadDhttpSettingsError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound =>
        {
            ("No default configuration found.", Ok(None))
        }
        Err(error) => (
            "Error loading default configuration.",
            Err(Error::from(error)),
        ),
    };
    tracing::Span::current().pb_set_finish_message(message);
    result
}

#[tracing::instrument()]
async fn save_settings(default_config: &DhttpSettingsFile) -> Result<(), Error> {
    let path = default_config.path().display();
    tracing::Span::current().pb_set_message(&format!("Saving default configuration to {path}..."));
    default_config.save().await?;
    tracing::Span::current()
        .pb_set_finish_message(&format!("Default configuration saved to {path}."));
    Ok(())
}

async fn ensure_default_identity(dhttp_home: &DhttpHome, names: &[Name<'_>]) -> Result<(), Error> {
    let default_config = load_current_settings(dhttp_home).await?;
    if default_config
        .as_ref()
        .and_then(|c| c.settings().default_identity_name())
        .is_some()
    {
        return Ok(());
    }

    let selected = if names.len() == 1 {
        let confirmed = prompt_confirm_set_as_default_name(names[0].borrow())
            .await
            .or_not_tty(|| {
                tracing::info!(
                    "no TTY, automatically setting {} as default identity",
                    names[0]
                );
                true
            })?;
        if confirmed {
            Some(names[0].to_owned())
        } else {
            None
        }
    } else {
        let owned: Vec<Name<'static>> = names.iter().map(|n| n.to_owned()).collect();
        prompt_select_default_identity(owned.clone())
            .await
            .or_not_tty(|| {
                tracing::info!(
                    "no TTY, automatically setting {} as default identity",
                    owned[0]
                );
                Some(owned[0].clone())
            })?
    };

    if let Some(name) = selected {
        let mut config = default_config.unwrap_or_else(|| dhttp_home.new_settings());
        config.settings_mut().set_default_identity_name(name);
        save_settings(&config).await?;
    }

    Ok(())
}

#[tracing::instrument()]
async fn query_exist_names_list(dhttp_home: &DhttpHome) -> Result<Vec<Name<'static>>, Error> {
    tracing::Span::current().pb_set_message("Querying existing identities...");
    let (message, result) = match dhttp_home
        .identity_profile_names()
        .try_collect::<Vec<_>>()
        .await
    {
        Ok(list) => (
            format!("Found {} existing identities.", list.len()),
            Ok(list),
        ),
        Err(ListIdentityProfilesError::ReadDir { source, .. })
            if source.kind() == io::ErrorKind::NotFound =>
        {
            ("No existing identities found.".to_string(), Ok(vec![]))
        }
        Err(error) => ("Error querying existing identities".to_string(), Err(error)),
    };
    tracing::Span::current().pb_set_finish_message(&message);
    Ok(result?)
}

/// Create a new identity
#[derive(Parser, Debug, Clone)]
pub struct Create {
    #[arg(short, long)]
    pub name: Option<String>,
    #[arg(short, long)]
    pub suffix: Option<String>,
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(long)]
    pub captcha: Option<String>,
}

impl Create {
    pub async fn run(&self, dhttp_home: &DhttpHome, cert_server: &CertServer) -> Result<(), Error> {
        let suffix: String = match self.suffix.as_ref() {
            Some(suffix) if !REGISTERABLE_SUFFIXES.contains(&suffix.as_str()) => {
                whatever!("`{suffix}` is not a registerable suffix")
            }
            Some(suffix) => suffix.into(),
            None => prompt_suffix()
                .await
                .require_interactive("--suffix")?
                .into(),
        };
        let username = match self.name.clone() {
            Some(name) => name,
            None => prompt_available_name(cert_server.clone(), suffix.clone())
                .await
                .require_interactive("--name")?,
        };
        let email: String = match self.email.clone() {
            Some(email) => email,
            None => prompt_available_email(cert_server.clone())
                .await
                .require_interactive("--email")?,
        };
        let name = Name::try_from(format!("{username}.{suffix}{}", Name::SUFFIX))
            .whatever_context::<_, Error>("invalid identity name format")?;
        let (key_pem, csr_pem) = generate_private_key_and_csr(&name)?;

        acquire_captcha(cert_server, &email).await?;

        // Non-interactive mode when --captcha is provided
        let RegisterResponse { cert_pem } = match self.captcha.clone() {
            Some(captcha) => {
                cert_server
                    .register(&username, &email, &captcha, &csr_pem)
                    .await?
            }
            None => prompt_register_catpcha(
                cert_server.clone(),
                username.clone(),
                email.clone(),
                csr_pem,
            )
            .await
            .require_interactive("--captcha")?,
        };

        save_identity(dhttp_home, &name, key_pem.as_bytes(), &cert_pem)
            .instrument(info_span!("save_identity"))
            .await?;

        ensure_default_identity(dhttp_home, &[name.borrow()]).await?;

        Ok(())
    }
}

/// Apply identity
#[derive(Parser, Debug, Clone)]
pub struct Apply {
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(short, long)]
    pub identities: Option<Vec<Name<'static>>>,
    #[arg(long)]
    pub captcha: Option<String>,
}

impl Apply {
    pub async fn run(&self, dhttp_home: &DhttpHome, cert_server: &CertServer) -> Result<(), Error> {
        let email = match self.email.clone() {
            Some(email) => email,
            None => prompt::prompt_email()
                .await
                .require_interactive("--email")?,
        };

        acquire_captcha(cert_server, &email).await?;
        let LoginResponse {
            access_token,
            domains,
        } = match self.captcha.clone() {
            Some(captcha) => cert_server.login(&email, &captcha).await?,
            None => prompt_login_catpcha(cert_server.clone(), email)
                .await
                .require_interactive("--captcha")?,
        };

        let names: Cow<'_, [Name<'static>]> = match self.identities.as_deref() {
            Some(identities) => identities.into(),
            None => prompt_select_identities(domains)
                .await
                .require_interactive("--identities")?
                .into(),
        };
        resign_identities(dhttp_home, cert_server, &access_token, &names).await?;
        ensure_default_identity(dhttp_home, &names).await?;

        Ok(())
    }
}

/// Renew identities
#[derive(Parser, Debug, Clone)]
pub struct Renew {
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(short, long)]
    pub identities: Option<Vec<Name<'static>>>,
    #[arg(long)]
    pub captcha: Option<String>,
}

impl Renew {
    pub async fn run(&self, dhttp_home: &DhttpHome, cert_server: &CertServer) -> Result<(), Error> {
        let email = match self.email.clone() {
            Some(email) => email,
            None => prompt::prompt_email()
                .await
                .require_interactive("--email")?,
        };

        acquire_captcha(cert_server, &email).await?;
        let LoginResponse {
            access_token,
            domains,
        } = match self.captcha.clone() {
            Some(captcha) => cert_server.login(&email, &captcha).await?,
            None => prompt_login_catpcha(cert_server.clone(), email)
                .await
                .require_interactive("--captcha")?,
        };

        let names: Cow<'_, [Name<'static>]> = match self.identities.as_deref() {
            Some(identities) => identities.into(),
            None => prompt_select_identities(domains)
                .await
                .require_interactive("--identities")?
                .into(),
        };
        renew_identities(dhttp_home, cert_server, &access_token, &names).await?;
        ensure_default_identity(dhttp_home, &names).await?;

        Ok(())
    }
}

/// Set default identity
#[derive(Parser, Debug, Clone)]
pub struct Default {
    pub name: Option<Name<'static>>,
}

impl Default {
    pub async fn run(
        &self,
        dhttp_home: &DhttpHome,
        _cert_server: &CertServer,
    ) -> Result<(), Error> {
        match self.name.as_ref() {
            None => {
                // Show info for current default identity
                let current_config = load_current_settings(dhttp_home).await?;
                let name = match current_config
                    .and_then(|c| c.settings().default_identity_name().cloned())
                {
                    Some(n) => n,
                    None => whatever!(
                        "no default identity configured, use `genmeta identity default <name>` to set one"
                    ),
                };
                let identity = dhttp_home.resolve_identity_profile(name.borrow()).await?;
                println!("{}", identity.name());
                let certs = identity.load_certs().await?;
                let der = certs[0].as_ref();
                display_cert_info(der, "  ")?;
                Ok(())
            }
            Some(name) => {
                // Configure name as default
                dhttp_home.resolve_identity_profile(name.borrow()).await?;
                let current_config = load_current_settings(dhttp_home).await?;
                let mut current_config = current_config
                    .unwrap_or_else(|| DhttpSettingsFile::new(dhttp_home.settings_path()));
                current_config
                    .settings_mut()
                    .set_default_identity_name(name.to_owned());
                save_settings(&current_config).await
            }
        }
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
        let names = query_exist_names_list(dhttp_home).await?;
        let default_config = load_current_settings(dhttp_home).await?;
        let default_name = default_config
            .as_ref()
            .and_then(|c| c.settings().default_identity_name().cloned());
        if names.is_empty() {
            println!("No local identities found.");
        } else {
            for name in &names {
                let marker = if default_name
                    .as_ref()
                    .map(|d| d.borrow() == name.borrow())
                    .unwrap_or(false)
                {
                    "* "
                } else {
                    "  "
                };
                println!("{marker}{name}");
                if self.verbose {
                    let identity = dhttp_home.resolve_identity_profile(name.borrow()).await?;
                    let certs = identity.load_certs().await?;
                    let der = certs[0].as_ref();
                    display_cert_info(der, "    ")?;
                }
            }
        }
        Ok(())
    }
}

/// Show details for an identity
#[derive(Parser, Debug, Clone)]
pub struct Info {
    /// Identity name (defaults to current default)
    pub name: Option<Name<'static>>,
}

impl Info {
    pub async fn run(
        &self,
        dhttp_home: &DhttpHome,
        _cert_server: &CertServer,
    ) -> Result<(), Error> {
        let name: Name<'static> = match self.name.as_ref() {
            Some(n) => n.to_owned(),
            None => {
                let cfg = load_current_settings(dhttp_home).await?;
                match cfg.and_then(|c| c.settings().default_identity_name().cloned()) {
                    Some(n) => n,
                    None => whatever!(
                        "no default identity configured, use `genmeta identity default <name>` to set one"
                    ),
                }
            }
        };
        let identity = dhttp_home.resolve_identity_profile(name.borrow()).await?;
        println!("{}", identity.name());

        let certs = identity.load_certs().await?;
        let der = certs[0].as_ref();
        display_cert_info(der, "  ")?;

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
            Options::Create(cmd) => cmd.run(dhttp_home, cert_server).await,
            Options::Apply(cmd) => cmd.run(dhttp_home, cert_server).await,
            Options::Renew(cmd) => cmd.run(dhttp_home, cert_server).await,
            Options::Default(cmd) => cmd.run(dhttp_home, cert_server).await,
            Options::Info(cmd) => cmd.run(dhttp_home, cert_server).await,
            Options::List(cmd) => cmd.run(dhttp_home, cert_server).await,
            Options::Version {} => {
                println!("{}", env!("CARGO_PKG_VERSION"));
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

pub async fn run(options: Options) -> Result<(), Error> {
    init_tracing();

    let dhttp_home = DhttpHome::load_from_environment()?;

    _ = rustls::crypto::ring::default_provider().install_default();
    let cert_server = CertServer::new(DEFAULT_CERT_SERVER_BASE_URL)?;

    options.run(&dhttp_home, &cert_server).await
}
