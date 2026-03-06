pub mod prompt;
pub mod validator;

use std::{borrow::Cow, fmt::Debug, ops::Deref};

use clap::Parser;
use genmeta_home::{
    GenmetaHome,
    identity::{
        Identities, Name,
        default::{DefaultConfigFile, LoadDefaultConfigError, SaveDefaultConfigError},
        fs::{ListIdentitiesError, LoadIdentityError, SaveIdentityError},
    },
};
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
    DEFAULT_CERT_SERVER_BASE_URL, REGISTERABLE_DOMAINS,
    cert_server::{self, CertServer, LoginResponse, RegisterResponse, ResignResponse},
    cli::prompt::{
        prompt_available_email, prompt_available_name, prompt_confim_update_default_name,
        prompt_confirm_select_default_name_not_exist, prompt_confirm_set_as_default_name,
        prompt_domain, prompt_login_catpcha, prompt_register_catpcha, prompt_select_default_name,
        prompt_select_resign_domains,
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
    LoadDefaultConfig { source: LoadDefaultConfigError },
    #[snafu(transparent)]
    SaveDefaultConfig { source: SaveDefaultConfigError },
    #[snafu(transparent)]
    ListIdentities { source: ListIdentitiesError },
    #[snafu(transparent)]
    LoadIdentity { source: LoadIdentityError },

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
    LocateGenmetaHome {
        source: genmeta_home::LocateGenmetaHomeError,
    },

    #[snafu(transparent)]
    Whatever { source: Whatever },
}

impl From<inquire::InquireError> for Error {
    fn from(source: inquire::InquireError) -> Self {
        prompt::Error::from(source).into()
    }
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
    domain: &Name<'_>,
) -> Result<(impl Deref<Target = String> + use<>, String), Error> {
    tracing::Span::current().pb_set_message(&format!("Generating private key for {domain}..."));
    let key_pem = rankey::generate_secp384r1_key()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        .context(GenerateKeySnafu)?;
    tracing::Span::current().pb_set_message(&format!(
        "Generating Certificate Signing Request (CSR) for {domain}..."
    ));
    let csr = rankey::generate_csr(&key_pem, "CN", domain.as_full(), &[domain.as_full()])
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        .context(GenerateCsrSnafu)?;
    let csr_pem = csr
        .to_pem(rankey::LineEnding::LF)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        .context(EncodeCsrSnafu)?;
    tracing::Span::current().pb_set_message(&format!(
        "Successfully generated private key and CSR for {domain}."
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
    identities: &Identities,
    domain: &Name<'_>,
    key_pem: &[u8],
    cert_pem: &[u8],
) -> Result<(), Error> {
    let identity_dir = identities.join_name(domain.borrow());
    tracing::Span::current().pb_set_message(&format!(
        "Saving identity for {domain} to {}...",
        identity_dir.display()
    ));
    identities.save(domain.borrow(), cert_pem, key_pem).await?;
    tracing::Span::current().pb_set_finish_message(&format!(
        "Identity for {domain} successfully saved to {}",
        identity_dir.display()
    ));
    Ok(())
}

#[tracing::instrument(skip(cert_server))]
async fn resign_domain(
    identities: &Identities,
    cert_server: &CertServer,
    access_token: &str,
    domain: &Name<'_>,
) -> Result<(), Error> {
    let (key_pem, csr_pem) = generate_private_key_and_csr(domain)?;

    tracing::Span::current().pb_set_message(&format!("Resigning certificate for {domain}..."));
    let ResignResponse { cert_pem } = cert_server
        .resign_cert(access_token, domain.as_full(), &csr_pem)
        .await?;

    // 4. save identity
    save_identity(identities, domain, key_pem.as_bytes(), &cert_pem).await?;

    Ok(())
}

#[tracing::instrument(skip(cert_server))]
async fn resign_domains(
    identities: &Identities,
    cert_server: &CertServer,
    access_token: &str,
    domains: &[Name<'_>],
) -> Result<(), Error> {
    tracing::Span::current().pb_set_style(
        &ProgressStyle::with_template("{span_child_prefix}{spinner} {msg} {pos}/{len}").unwrap(),
    );
    tracing::Span::current().pb_set_length(domains.len() as u64);
    tracing::Span::current().pb_set_message("Resigning certificates for selected domains...");
    for domain in domains {
        resign_domain(identities, cert_server, access_token, domain).await?;
        tracing::Span::current().pb_inc(1);
    }
    tracing::Span::current()
        .pb_set_finish_message("All selected domains have been successfully resigned.");
    Ok(())
}

#[tracing::instrument()]
async fn load_current_default_config(
    identities: &Identities,
) -> Result<Option<DefaultConfigFile>, Error> {
    let path = identities.default_config_path();
    tracing::Span::current().pb_set_message(&format!(
        "Loading default configuration from {}...",
        path.display()
    ));
    let (message, result) = match identities.load_default_config().await {
        Ok(default_config) => ("Default configuration loaded.", Ok(Some(default_config))),
        Err(LoadDefaultConfigError::Io { source, .. })
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
async fn save_default_config(default_config: &DefaultConfigFile) -> Result<(), Error> {
    let path = default_config.path().display();
    tracing::Span::current().pb_set_message(&format!("Saving default configuration to {path}..."));
    default_config.save().await?;
    tracing::Span::current()
        .pb_set_finish_message(&format!("Default configuration saved to {path}."));
    Ok(())
}

#[tracing::instrument()]
async fn query_exist_names_list(identities: &Identities) -> Result<Vec<Name<'static>>, Error> {
    tracing::Span::current().pb_set_message("Querying existing identities...");
    let (message, result) = match identities.list().await {
        Ok(list) => (
            format!("Found {} existing identities.", list.len()),
            Ok(list),
        ),
        Err(ListIdentitiesError::ReadDir { source, .. })
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
    pub domain: Option<String>,
    #[arg(short, long)]
    pub email: Option<String>,
}

impl Create {
    pub async fn run(
        &self,
        genmeta_home: &GenmetaHome,
        cert_server: &CertServer,
    ) -> Result<(), Error> {
        let domain: String = match self.domain.as_ref() {
            // TODO: wait for future cert server domain restrictions
            Some(domain) if !REGISTERABLE_DOMAINS.contains(&domain.as_str()) => {
                whatever!("domain `{domain}` is not registerable")
            }
            Some(domain) => domain.into(),
            None => prompt_domain().await?.into(),
        };
        let name = match self.name.clone() {
            Some(name) => name,
            None => prompt_available_name(cert_server.clone(), domain.clone()).await?,
        };
        let email: String = match self.email.clone() {
            Some(email) => email,
            None => prompt_available_email(cert_server.clone()).await?,
        };
        let domain = Name::try_from_str_full(format!("{name}.{domain}{}", Name::SUFFIX))
            .whatever_context::<_, Error>("invalid domain name format")?;
        let (key_pem, csr_pem) = generate_private_key_and_csr(&domain)?;

        acquire_captcha(cert_server, &email).await?;

        // TODO: cert server returns DER format, avoid double base64 encoding
        let RegisterResponse { cert_pem } =
            prompt_register_catpcha(cert_server.clone(), name, email, csr_pem).await?;

        let identities = genmeta_home.identities();
        save_identity(&identities, &domain, key_pem.as_bytes(), &cert_pem)
            .instrument(info_span!("save_identity"))
            .await?;

        let default_config = load_current_default_config(&identities).await?;
        let current_default_name = default_config
            .as_ref()
            .and_then(|config| config.config().name());

        let update_default_name = match current_default_name.map(|name| name.borrow()) {
            Some(current) => prompt_confim_update_default_name(current, domain.borrow()).await?,
            None => prompt_confirm_set_as_default_name(domain.borrow()).await?,
        };

        if update_default_name {
            let mut default_config =
                default_config.unwrap_or_else(|| identities.new_default_config());
            default_config.config_mut().set_name(domain.to_owned());
            save_default_config(&default_config).await?;
        }

        Ok(())
    }
}

/// Apply to resign identities
#[derive(Parser, Debug, Clone)]
pub struct Apply {
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(short, long)]
    pub domains: Option<Vec<Name<'static>>>,
}

impl Apply {
    pub async fn run(
        &self,
        genmeta_home: &GenmetaHome,
        cert_server: &CertServer,
    ) -> Result<(), Error> {
        let email = match self.email.clone() {
            Some(email) => email,
            None => prompt::prompt_email().await?,
        };

        acquire_captcha(cert_server, &email).await?;
        let LoginResponse {
            access_token,
            domains,
        } = prompt_login_catpcha(cert_server.clone(), email).await?;

        let domains: Cow<'_, [Name<'static>]> = match self.domains.as_deref() {
            Some(domains) => domains.into(),
            None => prompt_select_resign_domains(domains).await?.into(),
        };

        resign_domains(
            &genmeta_home.identities(),
            cert_server,
            &access_token,
            &domains,
        )
        .await?;

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
        genmeta_home: &GenmetaHome,
        _cert_server: &CertServer,
    ) -> Result<(), Error> {
        let identities = genmeta_home.identities();

        let current_config = load_current_default_config(&identities).await?;

        let name = match self.name.as_ref() {
            Some(name) => name.borrow(),
            None => {
                let current_default_name = current_config
                    .as_ref()
                    .and_then(|file| file.config().name().cloned());
                let exist_names = query_exist_names_list(&identities).await?;
                if exist_names.is_empty() {
                    whatever!("no existing identities found");
                }
                prompt_select_default_name(current_default_name, exist_names).await?
            }
        };

        if let Err(error) = identities.load(name.borrow()).await
            && !prompt_confirm_select_default_name_not_exist(&identities, name.to_owned(), error)
                .await?
        {
            whatever!("operation cancelled by user");
        }

        let mut current_config = current_config
            .unwrap_or_else(|| DefaultConfigFile::new(identities.default_config_path().to_owned()));
        current_config.config_mut().set_name(name.to_owned());
        save_default_config(&current_config).await
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
        genmeta_home: &GenmetaHome,
        _cert_server: &CertServer,
    ) -> Result<(), Error> {
        let identities = genmeta_home.identities();
        let names = query_exist_names_list(&identities).await?;
        let default_config = load_current_default_config(&identities).await?;
        let default_name = default_config
            .as_ref()
            .and_then(|c| c.config().name().cloned());
        if names.is_empty() {
            println!("No identities found.");
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
                println!("{marker}{}", name.as_full());
                if self.verbose {
                    let identity = identities.load(name.borrow()).await?;
                    let der = identity.certs()[0].as_ref();
                    let (_, cert) = x509_parser::parse_x509_certificate(der)
                        .whatever_context::<_, Error>("failed to parse certificate")?;
                    println!("    Serial:     {}", cert.serial);
                    println!("    Subject:    {}", cert.subject());
                    println!("    Not Before: {}", cert.validity().not_before);
                    println!("    Not After:  {}", cert.validity().not_after);
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
                            println!("    SANs:       {}", dns_names.join(", "));
                        }
                    }
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
        genmeta_home: &GenmetaHome,
        _cert_server: &CertServer,
    ) -> Result<(), Error> {
        let identities = genmeta_home.identities();
        let name: Name<'static> = match self.name.as_ref() {
            Some(n) => n.to_owned(),
            None => {
                let cfg = load_current_default_config(&identities).await?;
                match cfg.and_then(|c| c.config().name().cloned()) {
                    Some(n) => n,
                    None => whatever!("no default identity configured"),
                }
            }
        };
        let identity = identities.load(name.borrow()).await?;
        let der = identity.certs()[0].as_ref();
        let (_, cert) = x509_parser::parse_x509_certificate(der)
            .whatever_context::<_, Error>("failed to parse certificate")?;
        println!("{}", identity.name().as_full());
        println!("  Serial:     {}", cert.serial);
        println!("  Subject:    {}", cert.subject());
        println!("  Not Before: {}", cert.validity().not_before);
        println!("  Not After:  {}", cert.validity().not_after);
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
                println!("  SANs:       {}", dns_names.join(", "));
            }
        }
        Ok(())
    }
}

#[derive(Parser, Debug, Clone)]
pub enum Options {
    Create(Create),
    Apply(Apply),
    Default(Default),
    Info(Info),
    List(List),
}

impl Options {
    pub async fn run(
        &self,
        genmeta_home: &GenmetaHome,
        cert_server: &CertServer,
    ) -> Result<(), Error> {
        match self {
            Options::Create(cmd) => cmd.run(genmeta_home, cert_server).await,
            Options::Apply(cmd) => cmd.run(genmeta_home, cert_server).await,
            Options::Default(cmd) => cmd.run(genmeta_home, cert_server).await,
            Options::Info(cmd) => cmd.run(genmeta_home, cert_server).await,
            Options::List(cmd) => cmd.run(genmeta_home, cert_server).await,
        }
    }
}

fn init_tracing() {
    let indicatif_layer = IndicatifLayer::new().with_progress_style(
        ProgressStyle::with_template("{span_child_prefix}{spinner} {msg}").unwrap(),
    );
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(indicatif_layer.get_stderr_writer()),
        )
        .with(indicatif_layer)
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
}

pub async fn run(options: Options) -> Result<(), Error> {
    init_tracing();

    let genmeta_home = GenmetaHome::load_from_environment()?;

    _ = rustls::crypto::ring::default_provider().install_default();
    let cert_server = CertServer::new(DEFAULT_CERT_SERVER_BASE_URL)?;

    options.run(&genmeta_home, &cert_server).await
}
