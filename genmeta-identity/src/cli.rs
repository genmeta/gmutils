pub mod prompt;
pub mod validator;

use std::{borrow::Cow, io::IsTerminal, ops::Deref};

use clap::Parser;
use dhttp_home::{
    DhttpHome,
    identity::{
        settings::{DhttpSettingsFile, LoadDhttpSettingsError, SaveDhttpSettingsError},
        ssl::{
            ListIdentityProfilesError, LoadCertsError, LoadKeyError, ResolveIdentityProfileError,
            SaveIdentityError,
        },
    },
};
use dhttp_identity::name::DhttpName as Name;
use futures::TryStreamExt;
use indicatif::ProgressStyle;
use rankey::EncodePem;
use snafu::{OptionExt, ResultExt, Snafu, Whatever, whatever};
use tokio::io;
use tracing::{Instrument, info_span};
use tracing_indicatif::{IndicatifLayer, span_ext::IndicatifSpanExt};
use tracing_subscriber::{
    EnvFilter, filter::LevelFilter, prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
};

use crate::{
    CERT_SERVER_URL_ENV, DEFAULT_CERT_SERVER_BASE_URL,
    cert_server::{self, CertServer},
    cli::prompt::{
        InquireResultExt, prompt_confirm_set_as_default_name, prompt_select_default_identity,
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
    ResolveIdentityProfile { source: ResolveIdentityProfileError },
    #[snafu(transparent)]
    LoadCert { source: LoadCertsError },
    #[snafu(transparent)]
    LoadKey { source: LoadKeyError },
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

async fn acquire_verify_code(
    cert_server: &CertServer,
    email: &str,
    provided: Option<String>,
) -> Result<String, Error> {
    cert_server.send_email_verification(email).await?;
    match provided {
        Some(code) => Ok(code),
        None => prompt::prompt_verify_code()
            .await
            .require_interactive("--verify-code")
            .map_err(Error::from),
    }
}

fn mapped_domain(given_name: &str, surname: &str) -> Result<Name<'static>, Error> {
    let given_name = given_name.trim();
    let surname = surname.trim();
    if let Err(message) = validator::validate_dhttp_label(given_name) {
        whatever!("given name is invalid: {message}");
    }
    if let Err(message) = validator::validate_dhttp_label(surname) {
        whatever!("surname is invalid: {message}");
    }
    let domain = format!("{given_name}.{surname}{}", Name::SUFFIX);
    Name::try_from(domain).whatever_context::<_, Error>("mapped domain is invalid")
}

fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| crate::DEFAULT_DEVICE_NAME.to_string())
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
        Ok(cert_server
            .domain_login(domain.as_full(), &email, &verify_code)
            .await?
            .access_token)
    } else {
        Ok(cert_server.login(&email, &verify_code).await?.access_token)
    }
}

async fn account_token_after_identity_failure(
    cert_server: &CertServer,
    domain: &Name<'_>,
    email: Option<String>,
    verify_code: Option<String>,
    policy: crate::auth::AuthPolicy,
    error: cert_server::Error,
) -> Result<String, Error> {
    let can_get_email_credentials =
        std::io::stdin().is_terminal() || (email.is_some() && verify_code.is_some());
    let failure = crate::auth::classify_api_error(&error);
    if crate::auth::should_fallback_to_email(policy, can_get_email_credentials, failure) {
        println!("identity authentication failed; falling back to email verification");
        login_with_email(cert_server, Some(domain), email, verify_code).await
    } else if crate::auth::is_email_fallback_failure(failure) {
        Err(cert_server::Error::identity_fallback_disabled().into())
    } else {
        Err(error.into())
    }
}

/// Create a new identity
#[derive(Parser, Debug, Clone)]
pub struct Create {
    #[arg(long)]
    pub given_name: Option<String>,
    #[arg(long)]
    pub surname: Option<String>,
    #[arg(long)]
    pub domain: Option<Name<'static>>,
    #[arg(long, default_value = "primary")]
    pub kind: String,
    #[arg(long)]
    pub sequence: Option<i32>,
    #[arg(long)]
    pub device_name: Option<String>,
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(long)]
    pub verify_code: Option<String>,
    #[arg(long, value_enum, default_value_t = crate::auth::AuthPolicy::Auto)]
    pub auth: crate::auth::AuthPolicy,
}

impl Create {
    pub async fn run(&self, dhttp_home: &DhttpHome, cert_server: &CertServer) -> Result<(), Error> {
        let explicit_domain = self.domain.clone();
        let domain = match explicit_domain.clone() {
            Some(domain) => domain,
            None => {
                let given_name = match self.given_name.clone() {
                    Some(value) => value,
                    None => prompt::prompt_given_name()
                        .await
                        .require_interactive("--given-name")?,
                };
                let surname = match self.surname.clone() {
                    Some(value) => value,
                    None => prompt::prompt_surname()
                        .await
                        .require_interactive("--surname")?,
                };
                mapped_domain(&given_name, &surname)?
            }
        };

        validator::validate_kind(&self.kind)
            .whatever_context::<_, Error>("certificate kind is invalid")?;
        let device_name = self.device_name.clone().unwrap_or_else(default_device_name);
        let (key_pem, csr_pem) = generate_private_key_and_csr(&domain)?;

        if explicit_domain.is_some() {
            let identity_attempt = if matches!(self.auth, crate::auth::AuthPolicy::Email) {
                None
            } else {
                Some(
                    cert_server
                        .issue_cert_with_identity(
                            domain.as_full(),
                            domain.as_full(),
                            &self.kind,
                            self.sequence,
                            &device_name,
                            &csr_pem,
                        )
                        .await,
                )
            };

            let cert = match identity_attempt {
                Some(Ok(cert)) => cert,
                Some(Err(error)) if matches!(self.auth, crate::auth::AuthPolicy::Auto) => {
                    let token = account_token_after_identity_failure(
                        cert_server,
                        &domain,
                        self.email.clone(),
                        self.verify_code.clone(),
                        self.auth,
                        error,
                    )
                    .await?;
                    cert_server
                        .issue_cert(
                            &token,
                            domain.as_full(),
                            &self.kind,
                            self.sequence,
                            &device_name,
                            &csr_pem,
                        )
                        .await?
                }
                Some(Err(error)) => return Err(error.into()),
                None => {
                    let token = login_with_email(
                        cert_server,
                        Some(&domain),
                        self.email.clone(),
                        self.verify_code.clone(),
                    )
                    .await?;
                    cert_server
                        .issue_cert(
                            &token,
                            domain.as_full(),
                            &self.kind,
                            self.sequence,
                            &device_name,
                            &csr_pem,
                        )
                        .await?
                }
            };

            save_identity(
                dhttp_home,
                &domain,
                key_pem.as_bytes(),
                cert.cert_pem.as_bytes(),
            )
            .instrument(info_span!("save_identity"))
            .await?;
            ensure_default_identity(dhttp_home, &[domain.borrow()]).await?;
            return Ok(());
        }

        if matches!(self.auth, crate::auth::AuthPolicy::Identity) {
            whatever!("identity auth cannot create a domain before the first certificate exists");
        }

        let email = match self.email.clone() {
            Some(email) => email,
            None => prompt::prompt_email()
                .await
                .require_interactive("--email")?,
        };
        let verify_code =
            acquire_verify_code(cert_server, &email, self.verify_code.clone()).await?;
        let created = cert_server
            .create_domain_with_email(domain.as_full(), &email, &verify_code)
            .await?;

        let access_token = if let Some(auth) = created.auth.clone() {
            auth.access_token
        } else {
            cert_server.login(&email, &verify_code).await?.access_token
        };

        if let Some(payment_entry) = created.payment_entry.as_ref() {
            crate::checkout::print_payment_instructions(&created);
            let completed = crate::checkout::wait_for_checkout_completion(
                cert_server,
                &payment_entry.checkout_token,
            )
            .await?;
            match crate::checkout::classify_checkout(&completed) {
                crate::checkout::CheckoutState::Completed => {}
                crate::checkout::CheckoutState::Expired => {
                    whatever!("checkout expired before payment completed")
                }
                crate::checkout::CheckoutState::Cancelled => whatever!("checkout was cancelled"),
                crate::checkout::CheckoutState::Pending => {
                    whatever!("checkout did not reach a terminal state")
                }
            }
        }

        let cert = cert_server
            .issue_cert(
                &access_token,
                domain.as_full(),
                &self.kind,
                self.sequence,
                &device_name,
                &csr_pem,
            )
            .await?;

        save_identity(
            dhttp_home,
            &domain,
            key_pem.as_bytes(),
            cert.cert_pem.as_bytes(),
        )
        .instrument(info_span!("save_identity"))
        .await?;

        ensure_default_identity(dhttp_home, &[domain.borrow()]).await?;

        Ok(())
    }
}

/// Apply identity
#[derive(Parser, Debug, Clone)]
pub struct Apply {
    #[arg(long)]
    pub domain: Option<Name<'static>>,
    #[arg(long)]
    pub kind: Option<String>,
    #[arg(long)]
    pub sequence: Option<i32>,
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(long)]
    pub verify_code: Option<String>,
    #[arg(long, value_enum, default_value_t = crate::auth::AuthPolicy::Auto)]
    pub auth: crate::auth::AuthPolicy,
}

impl Apply {
    pub async fn run(&self, dhttp_home: &DhttpHome, cert_server: &CertServer) -> Result<(), Error> {
        let domain = match self.domain.clone() {
            Some(domain) => domain,
            None => prompt_select_default_identity(query_exist_names_list(dhttp_home).await?)
                .await
                .require_interactive("--domain")?
                .whatever_context::<_, Error>("no identity selected")?,
        };
        let kind = self.kind.clone().unwrap_or_else(|| "primary".to_string());
        validator::validate_kind(&kind)
            .whatever_context::<_, Error>("certificate kind is invalid")?;
        let sequence = match self.sequence {
            Some(sequence) => sequence,
            None => prompt::prompt_sequence()
                .await
                .require_interactive("--sequence")?,
        };

        let identity_attempt = if matches!(self.auth, crate::auth::AuthPolicy::Email) {
            None
        } else {
            Some(
                cert_server
                    .list_certs_with_identity(
                        domain.as_full(),
                        domain.as_full(),
                        Some(&kind),
                        Some(sequence),
                    )
                    .await,
            )
        };
        let (page, token) = match identity_attempt {
            Some(Ok(page)) => (page, None),
            Some(Err(error)) if matches!(self.auth, crate::auth::AuthPolicy::Auto) => {
                let token = account_token_after_identity_failure(
                    cert_server,
                    &domain,
                    self.email.clone(),
                    self.verify_code.clone(),
                    self.auth,
                    error,
                )
                .await?;
                let page = cert_server
                    .list_certs(&token, domain.as_full(), Some(&kind), Some(sequence))
                    .await?;
                (page, Some(token))
            }
            Some(Err(error)) => return Err(error.into()),
            None => {
                let token = login_with_email(
                    cert_server,
                    Some(&domain),
                    self.email.clone(),
                    self.verify_code.clone(),
                )
                .await?;
                let page = cert_server
                    .list_certs(&token, domain.as_full(), Some(&kind), Some(sequence))
                    .await?;
                (page, Some(token))
            }
        };
        let selected = page
            .list
            .iter()
            .find(|item| item.status == "active")
            .or_else(|| page.list.first())
            .whatever_context::<_, Error>("no certificate found for selected chain")?;
        let serial = selected
            .serial_number
            .as_ref()
            .whatever_context::<_, Error>("selected certificate has no serial number")?;
        let detail = match token {
            Some(token) => cert_server.get_cert_detail(&token, serial).await?,
            None => {
                cert_server
                    .get_cert_detail_with_identity(domain.as_full(), serial)
                    .await?
            }
        };

        let identity = dhttp_home.resolve_identity_profile(domain.borrow()).await?;
        let key = identity.load_key().await?;
        let matched = crate::local_identity::private_key_matches_certificate(
            key.secret_der(),
            detail.cert_pem.as_bytes(),
        )?;
        if !matched {
            whatever!(
                "local private key does not match downloaded certificate; use renew or create a new chain"
            );
        }
        let cert_path = identity
            .ssl_dir()
            .join(dhttp_home::identity::ssl::CERT_FILE_NAME);
        tokio::fs::write(&cert_path, detail.cert_pem.as_bytes())
            .await
            .whatever_context::<_, Error>(format!(
                "failed to write certificate file {}",
                cert_path.display()
            ))?;
        ensure_default_identity(dhttp_home, &[domain.borrow()]).await?;

        Ok(())
    }
}

/// Renew identities
#[derive(Parser, Debug, Clone)]
pub struct Renew {
    #[arg(long)]
    pub domain: Option<Name<'static>>,
    #[arg(long, default_value = "primary")]
    pub kind: String,
    #[arg(long)]
    pub sequence: Option<i32>,
    #[arg(long)]
    pub device_name: Option<String>,
    #[arg(short, long)]
    pub email: Option<String>,
    #[arg(long)]
    pub verify_code: Option<String>,
    #[arg(long, value_enum, default_value_t = crate::auth::AuthPolicy::Auto)]
    pub auth: crate::auth::AuthPolicy,
}

impl Renew {
    pub async fn run(&self, dhttp_home: &DhttpHome, cert_server: &CertServer) -> Result<(), Error> {
        let domain = match self.domain.clone() {
            Some(domain) => domain,
            None => prompt_select_default_identity(query_exist_names_list(dhttp_home).await?)
                .await
                .require_interactive("--domain")?
                .whatever_context::<_, Error>("no identity selected")?,
        };
        validator::validate_kind(&self.kind)
            .whatever_context::<_, Error>("certificate kind is invalid")?;
        let sequence = match self.sequence {
            Some(sequence) => sequence,
            None => prompt::prompt_sequence()
                .await
                .require_interactive("--sequence")?,
        };
        let device_name = self.device_name.clone().unwrap_or_else(default_device_name);
        let (key_pem, csr_pem) = generate_private_key_and_csr(&domain)?;
        let identity_attempt = if matches!(self.auth, crate::auth::AuthPolicy::Email) {
            None
        } else {
            Some(
                cert_server
                    .renew_cert_with_identity(
                        domain.as_full(),
                        domain.as_full(),
                        &self.kind,
                        sequence,
                        Some(&device_name),
                        &csr_pem,
                    )
                    .await,
            )
        };

        let detail = match identity_attempt {
            Some(Ok(detail)) => detail,
            Some(Err(error)) if matches!(self.auth, crate::auth::AuthPolicy::Auto) => {
                let token = account_token_after_identity_failure(
                    cert_server,
                    &domain,
                    self.email.clone(),
                    self.verify_code.clone(),
                    self.auth,
                    error,
                )
                .await?;
                cert_server
                    .renew_cert(
                        &token,
                        domain.as_full(),
                        &self.kind,
                        sequence,
                        Some(&device_name),
                        &csr_pem,
                    )
                    .await?
            }
            Some(Err(error)) => return Err(error.into()),
            None => {
                let token = login_with_email(
                    cert_server,
                    Some(&domain),
                    self.email.clone(),
                    self.verify_code.clone(),
                )
                .await?;
                cert_server
                    .renew_cert(
                        &token,
                        domain.as_full(),
                        &self.kind,
                        sequence,
                        Some(&device_name),
                        &csr_pem,
                    )
                    .await?
            }
        };
        save_identity(
            dhttp_home,
            &domain,
            key_pem.as_bytes(),
            detail.cert_pem.as_bytes(),
        )
        .await?;
        ensure_default_identity(dhttp_home, &[domain.borrow()]).await?;

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

fn cert_server_base_url(override_url: Option<String>) -> Cow<'static, str> {
    match override_url {
        Some(url) => Cow::Owned(url),
        None => Cow::Borrowed(DEFAULT_CERT_SERVER_BASE_URL),
    }
}

pub async fn run(options: Options) -> Result<(), Error> {
    init_tracing();

    let dhttp_home = DhttpHome::load_from_environment()?;

    _ = rustls::crypto::ring::default_provider().install_default();
    let cert_server_url = cert_server_base_url(std::env::var(CERT_SERVER_URL_ENV).ok());
    let cert_server = CertServer::new(cert_server_url.as_ref())?;

    options.run(&dhttp_home, &cert_server).await
}

#[cfg(test)]
mod tests {
    use super::cert_server_base_url;
    use crate::DEFAULT_CERT_SERVER_BASE_URL;

    #[test]
    fn cert_server_base_url_uses_default_when_env_is_absent() {
        let url = cert_server_base_url(None);
        assert_eq!(url.as_ref(), DEFAULT_CERT_SERVER_BASE_URL);
    }

    #[test]
    fn cert_server_base_url_uses_environment_override() {
        let url = cert_server_base_url(Some("https://keine.gensokyo".into()));
        assert_eq!(url.as_ref(), "https://keine.gensokyo");
    }
}
