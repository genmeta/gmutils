use std::io::IsTerminal;

use clap::{Parser, Subcommand};
use dhttp_home::DhttpHome;
use serde_json::{Value, json};
use snafu::FromString;

use super::{
    Error,
    flow::email::{EmailLogin, run_cert_server_email_session},
};
use crate::{cert_server::CertServer, code_signing};

#[derive(Parser, Debug, Clone)]
pub struct Developer {
    /// Actual developer child for Apply/Renew; billing commands use the root name
    pub name: String,
    #[arg(long)]
    pub email: Option<String>,
    #[arg(long, hide = true)]
    pub verify_code: Option<String>,
    #[command(subcommand)]
    pub command: DeveloperCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DeveloperCommand {
    Pricing,
    Subscription,
    /// Create or recover the same purchase; then pay its invoice in the web console
    Purchase {
        #[arg(long)]
        idempotency_key: String,
    },
    Invoice {
        invoice_no: String,
    },
    /// Issue one developer identity for TLS and package signing
    Apply {
        #[arg(long, default_value = "local developer")]
        device_name: String,
    },
    /// Renew one developer sequence, recovering checkout if entitlement has expired
    Renew {
        #[arg(long)]
        sequence: u32,
    },
    Revoke {
        #[arg(long)]
        serial_number: String,
        #[arg(long)]
        issuer_id: String,
        #[arg(long)]
        whole_sequence: bool,
    },
    Status {
        #[arg(long)]
        fingerprint_sha256: String,
    },
    AutoRenew {
        subscription_no: String,
        #[arg(value_parser=clap::value_parser!(bool))]
        enabled: bool,
    },
}

impl Developer {
    pub async fn run(&self, home: &DhttpHome, server: &CertServer) -> Result<(), Error> {
        let domain = dhttp_home::normalize_name(&self.name)
            .ok_or_else(|| Error::without_source("invalid developer identity".into()))?;
        if let DeveloperCommand::Pricing = self.command {
            return output(server.code_signing_pricing(&domain).await?);
        }
        if let DeveloperCommand::Status {
            ref fingerprint_sha256,
        } = self.command
        {
            let status = server
                .exact_certificate_status(&domain, fingerprint_sha256)
                .await?;
            return output(
                json!({"domain":status.domain,"purpose":status.purpose,"fingerprint_sha256":status.fingerprint_sha256,"publication_allowed":status.publication_allowed,"revocation_status":status.revocation_status,"issuer_status":status.issuer_status,"checked_at":status.checked_at}),
            );
        }
        let token = run_cert_server_email_session(
            server,
            EmailLogin::Account,
            self.email.as_deref(),
            self.verify_code.as_deref(),
            std::io::stdin().is_terminal(),
        )
        .await?;
        output(
            self.run_authorized(home, server, &token, std::io::stdin().is_terminal())
                .await?,
        )
    }

    async fn run_authorized(
        &self,
        home: &DhttpHome,
        server: &CertServer,
        token: &str,
        interactive: bool,
    ) -> Result<Value, Error> {
        let domain = dhttp_home::normalize_name(&self.name)
            .ok_or_else(|| Error::without_source("invalid developer identity".into()))?;
        let value = match &self.command {
            DeveloperCommand::Subscription => {
                server.code_signing_subscriptions(token, &domain).await?
            }
            DeveloperCommand::Purchase { idempotency_key } => {
                server
                    .purchase_code_signing(token, &domain, idempotency_key)
                    .await?
            }
            DeveloperCommand::Invoice { invoice_no } => {
                let invoice = server.get_invoice(token, invoice_no).await?;
                json!({"invoice_no":invoice.invoice_no,"domain":invoice.domain,"status":invoice.status,"amount":invoice.amount,"currency":invoice.currency,"url":invoice.url})
            }
            DeveloperCommand::AutoRenew {
                subscription_no,
                enabled,
            } => {
                server
                    .set_code_signing_renewal(token, subscription_no, *enabled)
                    .await?
            }
            DeveloperCommand::Revoke {
                serial_number,
                issuer_id,
                whole_sequence,
            } => {
                server
                    .revoke_developer_certificate(token, serial_number, issuer_id, *whole_sequence)
                    .await?
            }
            DeveloperCommand::Apply { .. } | DeveloperCommand::Renew { .. } => {
                let subscriptions = server.code_signing_subscriptions(token, &domain).await?;
                let (root, domain) = developer_target(&subscriptions, &domain)?;
                let profile = home
                    .identity_profile(&domain)
                    .map_err(|e| Error::without_source(e.to_string()))?;
                tokio::fs::create_dir_all(profile.path())
                    .await
                    .map_err(|e| Error::without_source(e.to_string()))?;
                let _lock = code_signing::lock(&profile).map_err(local_error)?;
                let sequence = if let DeveloperCommand::Renew { sequence } = self.command {
                    Some(sequence)
                } else {
                    None
                };
                let mut pending =
                    code_signing::Pending::prepare(&profile, sequence).map_err(local_error)?;
                let device = if let DeveloperCommand::Apply { device_name } = &self.command {
                    device_name.as_str()
                } else {
                    "local developer"
                };
                ensure_entitlement(server, token, &root, pending.operation_key(), interactive)
                    .await?;
                let binding = server.code_signing_subscriptions(token, &root).await?;
                let ready = binding["items"]
                    .as_array()
                    .and_then(|items| {
                        items
                            .iter()
                            .find(|item| item["domain"] == root && item["status"] == "active")
                    })
                    .is_some_and(|item| {
                        item["developer_domain"] == domain && item["developer_ready"] == true
                    });
                if !ready {
                    // Existing paid subscriptions can initialize their fixed child without another invoice.
                    let binding = server
                        .purchase_code_signing(token, &root, pending.operation_key())
                        .await?;
                    if binding["developer_domain"] != domain || binding["developer_ready"] != true {
                        return Err(Error::without_source("Developer domain is not provisioned yet; retry this operation after fulfillment.".into()));
                    }
                }
                let certificate = pending
                    .request_certificate(&profile, server, token, device)
                    .await?;
                let chain = code_signing::parse_chain(&certificate.certificate.cert_pem)
                    .map_err(local_error)?;
                let fingerprint = code_signing::fingerprint(&chain).map_err(local_error)?;
                code_signing::verify_chain(&chain, &domain, rustls::pki_types::UnixTime::now())
                    .map_err(local_error)?;
                let key_pem = pending.key_pem().to_owned();
                if certificate.certificate.csr.trim() != pending.csr().trim()
                    || certificate.purpose != "code_signing"
                {
                    return Err(Error::without_source(
                        "developer response does not match request".into(),
                    ));
                }
                super::flow::install::validate_install(
                    &certificate.certificate,
                    &super::flow::install::InstallExpectation {
                        target: super::flow::target::IdentityTarget::parse(&domain)?.dhttp_name(),
                        kind: super::flow::kind::IdentityKind::Primary,
                        sequence,
                    },
                    &key_pem,
                )?;
                // save_identity stages the certificate and private key as one identity.
                // Keep the pending request until both installation steps succeed.
                let has_transport = profile
                    .ssl_dir()
                    .join(dhttp_home::identity::ssl::CERT_FILE_NAME)
                    .try_exists()
                    .map_err(|e| Error::without_source(e.to_string()))?;
                let install_transport = !has_transport || installed_sequence(&profile)?.is_some();
                if install_transport {
                    profile
                        .save_identity(
                            certificate.certificate.cert_pem.as_bytes(),
                            key_pem.as_bytes(),
                        )
                        .await
                        .map_err(|e| Error::without_source(e.to_string()))?;
                }
                let sequence = certificate.certificate.sequence;
                pending
                    .install(&profile, &certificate)
                    .map_err(local_error)?;
                json!({"domain":domain,"root_domain":root,"transport_installed":install_transport,"purpose":"code_signing","sequence":sequence,"fingerprint_sha256":fingerprint,"valid_not_after":certificate.certificate.valid_not_after})
            }
            DeveloperCommand::Pricing | DeveloperCommand::Status { .. } => unreachable!(),
        };
        Ok(value)
    }
}
fn local_error(error: snafu::Whatever) -> Error {
    Error::without_source(error.to_string())
}
fn output(value: Value) -> Result<(), Error> {
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|e| Error::without_source(e.to_string()))?
    );
    Ok(())
}

/// Detect the certificate type even after expiry, so renewal never downgrades it.
pub(super) fn installed_sequence(
    profile: &dhttp_home::identity::IdentityProfile,
) -> Result<Option<u32>, Error> {
    let pem = match std::fs::read(
        profile
            .ssl_dir()
            .join(dhttp_home::identity::ssl::CERT_FILE_NAME),
    ) {
        Ok(pem) => pem,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::without_source(error.to_string())),
    };
    let pem = std::str::from_utf8(&pem).map_err(|e| Error::without_source(e.to_string()))?;
    let chain = code_signing::parse_chain(pem).map_err(local_error)?;
    let leaf = chain
        .first()
        .ok_or_else(|| Error::without_source("empty identity chain".into()))?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| Error::without_source(e.to_string()))?;
    let developer = cert
        .extended_key_usage()
        .map_err(|e| Error::without_source(e.to_string()))?
        .is_some_and(|eku| eku.value.code_signing);
    if !developer {
        return Ok(None);
    }
    let ski = dhttp_home::certificate::extract_dhttp_subject_key_identifier(&chain)
        .map_err(|e| Error::without_source(e.to_string()))?;
    Ok(Some(ski.chain().sequence().get()))
}

fn has_entitlement(subscriptions: &Value, domain: &str, now: i64) -> bool {
    subscriptions["items"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item["domain"].as_str() == Some(domain)
                && item["status"] == "active"
                && item["paid_through"].as_i64().is_some_and(|end| end > now)
        })
    })
}

pub(super) async fn apply_for_account(
    home: &DhttpHome,
    server: &CertServer,
    token: &str,
    domain: &str,
    device_name: &str,
    required: bool,
) -> Result<bool, Error> {
    let profile = home
        .identity_profile(domain)
        .map_err(|e| Error::without_source(e.to_string()))?;
    let sequence = installed_sequence(&profile)?;
    let pending_apply = code_signing::directory(&profile)
        .join("apply.pending.json")
        .exists();
    if !required && sequence.is_none() && !pending_apply {
        return Ok(false);
    }
    let command = Developer {
        name: domain.into(),
        email: None,
        verify_code: None,
        command: match sequence.filter(|_| !pending_apply) {
            Some(sequence) => DeveloperCommand::Renew { sequence },
            None => DeveloperCommand::Apply {
                device_name: device_name.into(),
            },
        },
    };
    output(
        command
            .run_authorized(home, server, token, std::io::stdin().is_terminal())
            .await?,
    )?;
    Ok(true)
}

fn developer_target(subscriptions: &Value, requested: &str) -> Result<(String, String), Error> {
    let items = subscriptions["items"]
        .as_array()
        .ok_or_else(|| Error::without_source("Invalid developer subscription response".into()))?;
    let binding = items
        .iter()
        .find(|item| item["status"] != "terminated" && item["developer_domain"] == requested);
    let root = match binding.and_then(|item| item["domain"].as_str()) {
        Some(root) => root,
        None => requested
            .strip_suffix(dhttp_home::DHTTP_SUFFIX)
            .and_then(|name| name.strip_prefix("dev."))
            .filter(|root| root.contains('.'))
            .and_then(|_| requested.strip_prefix("dev."))
            .ok_or_else(|| {
                Error::without_source(
                    "Select the actual development child, for example dev.alex.chen".into(),
                )
            })?,
    };
    let target = requested.to_owned();
    if dhttp_home::normalize_name(root).as_deref() != Some(root)
        || dhttp_home::normalize_name(&target).as_deref() != Some(target.as_str())
        || target != format!("dev.{root}")
    {
        return Err(Error::without_source("Invalid developer root name".into()));
    }
    if items.iter().any(|item| {
        item["domain"] == root
            && item["developer_domain"]
                .as_str()
                .is_some_and(|name| name != target)
    }) {
        return Err(Error::without_source(
            "The server developer binding does not match the root name".into(),
        ));
    }
    Ok((root.to_owned(), target))
}

/// Prepare credentials for the actual developer child without changing the requested name.
pub async fn prepare_for_publish(
    home: &DhttpHome,
    server: &CertServer,
    developer: &str,
    email: Option<&str>,
    interactive: bool,
) -> Result<Value, Error> {
    if !interactive {
        return Err(Error::without_source("Developer credentials must be prepared interactively before noninteractive publication.".into()));
    }
    let token =
        run_cert_server_email_session(server, EmailLogin::Account, email, None, true).await?;
    let command = Developer {
        name: developer.to_owned(),
        email: None,
        verify_code: None,
        command: DeveloperCommand::Apply {
            device_name: "jade publish".into(),
        },
    };
    command.run_authorized(home, server, &token, true).await
}

trait CheckoutUi {
    async fn confirm(&mut self, pricing: &Value) -> Result<bool, Error>;
    async fn open(&mut self, url: &str) -> Result<(), Error>;
    async fn wait(&mut self) -> Result<bool, Error>;
}
struct TerminalCheckout {
    polls: usize,
}
impl CheckoutUi for TerminalCheckout {
    async fn confirm(&mut self, pricing: &Value) -> Result<bool, Error> {
        use super::prompt::InquireResultExt;
        let price = &pricing["code_signing"];
        let amount = price["amount"]
            .as_i64()
            .filter(|amount| *amount >= 0)
            .ok_or_else(|| Error::without_source("Developer pricing is unavailable".into()))?;
        let currency = price["currency"]
            .as_str()
            .ok_or_else(|| Error::without_source("Developer currency is unavailable".into()))?;
        if price["enabled"] != true {
            return Err(Error::without_source(
                "Developer purchases are unavailable".into(),
            ));
        }
        let question = format!(
            "Activate developer signing for {}.{:02} {currency}/year with annual automatic renewal? Discounts and final payment are shown at checkout.",
            amount / 100,
            amount % 100
        );
        Ok(super::prompt::sync(move || {
            inquire::Confirm::new(&question)
                .with_default(false)
                .prompt()
        })
        .await
        .require_interactive("developer subscription purchase")?)
    }
    async fn open(&mut self, url: &str) -> Result<(), Error> {
        let parsed = reqwest::Url::parse(url).map_err(|e| Error::without_source(e.to_string()))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(Error::without_source(
                "Checkout requires a valid HTTPS URL".into(),
            ));
        }
        super::flow::transcript::print_err_block(
            &crate::checkout::payment_instruction_block_or_link(url),
        );
        #[cfg(target_os = "macos")]
        let command = Some(("open", vec![url]));
        #[cfg(target_os = "linux")]
        let command = Some(("xdg-open", vec![url]));
        #[cfg(target_os = "windows")]
        let command = Some(("rundll32", vec!["url.dll,FileProtocolHandler", url]));
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        let command: Option<(&str, Vec<&str>)> = None;
        if let Some((program, args)) = command {
            // Opening is best effort; the printed link remains usable on another device.
            let _ = tokio::process::Command::new(program)
                .args(args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await;
        }
        super::flow::transcript::print_line(
            "Waiting for confirmed payment. Ctrl+C preserves this checkout for retry.",
        );
        Ok(())
    }
    async fn wait(&mut self) -> Result<bool, Error> {
        if self.polls >= 120 {
            return Err(Error::without_source(
                "Checkout is still pending. Rerun the command to resume the same invoice.".into(),
            ));
        }
        self.polls += 1;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        Ok(true)
    }
}

async fn ensure_entitlement(
    server: &CertServer,
    token: &str,
    domain: &str,
    operation_key: &str,
    interactive: bool,
) -> Result<(), Error> {
    ensure_entitlement_with_ui(
        server,
        token,
        domain,
        operation_key,
        interactive,
        &mut TerminalCheckout { polls: 0 },
    )
    .await
}

async fn ensure_entitlement_with_ui(
    server: &CertServer,
    token: &str,
    domain: &str,
    operation_key: &str,
    interactive: bool,
    ui: &mut impl CheckoutUi,
) -> Result<(), Error> {
    let subscriptions = server.code_signing_subscriptions(token, domain).await?;
    if !subscriptions["items"].is_array() {
        return Err(Error::without_source(
            "Invalid developer subscription response".into(),
        ));
    }
    if has_entitlement(&subscriptions, domain, chrono::Utc::now().timestamp()) {
        return Ok(());
    }
    if !interactive {
        return Err(Error::without_source("Payment required. Complete developer setup interactively, then retry; no order was created.".into()));
    }
    let pricing = server.code_signing_pricing(domain).await?;
    if !ui.confirm(&pricing).await? {
        return Err(Error::without_source(
            "Developer checkout cancelled; no new order was created.".into(),
        ));
    }
    let mut attempt = server
        .purchase_code_signing(token, domain, operation_key)
        .await;
    if attempt
        .as_ref()
        .err()
        .is_some_and(|e| e.is_api_code("purchase_ended"))
    {
        let latest = subscriptions["items"]
            .as_array()
            .and_then(|items| items.iter().find(|item| item["domain"] == domain))
            .and_then(|item| item["invoice_no"].as_str())
            .ok_or_else(|| {
                Error::without_source(
                    "Cannot replace checkout without the ended invoice identity".into(),
                )
            })?;
        attempt = server
            .purchase_code_signing(token, domain, &format!("{operation_key}-{latest}"))
            .await;
    }
    let purchase = match attempt {
        Ok(value) => value,
        Err(error) if error.is_api_code("purchase_in_progress") => {
            let subscriptions = server.code_signing_subscriptions(token, domain).await?;
            if has_entitlement(&subscriptions, domain, chrono::Utc::now().timestamp()) {
                return Ok(());
            }
            subscriptions["items"]
                .as_array()
                .and_then(|items| {
                    items
                        .iter()
                        .find(|item| item["domain"] == domain && item["invoice_no"].is_string())
                })
                .cloned()
                .ok_or(error)?
        }
        Err(error) => return Err(error.into()),
    };
    if has_entitlement(
        &server.code_signing_subscriptions(token, domain).await?,
        domain,
        chrono::Utc::now().timestamp(),
    ) {
        return Ok(());
    }
    let invoice_no = purchase["invoice_no"].as_str().ok_or_else(|| {
        Error::without_source("Developer checkout did not return an invoice".into())
    })?;
    let invoice = server.get_invoice(token, invoice_no).await?;
    ui.open(&invoice.url).await?;
    loop {
        if !ui.wait().await? {
            return Err(Error::without_source(
                "Developer checkout cancelled; its operation is preserved.".into(),
            ));
        }
        if has_entitlement(
            &server.code_signing_subscriptions(token, domain).await?,
            domain,
            chrono::Utc::now().timestamp(),
        ) {
            return Ok(());
        }
        let invoice = server.get_invoice(token, invoice_no).await?;
        if !matches!(invoice.status.as_str(), "pending" | "paid") {
            return Err(Error::without_source(format!(
                "Developer checkout ended with status {}. Rerun to create or recover checkout.",
                invoice.status
            )));
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/cli/developer.rs"]
mod tests;
