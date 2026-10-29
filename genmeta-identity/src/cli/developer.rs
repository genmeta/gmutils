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
    /// Full domain or short identity name
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
    /// Issue a new developer key and certificate, preserving TLS credentials
    Apply {
        #[arg(long, default_value = "local developer")]
        device_name: String,
    },
    /// Rotate the key of one existing developer sequence without purchasing again
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
        let value = match &self.command {
            DeveloperCommand::Subscription => {
                server.code_signing_subscriptions(&token, &domain).await?
            }
            DeveloperCommand::Purchase { idempotency_key } => {
                server
                    .purchase_code_signing(&token, &domain, idempotency_key)
                    .await?
            }
            DeveloperCommand::Invoice { invoice_no } => {
                let invoice = server.get_invoice(&token, invoice_no).await?;
                json!({"invoice_no":invoice.invoice_no,"domain":invoice.domain,"status":invoice.status,"amount":invoice.amount,"currency":invoice.currency,"url":invoice.url})
            }
            DeveloperCommand::AutoRenew {
                subscription_no,
                enabled,
            } => {
                server
                    .set_code_signing_renewal(&token, subscription_no, *enabled)
                    .await?
            }
            DeveloperCommand::Revoke {
                serial_number,
                issuer_id,
                whole_sequence,
            } => {
                server
                    .revoke_developer_certificate(&token, serial_number, issuer_id, *whole_sequence)
                    .await?
            }
            DeveloperCommand::Apply { .. } | DeveloperCommand::Renew { .. } => {
                let profile = home.resolve_identity_profile_exactly(&domain).await?;
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
                let certificate = pending
                    .request_certificate(&profile, server, &token, device)
                    .await?;
                let chain = code_signing::parse_chain(&certificate.certificate.cert_pem)
                    .map_err(local_error)?;
                let fingerprint = code_signing::fingerprint(&chain).map_err(local_error)?;
                let status = server
                    .exact_certificate_status(&domain, &fingerprint)
                    .await?;
                code_signing::verify_status(&status, &chain, &domain, true).map_err(local_error)?;
                let sequence = certificate.certificate.sequence;
                pending
                    .install(&profile, &certificate)
                    .map_err(local_error)?;
                json!({"domain":domain,"purpose":"code_signing","sequence":sequence,"fingerprint_sha256":fingerprint,"valid_not_after":certificate.certificate.valid_not_after})
            }
            DeveloperCommand::Pricing | DeveloperCommand::Status { .. } => unreachable!(),
        };
        output(value)
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
