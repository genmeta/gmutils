use std::time::Duration;

use qrcode::{QrCode, render::unicode, types::QrError};
use snafu::FromString;

use crate::{cert_server::CreateDomainResponse, cli::flow::transcript};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutState {
    Pending,
    Completed,
    Expired,
    Cancelled,
    Failed,
}

pub fn classify_checkout(response: &CreateDomainResponse) -> CheckoutState {
    if response.next_action == "completed" {
        return CheckoutState::Completed;
    }

    if let Some(invoice) = &response.invoice {
        return match invoice.status.as_str() {
            "paid" => CheckoutState::Completed,
            "expired" => CheckoutState::Expired,
            "cancelled" | "canceled" => CheckoutState::Cancelled,
            "pending" | "open" | "unpaid" | "processing" => CheckoutState::Pending,
            _ => CheckoutState::Failed,
        };
    }

    if let Some(reservation) = &response.reservation {
        return match reservation.status.as_str() {
            "expired" => CheckoutState::Expired,
            "cancelled" | "canceled" => CheckoutState::Cancelled,
            "pending" | "reserved" => CheckoutState::Pending,
            _ => CheckoutState::Failed,
        };
    }

    match response.next_action.as_str() {
        "payment" | "pending" => CheckoutState::Pending,
        _ => CheckoutState::Failed,
    }
}

pub fn print_payment_instructions(response: &CreateDomainResponse) {
    if let Some(payment_entry) = &response.payment_entry {
        let block = payment_instruction_block_or_link(&payment_entry.url);
        transcript::print_err_block(&block);
    }
}

fn render_terminal_qr(url: &str) -> Result<String, QrError> {
    let code = QrCode::new(url.as_bytes())?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .module_dimensions(1, 1)
        .build())
}

pub(crate) fn payment_instruction_block(url: &str) -> Result<String, QrError> {
    let qr = render_terminal_qr(url)?;
    let mut block = String::from(
        "[!] Please complete your payment within 15 minutes.\n    Open the link, or scan the QR code below\n\n",
    );

    for line in qr
        .trim_end()
        .lines()
        .skip_while(|line| line.trim().is_empty())
    {
        block.push_str("    ");
        block.push_str(line);
        block.push('\n');
    }

    block.push_str("\n    Link: ");
    block.push_str(url);
    Ok(block)
}

pub(crate) fn payment_instruction_block_or_link(url: &str) -> String {
    payment_instruction_block(url).unwrap_or_else(|_| payment_link_only_instruction_block(url))
}

fn payment_link_only_instruction_block(url: &str) -> String {
    format!(
        "[!] Please complete your payment within 15 minutes.\n    Open the link below\n\n    Link: {url}"
    )
}

pub async fn wait_for_checkout_completion(
    cert_server: &crate::cert_server::CertServer,
    checkout_token: &str,
) -> Result<CreateDomainResponse, crate::cert_server::Error> {
    wait_for_checkout_completion_until(
        cert_server,
        checkout_token,
        crate::cli::flow::local::now_unix_timestamp().saturating_add(15 * 60),
    )
    .await
}

pub(crate) async fn wait_for_checkout_completion_until(
    cert_server: &crate::cert_server::CertServer,
    checkout_token: &str,
    expires_at: i64,
) -> Result<CreateDomainResponse, crate::cert_server::Error> {
    let wait = checkout_wait_duration(expires_at, crate::cli::flow::local::now_unix_timestamp());
    if wait.is_zero() {
        return Err(checkout_expired_error());
    }

    let poll =
        crate::cli::flow::progress::run(crate::cli::flow::progress::WAIT_FOR_PAYMENT, async {
            loop {
                let response = cert_server.get_checkout(checkout_token).await?;
                match classify_checkout(&response) {
                    CheckoutState::Completed => return Ok(response),
                    CheckoutState::Expired => return Err(checkout_expired_error()),
                    CheckoutState::Cancelled => {
                        return Err(crate::cert_server::Error::without_source(
                            "checkout was cancelled before payment was completed".to_string(),
                        ));
                    }
                    CheckoutState::Failed => {
                        return Err(crate::cert_server::Error::without_source(
                            "checkout failed or returned an unsupported terminal state".to_string(),
                        ));
                    }
                    CheckoutState::Pending => tokio::time::sleep(Duration::from_secs(3)).await,
                }
            }
        });
    match tokio::time::timeout(wait, poll).await {
        Ok(result) => result,
        Err(_) => Err(checkout_expired_error()),
    }
}

pub(crate) fn checkout_wait_duration(expires_at: i64, now: i64) -> Duration {
    const MAX_WAIT_SECONDS: u64 = 15 * 60;

    Duration::from_secs(
        u64::try_from(expires_at.saturating_sub(now))
            .unwrap_or(0)
            .min(MAX_WAIT_SECONDS),
    )
}

fn checkout_expired_error() -> crate::cert_server::Error {
    crate::cert_server::Error::without_source(
        "checkout expired before payment was completed".to_string(),
    )
}

#[cfg(test)]
#[path = "../tests/unit/checkout.rs"]
mod tests;
