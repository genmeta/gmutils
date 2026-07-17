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

    for line in qr.trim_end().lines() {
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

fn checkout_wait_duration(expires_at: i64, now: i64) -> Duration {
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
mod tests {
    use super::*;
    use crate::cert_server::CreateDomainResponse;

    #[test]
    fn completed_next_action_is_terminal() {
        let response: CreateDomainResponse = serde_json::from_str(
            r#"{"domain":"alice.smith.dhttp.net","quotes":{"currency":"USD","monthly":0,"yearly":0,"default_billing_cycle":"yearly"},"next_action":"completed"}"#,
        )
        .unwrap();
        assert_eq!(classify_checkout(&response), CheckoutState::Completed);
    }

    #[test]
    fn expired_invoice_is_terminal() {
        let response: CreateDomainResponse = serde_json::from_str(
            r#"{"domain":"alice.smith.dhttp.net","quotes":{"currency":"USD","monthly":9900,"yearly":99000,"default_billing_cycle":"yearly"},"next_action":"payment","invoice":{"number":"INV1","status":"expired","amount":9900,"currency":"USD"}}"#,
        )
        .unwrap();
        assert_eq!(classify_checkout(&response), CheckoutState::Expired);
    }

    #[test]
    fn terminal_qr_uses_the_compact_stable_layout() {
        let qr = render_terminal_qr("https://pay.example.test/checkout/ckt_123").unwrap();
        let rows = qr.lines().count();
        let columns = qr
            .lines()
            .map(str::chars)
            .map(Iterator::count)
            .max()
            .unwrap();

        assert!(rows <= 24, "QR uses {rows} terminal rows");
        assert!(columns <= 64, "QR uses {columns} terminal columns");
    }

    #[test]
    fn payment_block_keeps_instruction_qr_and_link_in_order() {
        let rendered =
            payment_instruction_block("https://pay.example.test/checkout/ckt_123").unwrap();
        let notice = rendered
            .find("[!] Please complete your payment within 15 minutes.")
            .unwrap();
        let instruction = rendered
            .find("Open the link, or scan the QR code below")
            .unwrap();
        let qr = rendered.find('█').unwrap();
        let link = rendered
            .find("Link: https://pay.example.test/checkout/ckt_123")
            .unwrap();

        assert!(
            notice < instruction && instruction < qr && qr < link,
            "{rendered}"
        );
        assert!(!rendered.contains("Open the link below, or scan the QR code above"));
    }

    #[test]
    fn payment_block_indents_every_qr_row_by_four_spaces() {
        let rendered = payment_instruction_block("https://pay.example.test/checkout").unwrap();
        let qr = rendered
            .split_once("Open the link, or scan the QR code below\n\n")
            .unwrap()
            .1
            .split_once("\n\n    Link: https://pay.example.test/checkout")
            .unwrap()
            .0;

        assert!(!qr.is_empty());
        assert!(
            qr.lines().all(|line| line.starts_with("    ")),
            "{rendered}"
        );
    }

    #[test]
    fn payment_block_falls_back_to_the_link_only_when_qr_encoding_is_impossible() {
        let url = format!("https://pay.example.test/{}", "x".repeat(10_000));
        let block = payment_instruction_block_or_link(&url);

        assert!(!block.contains(['▀', '▄', '█']));
        assert!(block.contains("Open the link below\n"));
        assert!(block.contains(&format!("Link: {url}")));
    }

    #[test]
    fn unknown_invoice_state_is_a_terminal_failure() {
        let response: CreateDomainResponse = serde_json::from_str(
            r#"{"domain":"alice.smith.dhttp.net","quotes":{"currency":"USD","monthly":9900,"yearly":99000,"default_billing_cycle":"yearly"},"next_action":"payment","invoice":{"number":"INV1","status":"surprising","amount":9900,"currency":"USD"}}"#,
        )
        .unwrap();

        assert_eq!(classify_checkout(&response), CheckoutState::Failed);
    }

    #[test]
    fn checkout_wait_uses_the_server_deadline_with_a_fifteen_minute_cap() {
        assert_eq!(checkout_wait_duration(999, 1_000), Duration::ZERO);
        assert_eq!(
            checkout_wait_duration(1_030, 1_000),
            Duration::from_secs(30)
        );
        assert_eq!(
            checkout_wait_duration(3_000, 1_000),
            Duration::from_secs(15 * 60)
        );
    }
}
