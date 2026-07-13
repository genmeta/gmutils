use std::io::IsTerminal;

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
        let include_qr = std::io::stderr().is_terminal();
        let block = payment_instruction_block(&payment_entry.url, include_qr)
            .or_else(|_| payment_instruction_block(&payment_entry.url, false))
            .expect("rendering payment instructions without a QR code cannot fail");
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

pub(crate) fn payment_instruction_block(url: &str, include_qr: bool) -> Result<String, QrError> {
    let mut block = String::new();

    if include_qr {
        block.push_str(render_terminal_qr(url)?.trim_end());
        block.push_str("\n\n");
    }

    block.push_str("[!] Please complete your payment within 15 minutes.\n");
    block.push_str("    Open the link below, or scan the QR code above\n\n");
    block.push_str("    Link: ");
    block.push_str(url);
    Ok(block)
}

pub async fn wait_for_checkout_completion(
    cert_server: &crate::cert_server::CertServer,
    checkout_token: &str,
) -> Result<CreateDomainResponse, crate::cert_server::Error> {
    crate::cli::flow::progress::run(crate::cli::flow::progress::WAIT_FOR_PAYMENT, async {
        loop {
            let response = cert_server.get_checkout(checkout_token).await?;
            match classify_checkout(&response) {
                CheckoutState::Completed => return Ok(response),
                CheckoutState::Expired => {
                    return Err(crate::cert_server::Error::without_source(
                        "checkout expired before payment was completed".to_string(),
                    ));
                }
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
                CheckoutState::Pending => {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await
                }
            }
        }
    })
    .await
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
    fn payment_block_omits_only_the_qr_on_a_non_terminal_stream() {
        let block =
            payment_instruction_block("https://pay.example.test/checkout/ckt_123", false).unwrap();

        assert!(!block.contains(['▀', '▄', '█']));
        assert_eq!(
            block,
            "[!] Please complete your payment within 15 minutes.\n    Open the link below, or scan the QR code above\n\n    Link: https://pay.example.test/checkout/ckt_123"
        );
    }

    #[test]
    fn payment_block_places_compact_qr_before_the_link() {
        let rendered =
            payment_instruction_block("https://pay.example.test/checkout", true).unwrap();
        let qr = rendered.find('█').unwrap();
        let notice = rendered
            .find("[!] Please complete your payment within 15 minutes.")
            .unwrap();
        let link = rendered
            .find("Link: https://pay.example.test/checkout")
            .unwrap();

        assert!(qr < notice && notice < link, "{rendered}");
        assert!(rendered.contains("Open the link below, or scan the QR code above"));
        assert!(!rendered.contains("Open link:"));
    }

    #[test]
    fn unknown_invoice_state_is_a_terminal_failure() {
        let response: CreateDomainResponse = serde_json::from_str(
            r#"{"domain":"alice.smith.dhttp.net","quotes":{"currency":"USD","monthly":9900,"yearly":99000,"default_billing_cycle":"yearly"},"next_action":"payment","invoice":{"number":"INV1","status":"surprising","amount":9900,"currency":"USD"}}"#,
        )
        .unwrap();

        assert_eq!(classify_checkout(&response), CheckoutState::Failed);
    }
}
