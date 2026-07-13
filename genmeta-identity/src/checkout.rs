use std::io::IsTerminal;

use qrcode::{QrCode, types::QrError};

use crate::{cert_server::CreateDomainResponse, cli::flow::transcript};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutState {
    Pending,
    Completed,
    Expired,
    Cancelled,
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
            _ => CheckoutState::Pending,
        };
    }

    if let Some(reservation) = &response.reservation {
        return match reservation.status.as_str() {
            "expired" => CheckoutState::Expired,
            "cancelled" | "canceled" => CheckoutState::Cancelled,
            _ => CheckoutState::Pending,
        };
    }

    CheckoutState::Pending
}

pub fn print_payment_instructions(response: &CreateDomainResponse) {
    transcript::print_err_block(&payment_instruction_block(
        response,
        std::io::stderr().is_terminal(),
    ));
}

fn payment_instruction_block(response: &CreateDomainResponse, include_qr: bool) -> String {
    let mut lines = vec![
        format!("payment required for {}", response.domain),
        format!("currency: {}", response.quotes.currency),
        format!("monthly: {}", response.quotes.monthly),
        format!("yearly: {}", response.quotes.yearly),
        format!(
            "default billing cycle: {}",
            response.quotes.default_billing_cycle
        ),
    ];
    if let Some(reservation) = &response.reservation {
        lines.push(format!("reservation: {}", reservation.reservation_no));
        lines.push(format!(
            "reservation expires at: {}",
            reservation.expires_at
        ));
    }
    if let Some(payment_entry) = &response.payment_entry {
        lines.push(format!("checkout expires at: {}", payment_entry.expires_at));
        return checkout_instruction_block(&lines.join("\n"), &payment_entry.url, include_qr);
    }
    lines.join("\n")
}

fn render_terminal_qr(url: &str) -> Result<String, QrError> {
    let code = QrCode::new(url.as_bytes())?;
    Ok(code
        .render()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .dark_color("\u{1b}[40m  \u{1b}[0m")
        .light_color("\u{1b}[47m  \u{1b}[0m")
        .build())
}

pub(crate) fn checkout_instruction_block(summary: &str, url: &str, include_qr: bool) -> String {
    let mut block = summary.to_string();

    if include_qr && let Ok(qr) = render_terminal_qr(url) {
        block.push_str("\n\nScan this QR code to pay:\n");
        block.push_str(&qr);
    }

    block.push_str("\n\nOpen link: ");
    block.push_str(url);
    block
}

pub async fn wait_for_checkout_completion(
    cert_server: &crate::cert_server::CertServer,
    checkout_token: &str,
) -> Result<CreateDomainResponse, crate::cert_server::Error> {
    crate::cli::flow::progress::run_with_spinner("Waiting for payment confirmation...", async {
        loop {
            let response = cert_server.get_checkout(checkout_token).await?;
            match classify_checkout(&response) {
                CheckoutState::Completed | CheckoutState::Expired | CheckoutState::Cancelled => {
                    return Ok(response);
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
    fn checkout_block_includes_terminal_qr_when_stderr_is_terminal() {
        let block = checkout_instruction_block(
            "Payment is required to create alice.smith.",
            "https://pay.example.test/checkout/ckt_123",
            true,
        );

        assert!(block.contains("Payment is required to create alice.smith."));
        assert!(block.contains("Scan this QR code to pay:"));
        assert!(block.contains("\u{1b}[47m"), "{block:?}");
        assert!(block.contains("Open link: https://pay.example.test/checkout/ckt_123"));
    }

    #[test]
    fn checkout_block_omits_terminal_qr_when_stderr_is_not_terminal() {
        let block = checkout_instruction_block(
            "Payment is required to create alice.smith.",
            "https://pay.example.test/checkout/ckt_123",
            false,
        );

        assert!(block.contains("Payment is required to create alice.smith."));
        assert!(!block.contains("Scan this QR code to pay:"));
        assert!(!block.contains("\u{1b}[47m"));
        assert_eq!(
            block,
            "Payment is required to create alice.smith.\n\nOpen link: https://pay.example.test/checkout/ckt_123"
        );
    }

    #[test]
    fn payment_instruction_block_adds_qr_to_payment_entry() {
        let response: CreateDomainResponse = serde_json::from_str(
            r#"{"domain":"alice.smith.dhttp.net","quotes":{"currency":"USD","monthly":9900,"yearly":99000,"default_billing_cycle":"yearly"},"next_action":"payment","payment_entry":{"url":"https://pay.example.com","checkout_token":"tok_123","expires_at":123456}}"#,
        )
        .unwrap();

        let block = payment_instruction_block(&response, true);

        assert!(block.contains("payment required for alice.smith.dhttp.net"));
        assert!(block.contains("currency: USD"));
        assert!(block.contains("Scan this QR code to pay:"));
        assert!(block.contains("Open link: https://pay.example.com"));
        assert!(!block.contains("tok_123"));
    }
}
