use crate::cert_server::CreateDomainResponse;

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
    println!("payment required for {}", response.domain);
    println!("currency: {}", response.quotes.currency);
    println!("monthly: {}", response.quotes.monthly);
    println!("yearly: {}", response.quotes.yearly);
    println!(
        "default billing cycle: {}",
        response.quotes.default_billing_cycle
    );
    if let Some(reservation) = &response.reservation {
        println!("reservation: {}", reservation.reservation_no);
        println!("reservation expires at: {}", reservation.expires_at);
    }
    if let Some(payment_entry) = &response.payment_entry {
        println!("payment url: {}", payment_entry.url);
        println!("checkout token: {}", payment_entry.checkout_token);
        println!("checkout expires at: {}", payment_entry.expires_at);
    }
}

pub async fn wait_for_checkout_completion(
    cert_server: &crate::cert_server::CertServer,
    checkout_token: &str,
) -> Result<CreateDomainResponse, crate::cert_server::Error> {
    loop {
        let response = cert_server.get_checkout(checkout_token).await?;
        match classify_checkout(&response) {
            CheckoutState::Completed | CheckoutState::Expired | CheckoutState::Cancelled => {
                return Ok(response);
            }
            CheckoutState::Pending => tokio::time::sleep(std::time::Duration::from_secs(3)).await,
        }
    }
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
}
