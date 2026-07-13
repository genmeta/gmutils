use std::io::IsTerminal;

use snafu::{FromString, OptionExt, whatever};

use super::target::IdentityTarget;
use crate::{
    cert_server::{
        CertServer, CreateDomainResponse, CreateSubdomainAttempt, CreateSubdomainResponse,
        InvoiceDetail, SubdomainQuotaQuote,
    },
    cli::{
        Error,
        prompt::{self, InquireResultExt},
    },
};

fn is_domain_not_found(error: &crate::cert_server::Error) -> bool {
    error.is_api_code("domain_not_found")
}

fn is_domain_conflict(error: &crate::cert_server::Error) -> bool {
    error.is_api_code("domain_conflict")
}

pub(crate) fn is_subdomain_quota_exceeded(error: &crate::cert_server::Error) -> bool {
    error.is_api_code("subdomain_quota_exceeded")
}

pub(crate) fn create_identity_progress_message() -> &'static str {
    "Creating identity..."
}

fn missing_parent_identity_message(target: &IdentityTarget, parent: &str) -> String {
    format!(
        "Cannot register {} because its parent identity, {parent}, does not exist.",
        target.short_name()
    )
}
pub(crate) fn ensure_non_interactive_root_checkout_not_required(
    target: &IdentityTarget,
    response: &CreateDomainResponse,
) -> Result<(), Error> {
    match crate::checkout::classify_checkout(response) {
        crate::checkout::CheckoutState::Completed => Ok(()),
        crate::checkout::CheckoutState::Pending
        | crate::checkout::CheckoutState::Expired
        | crate::checkout::CheckoutState::Cancelled => whatever!(
            "creating {} requires interactive checkout; rerun this command in an interactive terminal to complete payment",
            target.short_name()
        ),
    }
}

pub(crate) fn ensure_non_interactive_sub_identity_checkout_not_required(
    target: &IdentityTarget,
    response: &CreateSubdomainResponse,
) -> Result<(), Error> {
    if response.invoice.is_some() {
        whatever!(
            "creating {} exceeded the sub-identity quota and requires interactive checkout; rerun this command in an interactive terminal to expand the parent identity quota",
            target.short_name()
        );
    }
    Ok(())
}

pub(crate) async fn prompt_restart_checkout(message: &str) -> Result<bool, Error> {
    let message = message.to_string();
    Ok(
        prompt::sync(move || inquire::Confirm::new(&message).with_default(true).prompt())
            .await
            .require_interactive("interactive input")?,
    )
}
pub(crate) fn print_root_checkout_instructions(
    target: &IdentityTarget,
    response: &CreateDomainResponse,
) {
    if let Some(block) =
        root_checkout_instruction_block(target, response, std::io::stderr().is_terminal())
    {
        crate::cli::flow::transcript::print_err_block(&block);
    }
}

fn root_checkout_summary(target: &IdentityTarget) -> String {
    format!("Payment is required to create {}.", target.short_name())
}

fn root_checkout_instruction_block(
    target: &IdentityTarget,
    response: &CreateDomainResponse,
    include_qr: bool,
) -> Option<String> {
    response.payment_entry.as_ref().map(|payment_entry| {
        crate::checkout::checkout_instruction_block(
            &root_checkout_summary(target),
            &payment_entry.url,
            include_qr,
        )
    })
}

fn print_subdomain_checkout_instructions(
    target: &IdentityTarget,
    invoice: &InvoiceDetail,
    quote: &SubdomainQuotaQuote,
) {
    crate::cli::flow::transcript::print_err_block(&subdomain_checkout_instruction_block(
        target,
        invoice,
        quote,
        std::io::stderr().is_terminal(),
    ));
}

fn subdomain_checkout_summary(target: &IdentityTarget, quote: &SubdomainQuotaQuote) -> String {
    format!(
        "Creating {} exceeded the sub-identity quota.\n\nAmount due now to expand and continue: {} {}",
        target.short_name(),
        quote.currency,
        format_minor_amount(quote.due),
    )
}

fn subdomain_checkout_instruction_block(
    target: &IdentityTarget,
    invoice: &InvoiceDetail,
    quote: &SubdomainQuotaQuote,
    include_qr: bool,
) -> String {
    crate::checkout::checkout_instruction_block(
        &subdomain_checkout_summary(target, quote),
        &invoice.url,
        include_qr,
    )
}

fn format_minor_amount(amount: i64) -> String {
    let major = amount / 100;
    let cents = amount.abs() % 100;
    format!("{major}.{cents:02}")
}
async fn wait_for_invoice_terminal(
    cert_server: &CertServer,
    access_token: &str,
    invoice_no: &str,
) -> Result<InvoiceDetail, Error> {
    super::progress::run_with_spinner("Waiting for payment confirmation...", async {
        loop {
            let invoice = cert_server.get_invoice(access_token, invoice_no).await?;
            match invoice.status.as_str() {
                "paid" | "expired" | "cancelled" | "canceled" => return Ok(invoice),
                _ => tokio::time::sleep(std::time::Duration::from_secs(3)).await,
            }
        }
    })
    .await
}

pub(crate) async fn ensure_identity_exists_with_token(
    cert_server: &CertServer,
    target: &IdentityTarget,
    access_token: &str,
    progress_message: &str,
) -> Result<(), Error> {
    let created = match super::progress::run_with_spinner(
        progress_message,
        cert_server.create_domain_with_token(access_token, target.full_name()),
    )
    .await
    {
        Ok(created) => created,
        Err(error) if is_domain_conflict(&error) => return Ok(()),
        Err(error) => return Err(Error::from(error)),
    };

    ensure_non_interactive_root_checkout_not_required(target, &created)?;
    Ok(())
}

pub(crate) async fn ensure_identity_exists_with_token_interactively(
    cert_server: &CertServer,
    target: &IdentityTarget,
    access_token: &str,
    progress_message: &str,
) -> Result<(), Error> {
    loop {
        let created = match super::progress::run_with_spinner(
            progress_message,
            cert_server.create_domain_with_token(access_token, target.full_name()),
        )
        .await
        {
            Ok(created) => created,
            Err(error) if is_domain_conflict(&error) => return Ok(()),
            Err(error) => return Err(Error::from(error)),
        };

        if created.payment_entry.is_none() {
            return Ok(());
        }

        print_root_checkout_instructions(target, &created);
        let completed = crate::checkout::wait_for_checkout_completion(
            cert_server,
            &created
                .payment_entry
                .as_ref()
                .expect("payment entry just checked")
                .checkout_token,
        )
        .await?;

        match crate::checkout::classify_checkout(&completed) {
            crate::checkout::CheckoutState::Completed => return Ok(()),
            crate::checkout::CheckoutState::Expired => {
                if !prompt_restart_checkout(
                    "This checkout expired. Start a new checkout for this identity?",
                )
                .await?
                {
                    whatever!("checkout was not completed");
                }
            }
            crate::checkout::CheckoutState::Cancelled => {
                if !prompt_restart_checkout(
                    "This checkout was cancelled. Start a new checkout for this identity?",
                )
                .await?
                {
                    whatever!("checkout was not completed");
                }
            }
            crate::checkout::CheckoutState::Pending => {
                whatever!("checkout did not reach a terminal state");
            }
        }
    }
}

pub(crate) async fn create_sub_identity_with_token(
    cert_server: &CertServer,
    target: &IdentityTarget,
    access_token: &str,
    parent: &dhttp::name::DhttpName<'_>,
    label: &str,
) -> Result<CreateSubdomainResponse, Error> {
    match super::progress::run_with_spinner(
        create_identity_progress_message(),
        cert_server.create_subdomain(access_token, parent.as_full(), label, None),
    )
    .await
    {
        Ok(created) => Ok(created),
        Err(error) if is_domain_not_found(&error) => Err(Error::with_source(
            Box::new(error),
            missing_parent_identity_message(target, parent.as_partial()),
        )),
        Err(error) => Err(Error::from(error)),
    }
}

pub(crate) async fn create_sub_identity_with_token_interactively(
    cert_server: &CertServer,
    target: &IdentityTarget,
    access_token: &str,
    parent: &dhttp::name::DhttpName<'_>,
    label: &str,
) -> Result<CreateSubdomainResponse, Error> {
    loop {
        match super::progress::run_with_spinner(
            create_identity_progress_message(),
            cert_server.create_subdomain_attempt(access_token, parent.as_full(), label, None),
        )
        .await
        {
            Ok(CreateSubdomainAttempt::Created(response)) => return Ok(response),
            Ok(CreateSubdomainAttempt::QuotaExceeded(quote)) => {
                let continue_checkout = prompt_restart_checkout(&format!(
                    "Creating {} exceeded the sub-identity quota under {}. Expand quota and continue?",
                    target.short_name(),
                    parent.as_partial()
                ))
                .await?;
                if !continue_checkout {
                    whatever!("checkout was not completed");
                }

                loop {
                    let invoice_response = match super::progress::run_with_spinner(
                        create_identity_progress_message(),
                        cert_server.create_subdomain_attempt(
                            access_token,
                            parent.as_full(),
                            label,
                            Some(quote.due),
                        ),
                    )
                    .await?
                    {
                        CreateSubdomainAttempt::Created(response) => response,
                        CreateSubdomainAttempt::QuotaExceeded(_) => {
                            whatever!("subdomain quota expansion quote changed during checkout")
                        }
                    };
                    let invoice_no = invoice_response
                        .invoice
                        .as_ref()
                        .map(|invoice| invoice.number.as_str())
                        .whatever_context::<_, Error>(
                            "quota expansion checkout did not return an invoice number",
                        )?;
                    let invoice = super::progress::run_with_spinner(
                        "Loading payment details...",
                        cert_server.get_invoice(access_token, invoice_no),
                    )
                    .await?;
                    print_subdomain_checkout_instructions(target, &invoice, &quote);
                    let invoice =
                        wait_for_invoice_terminal(cert_server, access_token, invoice_no).await?;
                    match invoice.status.as_str() {
                        "paid" => break,
                        "expired" => {
                            if !prompt_restart_checkout(
                                "This checkout expired. Start a new checkout for this sub-identity slot?",
                            )
                            .await?
                            {
                                whatever!("checkout was not completed");
                            }
                        }
                        "cancelled" | "canceled" => {
                            if !prompt_restart_checkout(
                                "This checkout was cancelled. Start a new checkout for this sub-identity slot?",
                            )
                            .await?
                            {
                                whatever!("checkout was not completed");
                            }
                        }
                        _ => whatever!("invoice did not reach a terminal state"),
                    }
                }
            }
            Err(error) if is_domain_not_found(&error) => {
                return Err(Error::with_source(
                    Box::new(error),
                    missing_parent_identity_message(target, parent.as_partial()),
                ));
            }
            Err(error) => return Err(Error::from(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IdentityTarget, create_identity_progress_message, missing_parent_identity_message,
    };

    #[test]
    fn root_and_sub_identity_creation_share_the_approved_progress_copy() {
        assert_eq!(create_identity_progress_message(), "Creating identity...");
    }

    #[test]
    fn missing_parent_does_not_offer_to_create_a_root_identity() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        let parent = target.parent().unwrap();

        assert_eq!(
            missing_parent_identity_message(&target, parent.as_partial()),
            "Cannot register phone.alice.smith because its parent identity, alice.smith, does not exist."
        );
    }
}
