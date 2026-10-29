use std::path::Path;

use snafu::{FromString, Snafu};

use super::target::IdentityTarget;
use crate::{
    cert_server::{
        CertServer, CreateDomainResponse, CreateSubdomainResponse, DomainAvailabilityResponse,
        DomainQuotes,
    },
    cli::{
        Error,
        prompt::{self, InquireResultExt},
    },
};

fn is_domain_not_found(error: &crate::cert_server::Error) -> bool {
    error.is_api(reqwest::StatusCode::NOT_FOUND, "domain_not_found")
}

fn is_domain_conflict(error: &crate::cert_server::Error) -> bool {
    error.is_api(reqwest::StatusCode::CONFLICT, "domain_conflict")
}

fn is_subdomain_conflict(error: &crate::cert_server::Error) -> bool {
    error.is_api(reqwest::StatusCode::CONFLICT, "subdomain_conflict") || is_domain_conflict(error)
}

fn missing_parent_identity_message(target: &IdentityTarget, parent: &str) -> String {
    format!(
        "Cannot register {} because its parent identity, {parent}, does not exist.",
        target.short_name()
    )
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RegistrationProof<'a> {
    AccessToken(&'a str),
    ParentIdentityProfile(&'a Path),
}

pub(crate) trait RegistrationApi {
    async fn pricing(
        &self,
        token: &str,
        target: &IdentityTarget,
    ) -> Result<DomainAvailabilityResponse, RegistrationError>;

    async fn create_root(
        &self,
        token: &str,
        target: &IdentityTarget,
    ) -> Result<CreateDomainResponse, RegistrationError>;

    async fn create_child(
        &self,
        proof: RegistrationProof<'_>,
        target: &IdentityTarget,
    ) -> Result<CreateSubdomainResponse, RegistrationError>;

    async fn checkout(
        &self,
        token: &str,
        expires_at: i64,
    ) -> Result<CreateDomainResponse, RegistrationError>;

    async fn cancel_reservation(
        &self,
        token: &str,
        reservation_no: &str,
    ) -> Result<(), RegistrationError>;
}

pub(crate) trait RegistrationUi {
    async fn confirm_paid_root(&self, message: &str) -> Result<bool, RegistrationError>;
    fn print_payment(&self, url: &str) -> Result<(), RegistrationError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistrationOutcome {
    Existing,
    CreatedFree,
    CreatedPaid,
}

#[derive(Debug, Snafu)]
pub(crate) enum RegistrationError {
    #[snafu(transparent)]
    CertServer { source: crate::cert_server::Error },

    #[snafu(transparent)]
    Prompt { source: prompt::Error },

    #[snafu(display("identity registration was declined"))]
    Declined,

    #[snafu(display(
        "creating this identity requires interactive payment confirmation; rerun this command in an interactive terminal"
    ))]
    PaymentRequiresInteractive,

    #[snafu(display("cert server did not return monthly and yearly pricing for {target}"))]
    MissingPricing { target: String },

    #[snafu(display("{target} is not available to register"))]
    TargetUnavailable { target: String },

    #[snafu(display("cert server requested payment without returning a paid price"))]
    MissingCheckoutPricing,

    #[snafu(display("cert server requested payment without returning a checkout reservation"))]
    MissingCheckoutReservation,

    #[snafu(display("checkout did not complete successfully"))]
    CheckoutNotCompleted,

    #[snafu(display("cert server unexpectedly returned a child quota checkout"))]
    ChildQuotaCheckout,

    #[snafu(display("{message}"))]
    MissingParent { message: String },
}

impl From<RegistrationError> for Error {
    fn from(error: RegistrationError) -> Self {
        match error {
            RegistrationError::CertServer { source } => Self::from(source),
            RegistrationError::Prompt { source } => Self::from(source),
            other => Self::without_source(other.to_string()),
        }
    }
}

pub(crate) struct CertServerRegistrationApi<'a> {
    cert_server: &'a CertServer,
}

impl<'a> CertServerRegistrationApi<'a> {
    pub(crate) fn new(cert_server: &'a CertServer) -> Self {
        Self { cert_server }
    }
}

impl RegistrationApi for CertServerRegistrationApi<'_> {
    async fn pricing(
        &self,
        token: &str,
        target: &IdentityTarget,
    ) -> Result<DomainAvailabilityResponse, RegistrationError> {
        Ok(self
            .cert_server
            .inspect_domain_availability_with_token(token, target.full_name())
            .await?)
    }

    async fn create_root(
        &self,
        token: &str,
        target: &IdentityTarget,
    ) -> Result<CreateDomainResponse, RegistrationError> {
        Ok(self
            .cert_server
            .create_domain_with_token(token, target.full_name())
            .await?)
    }

    async fn create_child(
        &self,
        proof: RegistrationProof<'_>,
        target: &IdentityTarget,
    ) -> Result<CreateSubdomainResponse, RegistrationError> {
        let parent = target
            .parent()
            .ok_or_else(|| RegistrationError::MissingParent {
                message: "sub-identity target is missing its direct parent".to_string(),
            })?;
        let label =
            target
                .sub_identity_label()
                .ok_or_else(|| RegistrationError::MissingParent {
                    message: "sub-identity target is missing its direct child label".to_string(),
                })?;

        let response = match proof {
            RegistrationProof::AccessToken(token) => {
                self.cert_server
                    .create_subdomain(token, parent.as_full(), label, None)
                    .await?
            }
            RegistrationProof::ParentIdentityProfile(profile_dir) => {
                self.cert_server
                    .create_subdomain_with_identity_profile(
                        profile_dir,
                        parent.as_full(),
                        label,
                        None,
                    )
                    .await?
            }
        };
        Ok(response)
    }

    async fn checkout(
        &self,
        token: &str,
        expires_at: i64,
    ) -> Result<CreateDomainResponse, RegistrationError> {
        Ok(
            crate::checkout::wait_for_checkout_completion_until(
                self.cert_server,
                token,
                expires_at,
            )
            .await?,
        )
    }

    async fn cancel_reservation(
        &self,
        token: &str,
        reservation_no: &str,
    ) -> Result<(), RegistrationError> {
        Ok(self
            .cert_server
            .cancel_reservation(token, reservation_no)
            .await?)
    }
}

pub(crate) struct InquireRegistrationUi;

impl RegistrationUi for InquireRegistrationUi {
    async fn confirm_paid_root(&self, message: &str) -> Result<bool, RegistrationError> {
        let message = message.to_string();
        let answer =
            prompt::sync(move || inquire::Confirm::new(&message).with_default(true).prompt())
                .await
                .require_interactive("an interactive terminal to confirm payment")?;
        Ok(answer)
    }

    fn print_payment(&self, url: &str) -> Result<(), RegistrationError> {
        let block = crate::checkout::payment_instruction_block_or_link(url);
        crate::cli::flow::transcript::print_err_block(&block);
        Ok(())
    }
}

pub(crate) struct NoRegistrationUi;

impl RegistrationUi for NoRegistrationUi {
    async fn confirm_paid_root(&self, _message: &str) -> Result<bool, RegistrationError> {
        Err(RegistrationError::PaymentRequiresInteractive)
    }

    fn print_payment(&self, _url: &str) -> Result<(), RegistrationError> {
        Err(RegistrationError::PaymentRequiresInteractive)
    }
}

fn format_price(currency: &str, amount: i64) -> String {
    format!(
        "{currency} {}.{:02}",
        amount.div_euclid(100),
        amount.rem_euclid(100)
    )
}

fn paid_root_confirmation_message(
    target: &IdentityTarget,
    quotes: &DomainQuotes,
    free_quota_used: bool,
) -> String {
    let mut price = format!(
        "{}: {}/month or {}/year",
        target.short_name(),
        format_price(&quotes.currency, quotes.monthly),
        format_price(&quotes.currency, quotes.yearly)
    );
    if let Some(percent_off) = quotes.promotion_percent_off() {
        price.push_str(&format!(" ({percent_off}% off)"));
    }
    if free_quota_used {
        format!("Free quota used. {price}. Continue?")
    } else {
        format!("{price}. Continue to checkout?")
    }
}

async fn cancel_created_reservation(
    api: &impl RegistrationApi,
    token: &str,
    created: &CreateDomainResponse,
) -> Result<(), RegistrationError> {
    let reservation = created
        .reservation
        .as_ref()
        .ok_or(RegistrationError::MissingCheckoutReservation)?;
    api.cancel_reservation(token, &reservation.reservation_no)
        .await
}

pub(crate) async fn register_missing_root(
    api: &impl RegistrationApi,
    ui: &impl RegistrationUi,
    target: &IdentityTarget,
    token: &str,
    interactive: bool,
) -> Result<RegistrationOutcome, RegistrationError> {
    let pricing = api.pricing(token, target).await?;
    match pricing.availability.as_str() {
        "conflict" => return Ok(RegistrationOutcome::Existing),
        "available" => {}
        _ => {
            return Err(RegistrationError::TargetUnavailable {
                target: target.short_name().to_string(),
            });
        }
    }

    if pricing.monthly_amount().is_none() || pricing.yearly_amount().is_none() {
        return Err(RegistrationError::MissingPricing {
            target: target.short_name().to_string(),
        });
    }

    let quoted_free = pricing.is_free();
    if !quoted_free && !interactive {
        return Err(RegistrationError::PaymentRequiresInteractive);
    }

    let created = match api.create_root(token, target).await {
        Ok(created) => created,
        Err(RegistrationError::CertServer { source }) if is_domain_conflict(&source) => {
            return Ok(RegistrationOutcome::Existing);
        }
        Err(error) => return Err(error),
    };

    let Some(payment_entry) = created.payment_entry.as_ref() else {
        return Ok(RegistrationOutcome::CreatedFree);
    };

    if created.quotes.monthly == 0 && created.quotes.yearly == 0 {
        cancel_created_reservation(api, token, &created).await?;
        return Err(RegistrationError::MissingCheckoutPricing);
    }
    if !interactive {
        cancel_created_reservation(api, token, &created).await?;
        return Err(RegistrationError::PaymentRequiresInteractive);
    }
    let message = paid_root_confirmation_message(target, &created.quotes, quoted_free);
    let confirmed = match ui.confirm_paid_root(&message).await {
        Ok(confirmed) => confirmed,
        Err(error) => {
            cancel_created_reservation(api, token, &created).await?;
            return Err(error);
        }
    };
    if !confirmed {
        cancel_created_reservation(api, token, &created).await?;
        return Err(RegistrationError::Declined);
    }

    if let Err(error) = ui.print_payment(&payment_entry.url) {
        cancel_created_reservation(api, token, &created).await?;
        return Err(error);
    }
    let completed = api
        .checkout(&payment_entry.checkout_token, payment_entry.expires_at)
        .await?;
    if crate::checkout::classify_checkout(&completed) != crate::checkout::CheckoutState::Completed {
        return Err(RegistrationError::CheckoutNotCompleted);
    }

    Ok(RegistrationOutcome::CreatedPaid)
}

pub(crate) async fn register_missing_child(
    api: &impl RegistrationApi,
    target: &IdentityTarget,
    proof: RegistrationProof<'_>,
) -> Result<RegistrationOutcome, RegistrationError> {
    let parent = target
        .parent()
        .ok_or_else(|| RegistrationError::MissingParent {
            message: "sub-identity target is missing its direct parent".to_string(),
        })?;

    let created = match api.create_child(proof, target).await {
        Ok(created) => created,
        Err(RegistrationError::CertServer { source }) if is_subdomain_conflict(&source) => {
            return Ok(RegistrationOutcome::Existing);
        }
        Err(RegistrationError::CertServer { source }) if is_domain_not_found(&source) => {
            return Err(RegistrationError::MissingParent {
                message: missing_parent_identity_message(target, parent.as_partial()),
            });
        }
        Err(error) => return Err(error),
    };

    if created.invoice.is_some() {
        return Err(RegistrationError::ChildQuotaCheckout);
    }

    Ok(RegistrationOutcome::CreatedFree)
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/registration.rs"]
mod tests;
