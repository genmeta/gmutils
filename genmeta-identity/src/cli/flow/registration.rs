use std::io::IsTerminal;

use snafu::{FromString, Snafu, whatever};

use super::target::IdentityTarget;
use crate::{
    cert_server::{
        CertServer, CreateDomainResponse, CreateSubdomainResponse, DomainAvailabilityResponse,
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

fn is_subdomain_conflict(error: &crate::cert_server::Error) -> bool {
    error.is_api_code("subdomain_conflict") || is_domain_conflict(error)
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

#[derive(Debug, Clone, Copy)]
pub(crate) enum RegistrationProof<'a> {
    AccessToken(&'a str),
    ParentIdentity(&'a str),
}

pub(crate) trait RegistrationApi {
    async fn pricing(
        &self,
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

    async fn checkout(&self, token: &str) -> Result<CreateDomainResponse, RegistrationError>;
}

pub(crate) trait RegistrationUi {
    async fn confirm_paid_root(&self) -> Result<bool, RegistrationError>;
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

    #[snafu(display("failed to render the payment QR code"))]
    PaymentQr { source: qrcode::types::QrError },

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

    #[snafu(display("cert server unexpectedly returned a checkout for a free identity"))]
    UnexpectedFreeCheckout,

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
        target: &IdentityTarget,
    ) -> Result<DomainAvailabilityResponse, RegistrationError> {
        Ok(self
            .cert_server
            .inspect_domain_availability(target.full_name())
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
            RegistrationProof::ParentIdentity(identity) => {
                self.cert_server
                    .create_subdomain_with_identity(identity, parent.as_full(), label, None)
                    .await?
            }
        };
        Ok(response)
    }

    async fn checkout(&self, token: &str) -> Result<CreateDomainResponse, RegistrationError> {
        Ok(crate::checkout::wait_for_checkout_completion(self.cert_server, token).await?)
    }
}

pub(crate) struct InquireRegistrationUi;

impl RegistrationUi for InquireRegistrationUi {
    async fn confirm_paid_root(&self) -> Result<bool, RegistrationError> {
        let answer = prompt::sync(|| {
            inquire::Confirm::new(
                "This new name is nice, it costs $5/mon or $30/yr, would you like to subscribe to own it exclusively?",
            )
            .with_default(true)
            .prompt()
        })
        .await
        .require_interactive("an interactive terminal to confirm payment")?;
        Ok(answer)
    }

    fn print_payment(&self, url: &str) -> Result<(), RegistrationError> {
        let include_qr = std::io::stderr().is_terminal();
        let block = crate::checkout::payment_instruction_block(url, include_qr)
            .map_err(|source| RegistrationError::PaymentQr { source })?;
        crate::cli::flow::transcript::print_err_block(&block);
        Ok(())
    }
}

pub(crate) struct NoRegistrationUi;

impl RegistrationUi for NoRegistrationUi {
    async fn confirm_paid_root(&self) -> Result<bool, RegistrationError> {
        Err(RegistrationError::PaymentRequiresInteractive)
    }

    fn print_payment(&self, _url: &str) -> Result<(), RegistrationError> {
        Err(RegistrationError::PaymentRequiresInteractive)
    }
}

pub(crate) async fn register_missing_root(
    api: &impl RegistrationApi,
    ui: &impl RegistrationUi,
    target: &IdentityTarget,
    token: &str,
    interactive: bool,
) -> Result<RegistrationOutcome, RegistrationError> {
    let pricing = api.pricing(target).await?;
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

    let paid = !pricing.is_free();
    if paid {
        if !interactive {
            return Err(RegistrationError::PaymentRequiresInteractive);
        }
        if !ui.confirm_paid_root().await? {
            return Err(RegistrationError::Declined);
        }
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

    if !paid {
        return Err(RegistrationError::UnexpectedFreeCheckout);
    }

    ui.print_payment(&payment_entry.url)?;
    let completed = api.checkout(&payment_entry.checkout_token).await?;
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

pub(crate) fn ensure_non_interactive_root_checkout_not_required(
    target: &IdentityTarget,
    response: &CreateDomainResponse,
) -> Result<(), Error> {
    match crate::checkout::classify_checkout(response) {
        crate::checkout::CheckoutState::Completed => Ok(()),
        crate::checkout::CheckoutState::Pending
        | crate::checkout::CheckoutState::Expired
        | crate::checkout::CheckoutState::Cancelled
        | crate::checkout::CheckoutState::Failed => whatever!(
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

pub(crate) async fn ensure_identity_exists_with_token(
    cert_server: &CertServer,
    target: &IdentityTarget,
    access_token: &str,
    _progress_message: &str,
) -> Result<(), Error> {
    let api = CertServerRegistrationApi::new(cert_server);
    register_missing_root(&api, &NoRegistrationUi, target, access_token, false)
        .await
        .map(|_| ())
        .map_err(Error::from)
}

pub(crate) async fn ensure_identity_exists_with_token_interactively(
    cert_server: &CertServer,
    target: &IdentityTarget,
    access_token: &str,
    _progress_message: &str,
) -> Result<(), Error> {
    let api = CertServerRegistrationApi::new(cert_server);
    register_missing_root(&api, &InquireRegistrationUi, target, access_token, true)
        .await
        .map(|_| ())
        .map_err(Error::from)
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
    // Child quota failures are terminal. They belong to a separate quota flow and
    // must never enter the root-name payment transcript.
    create_sub_identity_with_token(cert_server, target, access_token, parent, label).await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct FakeRegistrationApi {
        pricing: DomainAvailabilityResponse,
        created: CreateDomainResponse,
        calls: Mutex<Vec<&'static str>>,
    }

    impl FakeRegistrationApi {
        fn free() -> Self {
            Self::new(0, 0, None)
        }

        fn paid() -> Self {
            Self::new(500, 3000, Some("https://pay.example.test/checkout"))
        }

        fn new(monthly: i64, yearly: i64, payment_url: Option<&str>) -> Self {
            let pricing = serde_json::from_value(serde_json::json!({
                "domain": "alice.smith.dhttp.net",
                "availability": "available",
                "currency": "USD",
                "prices": [
                    {"interval": "monthly", "amount": monthly},
                    {"interval": "yearly", "amount": yearly, "discount": 0.5}
                ]
            }))
            .unwrap();
            let mut created = serde_json::json!({
                "domain": "alice.smith.dhttp.net",
                "quotes": {
                    "currency": "USD",
                    "monthly": monthly,
                    "yearly": yearly,
                    "default_billing_cycle": "yearly"
                },
                "next_action": if payment_url.is_some() { "payment" } else { "completed" }
            });
            if let Some(url) = payment_url {
                created["payment_entry"] = serde_json::json!({
                    "url": url,
                    "checkout_token": "ckt_test",
                    "expires_at": 1_900_000_000_i64
                });
            }
            Self {
                pricing,
                created: serde_json::from_value(created).unwrap(),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl RegistrationApi for FakeRegistrationApi {
        async fn pricing(
            &self,
            _target: &IdentityTarget,
        ) -> Result<DomainAvailabilityResponse, RegistrationError> {
            self.calls.lock().unwrap().push("pricing");
            Ok(self.pricing.clone())
        }

        async fn create_root(
            &self,
            _token: &str,
            _target: &IdentityTarget,
        ) -> Result<CreateDomainResponse, RegistrationError> {
            self.calls.lock().unwrap().push("register-root");
            Ok(self.created.clone())
        }

        async fn create_child(
            &self,
            proof: RegistrationProof<'_>,
            target: &IdentityTarget,
        ) -> Result<CreateSubdomainResponse, RegistrationError> {
            self.calls.lock().unwrap().push(match proof {
                RegistrationProof::AccessToken(_) => "register-child:token",
                RegistrationProof::ParentIdentity(_) => "register-child:parent",
            });
            Ok(serde_json::from_value(serde_json::json!({
                "domain": target.full_name(),
                "parent": target.parent().unwrap().as_full(),
                "status": "active",
                "cert": {"limit": 5, "used": 1},
                "url": "https://license.genmeta.net/v2/subdomain",
                "certs_url": "https://license.genmeta.net/v2/cert",
                "created_at": 1_800_000_000_i64
            }))
            .unwrap())
        }

        async fn checkout(&self, _token: &str) -> Result<CreateDomainResponse, RegistrationError> {
            self.calls.lock().unwrap().push("checkout");
            let mut completed = self.created.clone();
            completed.next_action = "completed".to_string();
            Ok(completed)
        }
    }

    struct NoUi;

    impl RegistrationUi for NoUi {
        async fn confirm_paid_root(&self) -> Result<bool, RegistrationError> {
            Err(RegistrationError::PaymentRequiresInteractive)
        }

        fn print_payment(&self, _url: &str) -> Result<(), RegistrationError> {
            panic!("payment output must not be printed")
        }
    }

    struct DecliningUi;

    impl RegistrationUi for DecliningUi {
        async fn confirm_paid_root(&self) -> Result<bool, RegistrationError> {
            Ok(false)
        }

        fn print_payment(&self, _url: &str) -> Result<(), RegistrationError> {
            panic!("declined registration must not print payment output")
        }
    }

    #[derive(Default)]
    struct AcceptingUi {
        printed: Mutex<Vec<String>>,
    }

    impl RegistrationUi for AcceptingUi {
        async fn confirm_paid_root(&self) -> Result<bool, RegistrationError> {
            Ok(true)
        }

        fn print_payment(&self, url: &str) -> Result<(), RegistrationError> {
            self.printed.lock().unwrap().push(url.to_string());
            Ok(())
        }
    }

    fn target() -> IdentityTarget {
        IdentityTarget::parse("alice.smith").unwrap()
    }

    #[tokio::test]
    async fn free_registration_returns_created_free_without_checkout() {
        let api = FakeRegistrationApi::free();
        let outcome = register_missing_root(&api, &NoUi, &target(), "token", false)
            .await
            .unwrap();

        assert_eq!(outcome, RegistrationOutcome::CreatedFree);
        assert_eq!(api.calls(), ["pricing", "register-root"]);
    }

    #[tokio::test]
    async fn paid_registration_requires_confirmation_before_create_request() {
        let api = FakeRegistrationApi::paid();
        let result = register_missing_root(&api, &DecliningUi, &target(), "token", true).await;

        assert!(matches!(result, Err(RegistrationError::Declined)));
        assert_eq!(api.calls(), ["pricing"]);
    }

    #[tokio::test]
    async fn noninteractive_paid_registration_stops_before_create_or_checkout() {
        let api = FakeRegistrationApi::paid();
        let result = register_missing_root(&api, &NoUi, &target(), "token", false).await;

        assert!(matches!(
            result,
            Err(RegistrationError::PaymentRequiresInteractive)
        ));
        assert_eq!(api.calls(), ["pricing"]);
    }

    #[tokio::test]
    async fn confirmed_paid_registration_prints_payment_then_checks_out() {
        let api = FakeRegistrationApi::paid();
        let ui = AcceptingUi::default();

        let outcome = register_missing_root(&api, &ui, &target(), "token", true)
            .await
            .unwrap();

        assert_eq!(outcome, RegistrationOutcome::CreatedPaid);
        assert_eq!(api.calls(), ["pricing", "register-root", "checkout"]);
        assert_eq!(
            *ui.printed.lock().unwrap(),
            ["https://pay.example.test/checkout"]
        );
    }

    #[tokio::test]
    async fn missing_child_accepts_email_or_direct_parent_proof_without_checkout() {
        let child = IdentityTarget::parse("phone.alice.smith").unwrap();
        let email_api = FakeRegistrationApi::free();
        let parent_api = FakeRegistrationApi::free();

        assert_eq!(
            register_missing_child(&email_api, &child, RegistrationProof::AccessToken("token"))
                .await
                .unwrap(),
            RegistrationOutcome::CreatedFree
        );
        assert_eq!(email_api.calls(), ["register-child:token"]);

        assert_eq!(
            register_missing_child(
                &parent_api,
                &child,
                RegistrationProof::ParentIdentity("alice.smith.dhttp.net")
            )
            .await
            .unwrap(),
            RegistrationOutcome::CreatedFree
        );
        assert_eq!(parent_api.calls(), ["register-child:parent"]);
    }

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
