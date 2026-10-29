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

    fn free_then_paid() -> Self {
        let mut api = Self::new(0, 0, Some("https://pay.example.test/checkout"));
        api.created.quotes.monthly = 100;
        api.created.quotes.yearly = 600;
        api.created.quotes.options = serde_json::from_value(serde_json::json!([
            {
                "billing_cycle": "monthly",
                "price_code": "root_pro_monthly",
                "list_amount": 500,
                "discount_amount": 400,
                "payable_amount": 100,
                "benefit": {"type": "promotion", "percent_off": 80}
            },
            {
                "billing_cycle": "yearly",
                "price_code": "root_pro_yearly",
                "list_amount": 3000,
                "discount_amount": 2400,
                "payable_amount": 600,
                "benefit": {"type": "promotion", "percent_off": 80}
            }
        ]))
        .unwrap();
        api
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
            created["reservation"] = serde_json::json!({
                "reservation_no": "RSV_test",
                "status": "reserved",
                "expires_at": 1_900_000_000_i64
            });
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
        _token: &str,
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
            RegistrationProof::ParentIdentityProfile(_) => "register-child:parent",
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

    async fn checkout(
        &self,
        _token: &str,
        _expires_at: i64,
    ) -> Result<CreateDomainResponse, RegistrationError> {
        self.calls.lock().unwrap().push("checkout");
        let mut completed = self.created.clone();
        completed.next_action = "completed".to_string();
        Ok(completed)
    }

    async fn cancel_reservation(
        &self,
        _token: &str,
        reservation_no: &str,
    ) -> Result<(), RegistrationError> {
        assert_eq!(reservation_no, "RSV_test");
        self.calls.lock().unwrap().push("cancel");
        Ok(())
    }
}

struct NoUi;

impl RegistrationUi for NoUi {
    async fn confirm_paid_root(&self, _message: &str) -> Result<bool, RegistrationError> {
        Err(RegistrationError::PaymentRequiresInteractive)
    }

    fn print_payment(&self, _url: &str) -> Result<(), RegistrationError> {
        panic!("payment output must not be printed")
    }
}

struct DecliningUi;

impl RegistrationUi for DecliningUi {
    async fn confirm_paid_root(&self, _message: &str) -> Result<bool, RegistrationError> {
        Ok(false)
    }

    fn print_payment(&self, _url: &str) -> Result<(), RegistrationError> {
        panic!("declined registration must not print payment output")
    }
}

#[derive(Default)]
struct AcceptingUi {
    printed: Mutex<Vec<String>>,
    confirmations: Mutex<Vec<String>>,
}

impl RegistrationUi for AcceptingUi {
    async fn confirm_paid_root(&self, message: &str) -> Result<bool, RegistrationError> {
        self.confirmations.lock().unwrap().push(message.to_string());
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
async fn paid_registration_decline_leaves_checkout_unopened() {
    let api = FakeRegistrationApi::paid();
    let result = register_missing_root(&api, &DecliningUi, &target(), "token", true).await;

    assert!(matches!(result, Err(RegistrationError::Declined)));
    assert_eq!(api.calls(), ["pricing", "register-root", "cancel"]);
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
    assert_eq!(
        *ui.confirmations.lock().unwrap(),
        ["alice.smith: USD 5.00/month or USD 30.00/year. Continue to checkout?"]
    );
}

#[tokio::test]
async fn exhausted_free_quota_confirms_final_server_price_then_checks_out() {
    let api = FakeRegistrationApi::free_then_paid();
    let ui = AcceptingUi::default();

    let outcome = register_missing_root(&api, &ui, &target(), "token", true)
        .await
        .unwrap();

    assert_eq!(outcome, RegistrationOutcome::CreatedPaid);
    assert_eq!(api.calls(), ["pricing", "register-root", "checkout"]);
    assert_eq!(
        *ui.confirmations.lock().unwrap(),
        ["Free quota used. alice.smith: USD 1.00/month or USD 6.00/year (80% off). Continue?"]
    );
    assert_eq!(
        *ui.printed.lock().unwrap(),
        ["https://pay.example.test/checkout"]
    );
}

#[tokio::test]
async fn exhausted_free_quota_can_decline_before_checkout() {
    let api = FakeRegistrationApi::free_then_paid();
    let result = register_missing_root(&api, &DecliningUi, &target(), "token", true).await;

    assert!(matches!(result, Err(RegistrationError::Declined)));
    assert_eq!(api.calls(), ["pricing", "register-root", "cancel"]);
}

#[tokio::test]
async fn exhausted_free_quota_requires_an_interactive_checkout_confirmation() {
    let api = FakeRegistrationApi::free_then_paid();
    let result = register_missing_root(&api, &NoUi, &target(), "token", false).await;

    assert!(matches!(
        result,
        Err(RegistrationError::PaymentRequiresInteractive)
    ));
    assert_eq!(api.calls(), ["pricing", "register-root", "cancel"]);
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
            RegistrationProof::ParentIdentityProfile(std::path::Path::new("/tmp/alice.smith"))
        )
        .await
        .unwrap(),
        RegistrationOutcome::CreatedFree
    );
    assert_eq!(parent_api.calls(), ["register-child:parent"]);
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

#[test]
fn server_failures_cannot_be_reclassified_as_registration_state() {
    let conflict = crate::cert_server::Error::Api {
        status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        code: "domain_conflict".to_string(),
        message: "internal server error".to_string(),
    };
    let missing = crate::cert_server::Error::Api {
        status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        code: "domain_not_found".to_string(),
        message: "internal server error".to_string(),
    };

    assert!(!is_domain_conflict(&conflict));
    assert!(!is_subdomain_conflict(&conflict));
    assert!(!is_domain_not_found(&missing));
}
