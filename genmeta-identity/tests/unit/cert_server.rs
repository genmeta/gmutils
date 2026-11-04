use super::*;

#[test]
fn service_url_preserves_the_configured_authority() {
    _ = rustls::crypto::ring::default_provider().install_default();
    let configured = CertServer::new("https://api.genmeta.net").unwrap();
    assert_eq!(
        configured.service_url("/v2/cert"),
        "https://api.genmeta.net/v2/cert"
    );

    let custom_port = CertServer::new("https://api.example.test:8443").unwrap();
    assert_eq!(
        custom_port.service_url("/v2/cert"),
        "https://api.example.test:8443/v2/cert"
    );

    let local = CertServer::new("http://127.0.0.1:38080").unwrap();
    assert_eq!(
        local.service_url("/v2/cert"),
        "http://127.0.0.1:38080/v2/cert"
    );
}

#[test]
fn parses_v2_error_envelope() {
    let payload =
        br#"{"error":{"code":"domain_forbidden","message":"domain access is forbidden"}}"#;
    let error = parse_error_body(reqwest::StatusCode::FORBIDDEN, payload).unwrap_err();
    match error {
        Error::Api {
            status,
            code,
            message,
        } => {
            assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
            assert_eq!(code, "domain_forbidden");
            assert_eq!(message, "domain access is forbidden");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn api_code_helpers_match_api_errors() {
    let error = Error::Api {
        status: reqwest::StatusCode::CONFLICT,
        code: "starter_domain_limit_reached".to_string(),
        message: "starter plan is limited to 3 free domains per account".to_string(),
    };

    assert_eq!(error.api_code(), Some("starter_domain_limit_reached"));
    assert!(error.is_api_code("starter_domain_limit_reached"));
    assert!(!error.is_api_code("domain_not_found"));
    assert!(error.is_api(
        reqwest::StatusCode::CONFLICT,
        "starter_domain_limit_reached"
    ));
    assert!(!error.is_api(
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "starter_domain_limit_reached"
    ));
}

#[test]
fn invalid_idempotency_key_is_rejected_without_panicking() {
    let error = idempotency_header("renew-v1\ninvalid").unwrap_err();
    assert!(error.to_string().starts_with("invalid idempotency key:"));
}

#[test]
fn api_error_displays_the_certserver_problem_message_verbatim() {
    let error = Error::Api {
        status: reqwest::StatusCode::FORBIDDEN,
        code: "domain_forbidden".to_string(),
        message: "domain access is forbidden".to_string(),
    };

    assert_eq!(error.to_string(), "domain access is forbidden");
}

#[test]
fn parses_numeric_v2_error_code_and_preserves_the_wire_value() {
    let payload = br#"{"error":{"code":1101,"message":"The email address is invalid."}}"#;
    let error = parse_error_body(reqwest::StatusCode::BAD_REQUEST, payload).unwrap_err();

    assert_eq!(error.api_code(), Some("email_invalid"));
    assert_eq!(error.to_string(), "The email address is invalid.");
    match error {
        Error::Api { code, .. } => assert_eq!(code, "1101"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn unknown_numeric_error_code_remains_decimal() {
    let payload = br#"{"error":{"code":2999,"message":"future problem"}}"#;
    let error = parse_error_body(reqwest::StatusCode::CONFLICT, payload).unwrap_err();

    assert_eq!(error.api_code(), Some("2999"));
    assert_eq!(error.to_string(), "future problem");
}

#[test]
fn subdomain_quota_error_explains_how_to_add_seats() {
    let payload = br#"{"error":{"code":1304,"message":"The parent name has no available sub-identity slots."}}"#;
    let error = parse_error_body(reqwest::StatusCode::UNPROCESSABLE_ENTITY, payload).unwrap_err();

    assert_eq!(
        error.to_string(),
        "The parent identity has reached its sub-identity seat limit. Update your subscription plan to add more seats, then try again."
    );
}

#[test]
fn malformed_error_code_stays_a_json_response_error() {
    let payload = br#"{"error":{"code":true,"message":"invalid envelope"}}"#;
    assert!(matches!(
        parse_error_body(reqwest::StatusCode::BAD_REQUEST, payload),
        Err(Error::Json { .. })
    ));
}

#[test]
fn domain_availability_response_reads_pricing_envelope() {
    let payload = r#"
    {
      "domain":"alice.smith.dhttp.net",
      "availability":"conflict",
      "currency":"USD",
      "prices":[
        {"interval":"monthly","amount":500},
        {"interval":"yearly","amount":3000,"discount":0.5}
      ]
    }
    "#;
    let response: DomainAvailabilityResponse = serde_json::from_str(payload).unwrap();
    assert_eq!(response.domain, "alice.smith.dhttp.net");
    assert_eq!(response.availability, "conflict");
    assert_eq!(response.currency, "USD");
    assert_eq!(response.monthly_amount(), Some(500));
    assert_eq!(response.yearly_amount(), Some(3000));
    assert!(!response.is_free());
}

#[test]
fn domain_registration_requests_disable_implicit_auto_renewal() {
    let token_request = serde_json::to_value(CreateDomainRequest::new(
        "alice.smith.dhttp.net",
        None,
        None,
    ))
    .unwrap();
    let email_request = serde_json::to_value(CreateDomainRequest::new(
        "alice.smith.dhttp.net",
        Some("alice@example.test"),
        Some("123456"),
    ))
    .unwrap();

    assert_eq!(token_request["auto_renew"], false);
    assert!(token_request.get("email").is_none());
    assert!(token_request.get("verify_code").is_none());
    assert_eq!(email_request["auto_renew"], false);
    assert_eq!(email_request["email"], "alice@example.test");
    assert_eq!(email_request["verify_code"], "123456");
}

#[test]
fn create_domain_response_accepts_payment_payload() {
    let payload = r#"
    {
      "domain":"alice.smith.dhttp.net",
      "quotes":{"currency":"USD","monthly":9900,"yearly":99000,"default_billing_cycle":"yearly"},
      "reservation":{"reservation_no":"RSV123","status":"reserved","expires_at":1760001800},
      "payment_entry":{"url":"https://dhttp.net/checkout/ckt_123","checkout_token":"ckt_123","expires_at":1760000300},
      "next_action":"payment",
      "auth":{"email":"alice@example.com","is_new_user":true,"access_token":"token","token_expires_at":1760090000}
    }
    "#;
    let response: CreateDomainResponse = serde_json::from_str(payload).unwrap();
    assert_eq!(response.domain, "alice.smith.dhttp.net");
    assert_eq!(response.next_action, "payment");
    assert_eq!(response.payment_entry.unwrap().checkout_token, "ckt_123");
    assert_eq!(response.auth.unwrap().access_token, "token");
}

#[test]
fn subdomain_quota_error_details_are_parsed() {
    let payload = br#"{
      "error": {
        "code": 1304,
        "message": "subdomain quota exceeded",
        "details": {
          "domain": "phone.alice.smith.dhttp.net",
          "quota_quote": {
            "due": 500,
            "currency": "USD",
            "days_left": 120,
            "days_total": 365,
            "renewal": 1200
          }
        }
      }
    }"#;

    assert_eq!(
        parse_subdomain_quota_quote(reqwest::StatusCode::UNPROCESSABLE_ENTITY, payload).unwrap(),
        Some(SubdomainQuotaQuote {
            domain: "phone.alice.smith.dhttp.net".to_string(),
            due: 500,
            currency: "USD".to_string(),
            days_left: 120,
            days_total: 365,
            renewal: 1200,
        })
    );
}

#[test]
fn subdomain_quota_error_details_accept_missing_term_fields() {
    let payload = br#"{
      "error": {
        "code": "subdomain_quota_exceeded",
        "message": "subdomain quota exceeded",
        "details": {
          "domain": "phone.alice.smith.dhttp.net",
          "quota_quote": {
            "due": 500,
            "currency": "USD"
          }
        }
      }
    }"#;

    assert_eq!(
        parse_subdomain_quota_quote(reqwest::StatusCode::UNPROCESSABLE_ENTITY, payload).unwrap(),
        Some(SubdomainQuotaQuote {
            domain: "phone.alice.smith.dhttp.net".to_string(),
            due: 500,
            currency: "USD".to_string(),
            days_left: 0,
            days_total: 0,
            renewal: 0,
        })
    );
}

#[test]
fn subdomain_quota_error_details_accept_flat_quote_fields() {
    let payload = br#"{
      "error": {
        "code": "subdomain_quota_exceeded",
        "message": "subdomain quota exceeded",
        "details": {
          "domain": "phone.alice.smith.dhttp.net",
          "due": 500,
          "currency": "USD"
        }
      }
    }"#;

    assert_eq!(
        parse_subdomain_quota_quote(reqwest::StatusCode::UNPROCESSABLE_ENTITY, payload).unwrap(),
        Some(SubdomainQuotaQuote {
            domain: "phone.alice.smith.dhttp.net".to_string(),
            due: 500,
            currency: "USD".to_string(),
            days_left: 0,
            days_total: 0,
            renewal: 0,
        })
    );
}
