use std::sync::Arc;

use rustls::{RootCertStore, pki_types::CertificateDer, server::WebPkiClientVerifier};

use super::*;

const CHAIN: &str = include_str!("../../../fixtures/install/chain.pem");
const MALFORMED_SKI_CHAIN: &str = include_str!("../../../fixtures/install/malformed-ski-chain.pem");
const KEY: &str = include_str!("../../../fixtures/install/leaf.key");
const OTHER_KEY: &str = include_str!("../../../fixtures/install/other.key");
const ROOT: &[u8] = include_bytes!("../../../fixtures/install/root.crt");
const SKI: &str = "7:0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn detail() -> CertificateDetail {
    CertificateDetail {
        domain: "alice.smith.dhttp.net".to_string(),
        device_name: Some("test device".to_string()),
        sequence: 7,
        kind: "primary".to_string(),
        serial_number: None,
        ski: Some(SKI.to_string()),
        ski_version: Some("1".to_string()),
        status: "active".to_string(),
        csr: String::new(),
        cert_pem: CHAIN.to_string(),
        issued_at: 0,
        valid_not_after: i64::MAX,
        created_at: 0,
    }
}

fn expectation<'a>(name: DhttpName<'a>) -> InstallExpectation<'a> {
    InstallExpectation {
        target: name,
        kind: IdentityKind::Primary,
        sequence: Some(7),
    }
}

fn test_verifier() -> Arc<dyn ClientCertVerifier> {
    _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(ROOT).map(Result::unwrap));
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap()
}

fn assert_validation_error(
    detail: &CertificateDetail,
    expected: &InstallExpectation<'_>,
    key: &str,
    expected_message: &str,
) {
    let error = validate_install_with_verifier(detail, expected, key, test_verifier())
        .expect_err("fixture must fail validation");
    assert!(
        error.to_string().contains(expected_message),
        "expected {expected_message:?} in {error}"
    );
}

#[test]
fn install_validation_rejects_mismatched_target_kind_sequence_key_and_metadata() {
    let name = DhttpName::try_from("alice.smith").unwrap();
    let expected = expectation(name.borrow());
    validate_install_with_verifier(&detail(), &expected, KEY, test_verifier()).unwrap();
    validate_install_with_verifier(
        &detail(),
        &InstallExpectation {
            sequence: None,
            ..expected.clone()
        },
        KEY,
        test_verifier(),
    )
    .unwrap();

    let mut other_target = detail();
    other_target.domain = "other.smith.dhttp.net".to_string();
    assert_validation_error(&other_target, &expected, KEY, "target name");

    let other_name = DhttpName::try_from("other.smith").unwrap();
    let other_target_expected = InstallExpectation {
        target: other_name.borrow(),
        ..expected.clone()
    };
    assert_validation_error(&other_target, &other_target_expected, KEY, "target name");

    let mut other_kind = detail();
    other_kind.kind = "secondary".to_string();
    assert_validation_error(&other_kind, &expected, KEY, "usage");
    let secondary_expected = InstallExpectation {
        kind: IdentityKind::Secondary,
        ..expected.clone()
    };
    assert_validation_error(&other_kind, &secondary_expected, KEY, "usage");

    let other_sequence = InstallExpectation {
        sequence: Some(8),
        ..expected.clone()
    };
    assert_validation_error(&detail(), &other_sequence, KEY, "sequence");
    let mut other_sequence_detail = detail();
    other_sequence_detail.sequence = 8;
    assert_validation_error(&other_sequence_detail, &other_sequence, KEY, "sequence");
    assert_validation_error(&detail(), &expected, OTHER_KEY, "private key");

    let mut revoked = detail();
    revoked.status = "revoked".to_string();
    assert_validation_error(&revoked, &expected, KEY, "status");

    let mut missing_response_ski = detail();
    missing_response_ski.ski = None;
    assert_validation_error(
        &missing_response_ski,
        &expected,
        KEY,
        "DHTTP certificate metadata",
    );

    let mut malformed_leaf_ski = detail();
    malformed_leaf_ski.cert_pem = MALFORMED_SKI_CHAIN.to_string();
    assert_validation_error(
        &malformed_leaf_ski,
        &expected,
        KEY,
        "DHTTP certificate metadata",
    );
}

#[test]
fn production_trust_rejects_a_chain_outside_the_dhttp_root() {
    let name = DhttpName::try_from("alice.smith").unwrap();
    let error = validate_install(&detail(), &expectation(name.borrow()), KEY).unwrap_err();

    assert!(error.to_string().contains("trusted"), "{error}");
}

#[tokio::test]
async fn failed_validation_never_creates_or_saves_a_profile() {
    let home_path = std::env::temp_dir().join(format!(
        "genmeta-identity-invalid-install-{}",
        std::process::id()
    ));
    let _ = tokio::fs::remove_dir_all(&home_path).await;
    let home = dhttp_home::DhttpHome::new(home_path.clone());
    let name = DhttpName::try_from("alice.smith").unwrap();
    let mut invalid = detail();
    invalid.domain = "other.smith.dhttp.net".to_string();

    assert!(
        validate_and_save(
            &home,
            &invalid,
            &expectation(name.borrow()),
            KEY,
            dhttp::log::cert::CertificateAction::Apply,
        )
        .await
        .is_err()
    );
    assert!(!home_path.exists());
}
