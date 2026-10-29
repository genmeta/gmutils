use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use dhttp_home::{DhttpHome, HomeScope};

use super::{
    RenewPreflight, inventory_targets, renew_not_due_message, renew_not_saved_root_message,
    renew_remote_error, renewal_is_due, stops_automatic_renewal,
};
use crate::cli::{
    Renew,
    flow::{
        local::{IdentityUsage, LocalIdentityStatus, LocalIdentitySummary},
        target::IdentityTarget,
    },
};

fn unique_test_home_path(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "genmeta-identity-renew-{test_name}-{}-{nonce}",
        std::process::id()
    ))
}

fn dummy_cert_server() -> crate::cert_server::CertServer {
    _ = rustls::crypto::ring::default_provider().install_default();
    crate::cert_server::CertServer::new("https://license.genmeta.net").unwrap()
}

fn summary(status: LocalIdentityStatus, facts: bool) -> LocalIdentitySummary {
    LocalIdentitySummary {
        target: IdentityTarget::parse("alice.smith").unwrap(),
        usage: facts.then_some(IdentityUsage::ClientOnly),
        sequence: facts.then_some(2),
        valid_from: Some(1_700_000_000),
        expires_at: Some(1_900_000_000),
        status,
        dir: PathBuf::from("/tmp/alice.smith"),
        is_default: false,
    }
}

#[test]
fn renewal_is_due_only_within_fifteen_days_or_when_expiry_is_unknown() {
    const DAY: i64 = 24 * 60 * 60;
    let now = 1_800_000_000;

    assert!(renewal_is_due(None, now));
    assert!(renewal_is_due(Some(now - 1), now));
    assert!(renewal_is_due(Some(now + 15 * DAY - 1), now));
    assert!(!renewal_is_due(Some(now + 15 * DAY), now));
    assert!(!renewal_is_due(Some(now + 30 * DAY), now));
}

#[test]
fn batch_targets_follow_the_deterministic_inventory_order() {
    let alice = summary(
        LocalIdentityStatus::Ready {
            expires_at: 1_900_000_000,
        },
        true,
    );
    let mut bob = alice.clone();
    bob.target = IdentityTarget::parse("bob.smith").unwrap();
    let inventory = crate::cli::flow::local::build_inventory(vec![bob, alice]);

    let names = inventory_targets(inventory)
        .into_iter()
        .map(|target| target.short_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(names, ["alice.smith", "bob.smith"]);
}

#[test]
fn not_due_message_reports_remaining_days_and_force_hint() {
    const DAY: i64 = 24 * 60 * 60;
    let now = 1_800_000_000;

    assert_eq!(
        renew_not_due_message("alice.smith", now + 20 * DAY, now),
        "Renewal skipped: alice.smith is valid for 20 more days."
    );
    assert_eq!(
        renew_not_due_message("alice.smith", now + 15 * DAY, now),
        "Renewal skipped: alice.smith is valid for 15 more days."
    );
}

#[test]
fn renew_preflight_accepts_healthy_near_expiry_and_expired_without_force() {
    for summary in [
        summary(
            LocalIdentityStatus::Ready {
                expires_at: 1_900_000_000,
            },
            true,
        ),
        summary(
            LocalIdentityStatus::Ready {
                expires_at: 1_800_000_001,
            },
            true,
        ),
        summary(
            LocalIdentityStatus::Expired {
                expired_at: 1_700_000_000,
            },
            true,
        ),
    ] {
        let preflight = RenewPreflight::from_summary(&summary, false).unwrap();
        assert_eq!(
            preflight.kind,
            crate::cli::flow::kind::IdentityKind::Secondary
        );
        assert_eq!(preflight.sequence, 2);
    }
}

#[test]
fn renew_maps_certificate_usage_to_server_kind() {
    let mut primary = summary(
        LocalIdentityStatus::Ready {
            expires_at: 1_900_000_000,
        },
        true,
    );
    primary.usage = Some(IdentityUsage::BothClientAndServer);
    let primary = RenewPreflight::from_summary(&primary, false).unwrap();
    assert_eq!(primary.certificate_kind(), "primary");

    let secondary = RenewPreflight::from_summary(
        &summary(
            LocalIdentityStatus::Ready {
                expires_at: 1_900_000_000,
            },
            true,
        ),
        false,
    )
    .unwrap();
    assert_eq!(secondary.certificate_kind(), "secondary");
}

#[test]
fn force_only_recovers_nonready_material_with_certificate_facts() {
    let incomplete = summary(
        LocalIdentityStatus::Incomplete {
            detail: "private key missing".to_string(),
        },
        true,
    );
    let invalid = summary(
        LocalIdentityStatus::Invalid {
            detail: "certificate does not match local key".to_string(),
        },
        true,
    );
    let missing_certificate = summary(
        LocalIdentityStatus::Incomplete {
            detail: "certificate missing".to_string(),
        },
        false,
    );

    assert!(RenewPreflight::from_summary(&incomplete, false).is_err());
    assert!(RenewPreflight::from_summary(&incomplete, true).is_ok());
    assert!(RenewPreflight::from_summary(&invalid, true).is_ok());
    assert!(RenewPreflight::from_summary(&missing_certificate, true).is_err());
}

#[test]
fn missing_chain_error_keeps_server_message_and_appends_apply_hint() {
    let error = crate::cert_server::Error::Api {
        status: reqwest::StatusCode::NOT_FOUND,
        code: "cert_sequence_not_found".to_string(),
        message: "certificate chain was not found".to_string(),
    };
    assert_eq!(
        renew_remote_error(error, "alice.smith").to_string(),
        "certificate chain was not found\nRun `genmeta identity apply alice.smith` to request a new certificate chain."
    );
}

#[test]
fn server_failure_with_reused_code_does_not_offer_apply_recovery() {
    let error = crate::cert_server::Error::Api {
        status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        code: "cert_sequence_not_found".to_string(),
        message: "internal server error".to_string(),
    };

    assert_eq!(
        renew_remote_error(error, "alice.smith").to_string(),
        "internal server error"
    );
}

#[test]
fn expired_and_revoked_domains_stop_automatic_renewal() {
    for code in ["domain_expired", "domain_revoked", "1212", "1213"] {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::CONFLICT,
            code: code.to_string(),
            message: "terminal domain state".to_string(),
        };
        assert!(stops_automatic_renewal(&error), "code {code}");
    }

    let retryable = crate::cert_server::Error::Api {
        status: reqwest::StatusCode::CONFLICT,
        code: "certificate_renewal_not_due".to_string(),
        message: "renewal is not due".to_string(),
    };
    assert!(!stops_automatic_renewal(&retryable));
}

#[test]
fn renew_not_saved_message_matches_the_edited_document() {
    assert_eq!(
        renew_not_saved_root_message("alice.ma"),
        "Failed to renew: alice.ma not found!"
    );
}

#[tokio::test]
async fn renew_reports_saved_local_requirement_before_network_or_email() {
    let home_path = unique_test_home_path("renew-unsaved");
    let dhttp_home = DhttpHome::new(home_path);
    let command = Renew {
        name: Some("alice.smith".to_string()),
        all: false,
        force: false,
        device_name: None,
        email: None,
        verify_code: None,
    };

    let error = super::run(&command, &dhttp_home, HomeScope::User, &dummy_cert_server())
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "Failed to renew: alice.smith not found!");
}

#[test]
fn renewed_success_copy_is_visible_and_stable() {
    assert_eq!(
        super::RENEWED,
        "✔ Identity successfully renewed on this device."
    );
}
