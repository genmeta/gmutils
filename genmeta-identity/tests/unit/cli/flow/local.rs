use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use dhttp_home::DhttpHome;
use dhttp_identity::name::DhttpName;

#[cfg(not(windows))]
use super::try_load_summary_exact;
use super::{
    IdentityUsage, InteractiveInventoryChoice, LocalIdentityAssessment, LocalIdentityMaterialState,
    LocalIdentityStatus, LocalIdentitySummary, LocalInventoryRoot, build_default_inventory_choices,
    build_inventory, build_renew_inventory_choices, classify_status, is_near_expiry,
};
use crate::cli::flow::target::IdentityTarget;

const NOW: i64 = 1_794_298_000;

fn unique_test_home_path(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "genmeta-identity-local-{test_name}-{}-{nonce}",
        std::process::id()
    ))
}

fn ready_summary(name: &str, is_default: bool, chain: &str) -> LocalIdentitySummary {
    let (usage, sequence) = match chain.split_once(':').unwrap() {
        ("primary", sequence) => (
            IdentityUsage::BothClientAndServer,
            sequence.parse().unwrap(),
        ),
        ("secondary", sequence) => (IdentityUsage::ClientOnly, sequence.parse().unwrap()),
        _ => panic!("unsupported test certificate chain"),
    };
    LocalIdentitySummary {
        target: IdentityTarget::parse(name).unwrap(),
        usage: Some(usage),
        sequence: Some(sequence),
        valid_from: Some(NOW - 300),
        expires_at: Some(NOW + 300),
        status: LocalIdentityStatus::Ready {
            expires_at: NOW + 300,
        },
        dir: PathBuf::from(format!("/tmp/{name}")),
        is_default,
    }
}

#[test]
fn near_expiry_starts_at_two_thirds_of_the_validity_window() {
    let valid_from = 1_000;
    let expires_at = 1_900;
    assert!(!is_near_expiry(valid_from, expires_at, 1_599));
    assert!(is_near_expiry(valid_from, expires_at, 1_600));
    assert!(is_near_expiry(valid_from, expires_at, 1_899));
    assert!(!is_near_expiry(valid_from, expires_at, 1_900));
}

#[test]
fn trust_check_keeps_zero_length_expired_certificates_classifiable() {
    assert_eq!(
        super::trust_check_timestamp(1_000, 1_000, 1_001),
        Some(1_000)
    );
    assert_eq!(super::trust_check_timestamp(1_001, 1_000, 1_001), None);
}

#[cfg(not(windows))]
#[tokio::test]
async fn exact_summary_never_falls_back_to_a_wildcard_profile() {
    let home_path = unique_test_home_path("exact-only");
    let home = DhttpHome::new(home_path.clone());
    let requested = DhttpName::try_from("phone.alice.smith").unwrap();
    let wildcard = requested.clone().to_wildcard();
    tokio::fs::create_dir_all(
        home.identity_profile((wildcard.borrow()).as_full())
            .expect("validated identity name")
            .ssl_dir(),
    )
    .await
    .unwrap();

    assert!(
        try_load_summary_exact(&home, requested.borrow(), None)
            .await
            .unwrap()
            .is_none()
    );

    tokio::fs::remove_dir_all(home_path).await.unwrap();
}

#[tokio::test]
async fn untrusted_local_certificate_is_invalid_before_authentication() {
    const CHAIN: &str = include_str!("../../../fixtures/install/chain.pem");
    const KEY: &str = include_str!("../../../fixtures/install/leaf.key");

    let home_path = unique_test_home_path("untrusted-local-certificate");
    let home = DhttpHome::new(home_path);
    let name = DhttpName::try_from("alice.smith").unwrap();
    home.identity_profile((name.borrow()).as_full())
        .expect("validated identity name")
        .save_identity(CHAIN.as_bytes(), KEY.as_bytes())
        .await
        .unwrap();

    let summary = super::load_summary_exact(&home, name.borrow(), None)
        .await
        .unwrap();
    assert_eq!(
        summary.status,
        LocalIdentityStatus::Invalid {
            detail: "certificate chain is not trusted".to_string(),
        }
    );
}

#[test]
fn classifies_ready_expired_incomplete_and_invalid() {
    let ready = classify_status(
        &LocalIdentityAssessment {
            certificate: LocalIdentityMaterialState::Present,
            private_key: LocalIdentityMaterialState::Present,
            certificate_target_matches: Some(true),
            usage: Some(IdentityUsage::BothClientAndServer),
            sequence: Some(0),
            valid_from: Some(NOW - 300),
            expires_at: Some(NOW + 300),
        },
        NOW,
    );
    assert_eq!(
        ready,
        LocalIdentityStatus::Ready {
            expires_at: NOW + 300,
        }
    );

    let expired = classify_status(
        &LocalIdentityAssessment {
            certificate: LocalIdentityMaterialState::Present,
            private_key: LocalIdentityMaterialState::Present,
            certificate_target_matches: Some(true),
            usage: Some(IdentityUsage::ClientOnly),
            sequence: Some(2),
            valid_from: Some(NOW - 300),
            expires_at: Some(NOW - 1),
        },
        NOW,
    );
    assert_eq!(
        expired,
        LocalIdentityStatus::Expired {
            expired_at: NOW - 1,
        }
    );

    let incomplete = classify_status(
        &LocalIdentityAssessment {
            certificate: LocalIdentityMaterialState::Present,
            private_key: LocalIdentityMaterialState::Missing("private key missing"),
            certificate_target_matches: Some(true),
            usage: Some(IdentityUsage::ClientOnly),
            sequence: Some(3),
            valid_from: Some(NOW - 300),
            expires_at: Some(NOW + 300),
        },
        NOW,
    );
    assert_eq!(
        incomplete,
        LocalIdentityStatus::Incomplete {
            detail: "private key missing".to_string(),
        }
    );

    let invalid = classify_status(
        &LocalIdentityAssessment {
            certificate: LocalIdentityMaterialState::Invalid(
                "certificate does not match local key".to_string(),
            ),
            private_key: LocalIdentityMaterialState::Present,
            certificate_target_matches: Some(true),
            usage: Some(IdentityUsage::ClientOnly),
            sequence: Some(4),
            valid_from: Some(NOW - 300),
            expires_at: Some(NOW + 300),
        },
        NOW,
    );
    assert_eq!(
        invalid,
        LocalIdentityStatus::Invalid {
            detail: "certificate does not match local key".to_string(),
        }
    );

    let not_valid_yet = classify_status(
        &LocalIdentityAssessment {
            certificate: LocalIdentityMaterialState::Present,
            private_key: LocalIdentityMaterialState::Present,
            certificate_target_matches: Some(true),
            usage: Some(IdentityUsage::BothClientAndServer),
            sequence: Some(0),
            valid_from: Some(NOW + 1),
            expires_at: Some(NOW + 300),
        },
        NOW,
    );
    assert_eq!(
        not_valid_yet,
        LocalIdentityStatus::Invalid {
            detail: "certificate is not valid yet".to_string(),
        }
    );
}

#[test]
fn builds_inventory_with_saved_and_organization_roots() {
    let mut tv = ready_summary("tv.alice.smith", false, "secondary:3");
    tv.status = LocalIdentityStatus::Incomplete {
        detail: "private key missing".to_string(),
    };
    tv.usage = None;
    tv.sequence = None;

    let inventory = build_inventory(vec![
        ready_summary("tablet.reimu.scarlet", false, "secondary:1"),
        tv,
        ready_summary("phone.alice.smith", false, "secondary:2"),
        ready_summary("alice.smith", true, "primary:0"),
    ]);

    match &inventory.groups[0].root {
        LocalInventoryRoot::Saved(summary) => {
            assert_eq!(summary.target.short_name(), "alice.smith");
            assert!(summary.is_default);
        }
        other => panic!("expected saved root, got {other:?}"),
    }
    assert_eq!(inventory.groups[0].children.len(), 2);
    assert_eq!(
        inventory.groups[0].children[0].target.short_name(),
        "phone.alice.smith"
    );
    assert_eq!(
        inventory.groups[0].children[1].target.short_name(),
        "tv.alice.smith"
    );

    match &inventory.groups[1].root {
        LocalInventoryRoot::Organization { target } => {
            assert_eq!(target.short_name(), "reimu.scarlet");
        }
        other => panic!("expected organization root, got {other:?}"),
    }
    assert_eq!(inventory.groups[1].children.len(), 1);
    assert_eq!(
        inventory.groups[1].children[0].target.short_name(),
        "tablet.reimu.scarlet"
    );
}

#[test]
fn build_renew_inventory_choices_keeps_missing_parent_roots() {
    let child = ready_summary("shanghai.alice.ma", false, "secondary:1");
    let inventory = build_inventory(vec![child.clone()]);

    assert_eq!(
        build_renew_inventory_choices(&inventory),
        vec![
            InteractiveInventoryChoice::Organization {
                target: IdentityTarget::parse("alice.ma").unwrap(),
            },
            InteractiveInventoryChoice::Saved(child),
        ]
    );
}

#[test]
fn builds_default_inventory_choices_with_organization_roots_without_enter_another_identity() {
    let inventory = build_inventory(vec![
        ready_summary("phone.alice.smith", false, "secondary:2"),
        ready_summary("tablet.reimu.scarlet", false, "secondary:1"),
    ]);

    assert_eq!(
        build_default_inventory_choices(&inventory),
        vec![
            InteractiveInventoryChoice::Organization {
                target: IdentityTarget::parse("alice.smith").unwrap(),
            },
            InteractiveInventoryChoice::Saved(ready_summary(
                "phone.alice.smith",
                false,
                "secondary:2",
            )),
            InteractiveInventoryChoice::Organization {
                target: IdentityTarget::parse("reimu.scarlet").unwrap(),
            },
            InteractiveInventoryChoice::Saved(ready_summary(
                "tablet.reimu.scarlet",
                false,
                "secondary:1",
            )),
        ]
    );
}

#[tokio::test]
async fn load_inventory_returns_empty_when_home_directory_is_missing() {
    let home_path = unique_test_home_path("missing-home-inventory");
    let dhttp_home = DhttpHome::new(home_path);

    let inventory = super::load_inventory(&dhttp_home, None).await.unwrap();

    assert!(inventory.groups.is_empty());
}

#[tokio::test]
async fn try_load_summary_returns_none_when_profile_is_missing() {
    let home_path = unique_test_home_path("missing-home-summary");
    let dhttp_home = DhttpHome::new(home_path);
    let name = DhttpName::try_from("alice.smith").unwrap();

    let summary = super::try_load_summary_exact(&dhttp_home, name.borrow(), None)
        .await
        .unwrap();

    assert!(summary.is_none());
}
