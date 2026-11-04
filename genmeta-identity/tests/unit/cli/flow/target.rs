use std::path::PathBuf;

use dhttp_identity::name::DhttpName;

use super::{
    IdentityLevel, IdentityTarget, RemoteTargetState, ReplacementRequirement,
    remote_state_from_availability, replacement_requirement,
};
use crate::cli::flow::local::{IdentityUsage, LocalIdentityStatus, LocalIdentitySummary};

fn summary(status: LocalIdentityStatus) -> LocalIdentitySummary {
    LocalIdentitySummary {
        target: IdentityTarget::parse("alice.smith").unwrap(),
        usage: Some(IdentityUsage::BothClientAndServer),
        code_signing: None,
        sequence: Some(0),
        valid_from: Some(1_700_000_000),
        expires_at: Some(1_900_000_000),
        status,
        dir: PathBuf::from("/tmp/alice.smith"),
        is_default: false,
    }
}

#[test]
fn availability_maps_existing_and_missing_targets_without_rejecting_apply() {
    assert_eq!(
        remote_state_from_availability("conflict").unwrap(),
        RemoteTargetState::Exists
    );
    assert_eq!(
        remote_state_from_availability("available").unwrap(),
        RemoteTargetState::Missing
    );
    assert_eq!(
        remote_state_from_availability("reserved").unwrap(),
        RemoteTargetState::Unavailable
    );
    assert_eq!(
        remote_state_from_availability("unavailable").unwrap(),
        RemoteTargetState::Unavailable
    );
}

#[test]
fn replacement_decision_only_blocks_ready_and_expired_material() {
    let ready = summary(LocalIdentityStatus::Ready {
        expires_at: 1_900_000_000,
    });
    let expired = summary(LocalIdentityStatus::Expired {
        expired_at: 1_600_000_000,
    });
    let invalid = summary(LocalIdentityStatus::Invalid {
        detail: "certificate is unreadable".to_string(),
    });
    let incomplete = summary(LocalIdentityStatus::Incomplete {
        detail: "private key is missing".to_string(),
    });

    assert_eq!(replacement_requirement(None), ReplacementRequirement::None);
    assert_eq!(
        replacement_requirement(Some(&ready)),
        ReplacementRequirement::Confirm
    );
    assert_eq!(
        replacement_requirement(Some(&expired)),
        ReplacementRequirement::Confirm
    );
    assert_eq!(
        replacement_requirement(Some(&invalid)),
        ReplacementRequirement::None
    );
    assert_eq!(
        replacement_requirement(Some(&incomplete)),
        ReplacementRequirement::None
    );
}

#[test]
fn parses_short_and_full_identity_names() {
    let identity = IdentityTarget::parse("alice.smith").unwrap();
    assert_eq!(identity.level(), IdentityLevel::Identity);
    assert_eq!(identity.short_name(), "alice.smith");
    assert_eq!(identity.full_name(), "alice.smith.dhttp.net");
    assert_eq!(identity.parent(), None);

    let sub_identity = IdentityTarget::parse("phone.alice.smith.dhttp.net").unwrap();
    assert_eq!(sub_identity.level(), IdentityLevel::SubIdentity);
    assert_eq!(sub_identity.short_name(), "phone.alice.smith");
    assert_eq!(sub_identity.full_name(), "phone.alice.smith.dhttp.net");
    assert_eq!(
        sub_identity.parent().unwrap(),
        DhttpName::try_from("alice.smith").unwrap(),
    );
}

#[test]
fn rejects_unsupported_identity_depths() {
    for input in ["alice", "one.two.three.four"] {
        let error = IdentityTarget::parse(input).unwrap_err();
        assert_eq!(
            error.to_string(),
            "This name must match [handle.]your.name."
        );
    }
}

#[test]
fn direct_name_errors_use_the_same_copy_as_the_prompt() {
    assert_eq!(
        IdentityTarget::parse("alice!.smith")
            .unwrap_err()
            .to_string(),
        "This name contains unsupported special characters."
    );
}

#[test]
fn prompt_errors_use_the_approved_name_language() {
    assert_eq!(
        IdentityTarget::parse("alice").unwrap_err().prompt_message(),
        "This name must match [handle.]your.name."
    );
    assert_eq!(
        IdentityTarget::parse("alice!.smith")
            .unwrap_err()
            .prompt_message(),
        "This name contains unsupported special characters."
    );
}

#[test]
fn extracts_sub_identity_label_from_first_label() {
    let identity = IdentityTarget::parse("phone.alice.smith").unwrap();
    assert_eq!(identity.sub_identity_label(), Some("phone"));

    let root_identity = IdentityTarget::parse("alice.smith").unwrap();
    assert_eq!(root_identity.sub_identity_label(), None);
}
