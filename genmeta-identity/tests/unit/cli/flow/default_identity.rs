use std::path::PathBuf;

use super::{DefaultSetDecision, default_not_found_message, default_set_decision};
use crate::cli::flow::{
    local::{IdentityUsage, LocalIdentityStatus, LocalIdentitySummary},
    target::IdentityTarget,
};

fn summary(status: LocalIdentityStatus) -> LocalIdentitySummary {
    LocalIdentitySummary {
        target: IdentityTarget::parse("alice.smith").unwrap(),
        usage: Some(IdentityUsage::BothClientAndServer),
        sequence: Some(0),
        valid_from: Some(1_700_000_000),
        expires_at: Some(1_900_000_000),
        status,
        dir: PathBuf::from("/tmp/alice.smith"),
        is_default: false,
    }
}

#[test]
fn missing_default_target_matches_the_edited_document() {
    assert_eq!(
        default_not_found_message("alice.smith"),
        "Failed to set default identity: alice.smith not found!"
    );
}

#[test]
fn default_setter_requires_force_for_every_nonready_status() {
    let ready = summary(LocalIdentityStatus::Ready {
        expires_at: 1_900_000_000,
    });
    assert_eq!(
        default_set_decision(&ready, false),
        DefaultSetDecision::Allow
    );

    for nonready in [
        LocalIdentityStatus::Expired {
            expired_at: 1_700_000_000,
        },
        LocalIdentityStatus::Invalid {
            detail: "certificate is invalid".to_string(),
        },
        LocalIdentityStatus::Incomplete {
            detail: "private key is missing".to_string(),
        },
    ] {
        let summary = summary(nonready);
        assert_eq!(
            default_set_decision(&summary, false),
            DefaultSetDecision::RequireForce
        );
        assert_eq!(
            default_set_decision(&summary, true),
            DefaultSetDecision::Allow
        );
    }
}
