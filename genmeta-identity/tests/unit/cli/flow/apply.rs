use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;
use crate::cli::flow::local::{IdentityUsage, LocalIdentityStatus, LocalIdentitySummary};

struct ServerFixture {
    root: PathBuf,
    home: DhttpHome,
    target: IdentityTarget,
}

impl ServerFixture {
    async fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "genmeta-identity-apply-server-{label}-{}-{nonce}",
            std::process::id()
        ));
        let home = DhttpHome::new(root.clone());
        let target = IdentityTarget::parse("alice.smith").unwrap();
        tokio::fs::create_dir_all(
            home.identity_profile((target.dhttp_name()).as_full())
                .expect("validated identity name")
                .path(),
        )
        .await
        .unwrap();
        Self { root, home, target }
    }

    fn profile(&self) -> dhttp_home::identity::IdentityProfile {
        self.home
            .identity_profile((self.target.dhttp_name()).as_full())
            .expect("validated identity name")
    }
}

impl Drop for ServerFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn command(name: Option<&str>) -> Apply {
    Apply {
        name: name.map(ToOwned::to_owned),
        force: false,
        device_name: None,
        email: None,
        verify_code: None,
    }
}

#[test]
fn auto_renew_enabled_copy_includes_the_identity_name() {
    assert_eq!(
        auto_renew_enabled_message("alice.smith"),
        "✔ Automatic certificate renewal enabled for alice.smith."
    );
}

fn resolved_with(status: Option<LocalIdentityStatus>) -> ResolvedApplyTarget {
    ResolvedApplyTarget {
        target: IdentityTarget::parse("alice.smith").unwrap(),
        remote: RemoteTargetState::Unknown,
        local: status.map(|status| LocalIdentitySummary {
            target: IdentityTarget::parse("alice.smith").unwrap(),
            usage: Some(IdentityUsage::BothClientAndServer),
            sequence: Some(0),
            valid_from: Some(1_700_000_000),
            expires_at: Some(1_900_000_000),
            status,
            dir: PathBuf::from("/tmp/alice.smith"),
            is_default: false,
        }),
    }
}

#[test]
fn certificate_action_tracks_exact_local_material_lifecycle() {
    assert_eq!(
        certificate_action(&resolved_with(None)),
        dhttp::log::cert::CertificateAction::Apply,
    );
    assert_eq!(
        certificate_action(&resolved_with(Some(LocalIdentityStatus::Invalid {
            detail: "certificate is unreadable".to_string(),
        }))),
        dhttp::log::cert::CertificateAction::Replace,
    );
    assert_eq!(
        certificate_action(&resolved_with(Some(LocalIdentityStatus::Ready {
            expires_at: 1_900_000_000,
        }))),
        dhttp::log::cert::CertificateAction::Replace,
    );
}

#[test]
fn replacement_reuses_sequence_only_for_the_same_certificate_kind() {
    assert_eq!(
        replacement_sequence(&resolved_with(None), IdentityKind::Primary),
        None
    );
    let resolved = resolved_with(Some(LocalIdentityStatus::Incomplete {
        detail: "private key is missing".to_string(),
    }));
    assert_eq!(
        replacement_sequence(&resolved, IdentityKind::Primary),
        Some(0),
    );
    assert_eq!(
        replacement_sequence(&resolved, IdentityKind::Secondary),
        None,
    );

    let mut secondary = resolved;
    secondary.local.as_mut().unwrap().usage = Some(IdentityUsage::ClientOnly);
    assert_eq!(
        replacement_sequence(&secondary, IdentityKind::Secondary),
        Some(0),
    );
    assert_eq!(
        replacement_sequence(&secondary, IdentityKind::Primary),
        None,
    );
}

#[test]
fn replacement_without_local_usage_or_sequence_requests_a_new_chain() {
    let mut resolved = resolved_with(Some(LocalIdentityStatus::Invalid {
        detail: "certificate metadata is incomplete".to_string(),
    }));
    resolved.local.as_mut().unwrap().usage = None;
    assert_eq!(replacement_sequence(&resolved, IdentityKind::Primary), None,);

    resolved.local.as_mut().unwrap().usage = Some(IdentityUsage::BothClientAndServer);
    resolved.local.as_mut().unwrap().sequence = None;
    assert_eq!(replacement_sequence(&resolved, IdentityKind::Primary), None,);
}

#[test]
fn apply_copy_matches_the_approved_transcript() {
    assert_eq!(
        APPLY_OPENING,
        "Applying identity, generating ECC key pair locally, then requesting and deploying certificate."
    );
    assert_eq!(NEW_NAME_FREE, "This new name is yours now.");
    assert_eq!(
        INSTALLED,
        "✔ Identity successfully installed on this device."
    );
}

#[test]
fn apply_always_requests_a_client_and_server_certificate() {
    assert_eq!(APPLY_CERTIFICATE_KIND, IdentityKind::Primary);
    assert_eq!(APPLY_CERTIFICATE_KIND.as_str(), "primary");
}

#[tokio::test]
async fn noninteractive_apply_does_not_create_server_configuration_or_default_files() {
    let fixture = ServerFixture::new("client").await;
    assert!(
        !offer_server_activation(&fixture.home, &fixture.target, false)
            .await
            .unwrap()
    );
    assert!(!fixture.profile().config_db_path().exists());
    assert!(
        !fixture
            .profile()
            .join(".volume/sys/setting/database")
            .exists()
    );
    assert!(!fixture.profile().join(".volume/sys/file").exists());
    assert!(!fixture.profile().join("file/welcome/index.html").exists());
}

#[tokio::test]
#[ignore = "requires matching PISHOO_BIN; run the cross-repository configuration tests"]
async fn noninteractive_apply_keeps_listening_disabled() {
    let fixture = ServerFixture::new("disabled").await;
    let profile = fixture.profile();
    let config = super::super::site::ServerConfig::for_profile(&profile);
    config.create_disabled().await.unwrap();
    assert!(
        !offer_server_activation(&fixture.home, &fixture.target, false)
            .await
            .unwrap()
    );
    assert_eq!(
        config.state().await.unwrap(),
        super::super::site::ServerConfigState::Disabled
    );
}

#[tokio::test]
#[ignore = "requires matching PISHOO_BIN; run the cross-repository configuration tests"]
async fn apply_keeps_an_enabled_pishoo_configuration() {
    let fixture = ServerFixture::new("enabled").await;
    let config = super::super::site::ServerConfig::for_profile(&fixture.profile());
    config.create_disabled().await.unwrap();
    config.enable().await.unwrap();
    for interactive in [false, true] {
        assert!(
            offer_server_activation(&fixture.home, &fixture.target, interactive)
                .await
                .unwrap()
        );
    }
    assert_eq!(
        config.state().await.unwrap(),
        super::super::site::ServerConfigState::Enabled
    );
}

#[tokio::test]
async fn installed_identity_survives_service_configuration_failure() {
    let fixture = ServerFixture::new("broken-service").await;
    let path = fixture.profile().join(".volume/sys/setting/database");
    std::fs::create_dir_all(&path).unwrap();
    assert!(
        !offer_server_activation(&fixture.home, &fixture.target, false)
            .await
            .unwrap()
    );
    assert!(path.is_dir());
}

#[test]
fn explicit_target_is_parsed_without_remote_preclassification() {
    assert_eq!(
        explicit_target_from_command(&command(Some("alice.smith")))
            .unwrap()
            .unwrap()
            .short_name(),
        "alice.smith"
    );
    assert!(
        explicit_target_from_command(&command(None))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn replacement_authorization_prevents_noninteractive_side_effects_without_force() {
    let ready = resolved_with(Some(LocalIdentityStatus::Ready {
        expires_at: 1_900_000_000,
    }));
    assert!(
        authorize_local_replacement(&ready, false, false)
            .await
            .is_err()
    );
    authorize_local_replacement(&ready, true, false)
        .await
        .unwrap();

    let invalid = resolved_with(Some(LocalIdentityStatus::Invalid {
        detail: "certificate is unreadable".to_string(),
    }));
    authorize_local_replacement(&invalid, false, false)
        .await
        .unwrap();
}

#[test]
fn missing_targets_are_replanned_to_the_safe_candidate_order() {
    let root = IdentityTarget::parse("alice.smith").unwrap();
    let child = IdentityTarget::parse("phone.alice.smith").unwrap();
    assert_eq!(
        super::super::auth_plan::candidate_specs(&root, RemoteTargetState::Missing),
        vec![super::super::auth_plan::AuthCandidateSpec::Email]
    );
    assert_eq!(
        super::super::auth_plan::candidate_specs(&child, RemoteTargetState::Missing),
        vec![
            super::super::auth_plan::AuthCandidateSpec::Identity(
                dhttp_identity::name::DhttpName::try_from("alice.smith")
                    .unwrap()
                    .into_owned()
            ),
            super::super::auth_plan::AuthCandidateSpec::Email,
        ]
    );
}

#[test]
fn explicit_targets_register_only_with_the_direct_parent_proof() {
    let root = IdentityTarget::parse("alice.smith").unwrap();
    let child = IdentityTarget::parse("phone.alice.smith").unwrap();

    assert!(!should_register_with_parent(
        &root,
        RemoteTargetState::Unknown,
        "alice.smith.dhttp.net",
    ));
    assert!(!should_register_with_parent(
        &child,
        RemoteTargetState::Unknown,
        "phone.alice.smith.dhttp.net",
    ));
    assert!(should_register_with_parent(
        &child,
        RemoteTargetState::Unknown,
        "alice.smith.dhttp.net",
    ));
    assert!(!should_register_with_parent(
        &child,
        RemoteTargetState::Exists,
        "alice.smith.dhttp.net",
    ));
    assert!(should_register_with_email(RemoteTargetState::Unknown));
    assert!(should_register_with_email(RemoteTargetState::Missing));
    assert!(!should_register_with_email(RemoteTargetState::Exists));
}
