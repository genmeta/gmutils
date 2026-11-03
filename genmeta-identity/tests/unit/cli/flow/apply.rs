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
        developer: false,
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
}

#[tokio::test]
async fn ordinary_apply_tries_saved_identity_proofs_before_email() {
    struct Loader(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
    impl super::super::auth_plan::ExactIdentityLoader for Loader {
        async fn load_exact(
            &mut self,
            name: dhttp_identity::name::DhttpName<'_>,
        ) -> Result<Option<LocalIdentitySummary>, Error> {
            self.0.lock().unwrap().push(name.as_full().to_owned());
            Ok(None)
        }
    }
    _ = rustls::crypto::ring::default_provider().install_default();
    let cert_server = CertServer::new("http://127.0.0.1:1").unwrap();
    for name in ["alice.smith", "phone.alice.smith"] {
        let target = IdentityTarget::parse(name).unwrap();
        let mut resolved = ResolvedApplyTarget {
            target: target.clone(),
            remote: RemoteTargetState::Unknown,
            local: None,
        };
        let command = command(Some(name));
        let mut key_material =
            super::super::key_material::LazyKeyMaterial::for_name(target.dhttp_name());
        let requested = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let error = attempt_apply_with_candidates(
            &mut resolved,
            ApplyAttemptContext {
                command: &command,
                cert_server: &cert_server,
                kind: APPLY_CERTIFICATE_KIND,
                device_name: "test",
                interactive: false,
                key_material: &mut key_material,
                renewal_operation_key: None,
            },
            Loader(requested.clone()),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Email verification requires an interactive terminal for this command."
        );
        let mut expected = vec![target.full_name().to_owned()];
        if let Some(parent) = target.parent() {
            expected.push(parent.as_full().to_owned());
        }
        assert_eq!(*requested.lock().unwrap(), expected);
    }
}

#[tokio::test]
async fn developer_apply_reaches_entitlement_without_ordinary_child_registration() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    _ = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cert_server =
        CertServer::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let mock = tokio::spawn(async move {
        let mut requests = Vec::new();
        let replies = [
            serde_json::json!({"email":"test@example.com", "access_token":"account", "token_expires_at":i64::MAX}),
            serde_json::json!({"items":[]}),
            serde_json::json!({"items":[]}),
        ];
        for reply in replies {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0; 4096];
                let count = socket.read(&mut bytes).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&bytes[..count]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")?
                                .trim()
                                .parse::<usize>()
                                .ok()
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(request).unwrap());
            let body = reply.to_string();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        }
        requests
    });
    let tmp = tempfile::tempdir().unwrap();
    let home = DhttpHome::new(tmp.path().to_path_buf());
    let mut command = command(Some("dev.alex.chen"));
    command.developer = true;
    command.email = Some("test@example.com".into());
    command.verify_code = Some("123456".into());
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        run(&command, &home, HomeScope::User, &cert_server),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        error.to_string().contains("no order was created"),
        "{error}"
    );
    let requests = mock.await.unwrap();
    assert!(requests[0].starts_with("POST /v2/user/login "));
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.starts_with("GET /v2/subscription?"))
    );
    let profile = home.identity_profile("dev.alex.chen").unwrap();
    assert!(
        crate::code_signing::directory(&profile)
            .join("apply.pending.json")
            .exists()
    );
    assert!(!profile.ssl_dir().exists());
}
