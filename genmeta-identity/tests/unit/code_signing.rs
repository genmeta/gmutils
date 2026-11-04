use super::*;
use crate::cert_server::{CertificateDetail, DeveloperCertificate, SigningCertificateStatus};
const DOMAIN: &str = "developer.dhttp.net";
fn fixture(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/code-signing")
            .join(name),
    )
    .unwrap()
}
fn root() -> Vec<u8> {
    parse_chain(&fixture("root.cert.pem")).unwrap()[0]
        .as_ref()
        .to_vec()
}
fn chain(name: &str) -> Vec<CertificateDer<'static>> {
    parse_chain(
        &(fixture(&format!("{name}.cert.pem"))
            + &fixture(if name == "tls" || name == "wrong-issuer" {
                "tls-issuer.cert.pem"
            } else {
                "code-issuer.cert.pem"
            })),
    )
    .unwrap()
}
fn status() -> SigningCertificateStatus {
    let mut s: SigningCertificateStatus =
        serde_json::from_str(&fixture("developer.status.json")).unwrap();
    s.checked_at = UnixTime::now().as_secs() as i64;
    s
}
#[test]
fn shared_vectors_enforce_profile_root_names_and_historical_time() {
    let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        status().valid_not_before as u64 + 60,
    ));
    assert!(verify_chain_with_root(&chain("developer"), DOMAIN, time, &root()).is_ok());
    assert!(
        verify_chain_with_root(&chain("developer"), DOMAIN, time, chain("tls")[1].as_ref())
            .is_err(),
        "an arbitrary issuer is not a trusted root"
    );
    for invalid in [
        "tls",
        "missing-eku",
        "any-eku",
        "wrong-issuer",
        "wrong-san",
        "expired",
    ] {
        assert!(
            verify_chain_with_root(&chain(invalid), DOMAIN, time, &root()).is_err(),
            "{invalid}"
        );
    }
    let expired_time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1719792000));
    assert!(
        verify_chain_with_root(&chain("expired"), DOMAIN, expired_time, &root()).is_ok(),
        "historical validation uses trusted publication time"
    );
    assert!(verify_chain_with_root(&chain("developer"), "other.dhttp.net", time, &root()).is_err());
}
#[test]
fn exact_status_binds_instance_issuer_owner_and_freshness() {
    let chain = chain("developer");
    let original = status();
    assert!(verify_status(&original, &chain, DOMAIN, true).is_ok());
    let mut s = original.clone();
    s.publication_allowed = false;
    assert!(verify_status(&s, &chain, DOMAIN, true).is_err());
    assert!(
        verify_status(&s, &chain, DOMAIN, false).is_ok(),
        "installation does not require current paid entitlement"
    );
    for which in 0..7 {
        let mut s = original.clone();
        match which {
            0 => s.revoked_at = Some(1),
            1 => s.issuer_status = "untrusted".into(),
            2 => s.checked_at -= 31,
            3 => s.fingerprint_sha256 = "0".repeat(64),
            4 => s.purpose = "tls".into(),
            5 => s.issuer_id = Some("0".repeat(64)),
            _ => s.sequence = 2,
        };
        assert!(
            verify_status(&s, &chain, DOMAIN, true).is_err(),
            "case {which}"
        );
    }
}
fn profile(root: &Path) -> IdentityProfile {
    let path = root.join("developer");
    fs::create_dir(&path).unwrap();
    IdentityProfile::try_from(path).unwrap()
}
#[test]
fn pending_survives_retries_and_preserves_tls_until_installation() {
    let tmp = tempfile::tempdir().unwrap();
    let p = profile(tmp.path());
    fs::create_dir(p.join("ssl")).unwrap();
    fs::write(p.join("ssl/privkey.pem"), b"TLS PRESERVED").unwrap();
    let _lock = lock(&p).unwrap();
    assert!(lock(&p).is_err());
    let pending = Pending::prepare(&p, Some(1)).unwrap();
    let again = Pending::prepare(&p, Some(1)).unwrap();
    assert_eq!(pending.operation_key(), again.operation_key());
    assert_eq!(pending.csr(), again.csr());
    assert_eq!(pending.key_pem, again.key_pem);
    let another = Pending::prepare(&p, Some(2)).unwrap();
    assert_ne!(pending.key_pem, another.key_pem);
    assert_ne!(pending.operation_key(), another.operation_key());
    assert_eq!(
        fs::read(p.join("ssl/privkey.pem")).unwrap(),
        b"TLS PRESERVED"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(directory(&p).join("renew-1.pending.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
#[tokio::test]
async fn completed_pending_installs_matching_key_certificate_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    let p = profile(tmp.path());
    let _lock = lock(&p).unwrap();
    fs::create_dir(p.ssl_dir()).unwrap();
    fs::write(p.cert_path(), fixture("tls.cert.pem")).unwrap();
    fs::write(p.key_path(), fixture("superseded.key.pem")).unwrap();
    let mut pending = Pending::prepare(&p, None).unwrap();
    pending.key_pem = fixture("developer.key.pem");
    let cert = DeveloperCertificate {
        purpose: "code_signing".into(),
        certificate: CertificateDetail {
            domain: DOMAIN.into(),
            device_name: None,
            sequence: 1,
            kind: "primary".into(),
            serial_number: Some("1000".into()),
            ski: Some(status().ski.unwrap()),
            ski_version: None,
            status: "active".into(),
            csr: pending.csr().into(),
            cert_pem: fixture("developer.cert.pem").to_owned() + &fixture("code-issuer.cert.pem"),
            issued_at: 0,
            valid_not_after: status().valid_not_after,
            created_at: 0,
        },
    };
    pending.persist(&p).unwrap();
    let mut invalid = cert.clone();
    invalid.certificate.domain = "other.dhttp.net".into();
    assert!(
        Pending::prepare(&p, None)
            .unwrap()
            .install_with_root(&p, &invalid, &root())
            .await
            .is_err()
    );
    assert_eq!(
        fs::read_to_string(p.cert_path()).unwrap(),
        fixture("tls.cert.pem")
    );
    assert_eq!(
        fs::read_to_string(p.key_path()).unwrap(),
        fixture("superseded.key.pem")
    );
    assert!(directory(&p).join("apply.pending.json").exists());
    pending.install_with_root(&p, &cert, &root()).await.unwrap();
    assert!(!directory(&p).join("apply.pending.json").exists());
    let saved = load_with_root(&p, Some(1), &root()).unwrap();
    assert_eq!(p.load_certs().await.unwrap(), saved.chain().unwrap());
    p.load_key().await.unwrap();
    assert!(!directory(&p).join("1").exists());
    saved.validate_with_root(DOMAIN, &root()).unwrap();
    let wrong = Credentials {
        cert_pem: saved.cert_pem.clone(),
        key_pem: fixture("superseded.key.pem"),
    };
    assert!(wrong.validate_with_root(DOMAIN, &root()).is_err());
}
#[test]
fn tls_only_and_symlinked_credentials_cannot_be_selected() {
    let tmp = tempfile::tempdir().unwrap();
    let p = profile(tmp.path());
    fs::create_dir(p.join("ssl")).unwrap();
    fs::write(p.join("ssl/fullchain.crt"), fixture("tls.cert.pem")).unwrap();
    assert!(load(&p, None).is_err());
    #[cfg(unix)]
    {
        fs::remove_file(p.cert_path()).unwrap();
        save_private(&p.key_path(), fixture("developer.key.pem").as_bytes()).unwrap();
        std::os::unix::fs::symlink(p.key_path(), p.cert_path()).unwrap();
        assert!(load(&p, Some(1)).is_err());
    }
}

async fn recover_committed_initial_issuance(use_server_error: bool) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let tmp = tempfile::tempdir().unwrap();
    let profile = profile(tmp.path());
    let _lock = lock(&profile).unwrap();
    let mut pending = Pending::prepare(&profile, None).unwrap();
    pending.key_pem = fixture("developer.key.pem");
    let key = p384::ecdsa::SigningKey::from_pkcs8_pem(&pending.key_pem).unwrap();
    let subject = format!("CN={DOMAIN}").parse().unwrap();
    let mut builder = RequestBuilder::new(subject, &key).unwrap();
    builder
        .add_extension(&x509_cert::ext::pkix::SubjectAltName(vec![
            x509_cert::ext::pkix::name::GeneralName::DnsName(
                x509_cert::der::asn1::Ia5String::new(DOMAIN).unwrap(),
            ),
        ]))
        .unwrap();
    pending.csr_pem = builder
        .build::<p384::ecdsa::DerSignature>()
        .unwrap()
        .to_pem(LineEnding::LF)
        .unwrap();
    pending.persist(&profile).unwrap();
    let csr = pending.csr_pem.clone();
    let original_key = pending.key_pem.clone();
    let detail = serde_json::json!({"purpose":"code_signing","domain":DOMAIN,"device_name":"test","sequence":1,"kind":"primary","serial_number":"1000","ski":status().ski,"ski_version":"v1","status":"active","csr":csr,"cert_pem":fixture("developer.cert.pem")+&fixture("code-issuer.cert.pem"),"issued_at":0,"valid_not_after":status().valid_not_after,"created_at":0});
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server =
        crate::cert_server::CertServer::new(format!("http://{}", listener.local_addr().unwrap()))
            .unwrap();
    let mock = tokio::spawn(async move {
        for step in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
                assert_ne!(n, 0);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("POST /v2/cert "));
            let body: serde_json::Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(body["csr"], detail["csr"]);
            if step == 0 {
                if use_server_error {
                    let body = r#"{"error":{"code":1412,"message":"response detail unavailable after commit"}}"#;
                    socket.write_all(format!("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                }
                continue;
            }
            let body = serde_json::to_string(&detail).unwrap();
            socket.write_all(format!("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
    });
    assert!(
        pending
            .request_certificate(&profile, &server, "account-token", "test")
            .await
            .is_err()
    );
    let mut restored = Pending::prepare(&profile, None).unwrap();
    assert!(restored.issuance_submitted);
    assert_eq!(restored.key_pem, original_key);
    let recovered = restored
        .request_certificate(&profile, &server, "account-token", "test")
        .await
        .unwrap();
    mock.await.unwrap();
    restored
        .install_with_root(&profile, &recovered, &root())
        .await
        .unwrap();
    let saved = load_with_root(&profile, None, &root()).unwrap();
    assert_eq!(saved.key_pem, original_key);
    saved.validate_with_root(DOMAIN, &root()).unwrap();
}

#[tokio::test]
async fn uncertain_issuance_retries_the_same_persisted_csr() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let tmp = tempfile::tempdir().unwrap();
    let profile = profile(tmp.path());
    let _lock = lock(&profile).unwrap();
    let mut pending = Pending::prepare(&profile, None).unwrap();
    pending.issuance_submitted = true;
    pending.persist(&profile).unwrap();
    let csr = pending.csr().to_owned();
    let key = pending.key_pem().to_owned();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server =
        crate::cert_server::CertServer::new(format!("http://{}", listener.local_addr().unwrap()))
            .unwrap();
    let expected = csr.clone();
    let mock = tokio::spawn(async move {
        for _ in 0..1 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let n = socket.read(&mut chunk).await.unwrap();
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
                assert_ne!(n, 0);
            }
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.starts_with("POST /v2/cert "));
            let request: serde_json::Value =
                serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(request["csr"], expected);
            let status = 503;
            let body = r#"{"error":{"code":1427,"message":"issuer unavailable"}}"#;
            socket.write_all(format!("HTTP/1.1 {status} response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
    });
    assert!(
        pending
            .request_certificate(&profile, &server, "account-token", "test")
            .await
            .is_err()
    );
    mock.await.unwrap();
    let restored = Pending::prepare(&profile, None).unwrap();
    assert_eq!(restored.csr(), csr);
    assert_eq!(restored.key_pem(), key);
}

#[test]
fn chain_allows_only_optional_exact_root_and_rejects_unrelated_tail() {
    let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        status().valid_not_before as u64 + 60,
    ));
    let root = root();
    let mut valid = chain("developer");
    valid.push(CertificateDer::from(root.clone()));
    assert!(verify_chain_with_root(&valid, DOMAIN, time, &root).is_ok());
    valid[2] = chain("tls")[1].clone();
    assert!(verify_chain_with_root(&valid, DOMAIN, time, &root).is_err());
    valid.push(CertificateDer::from(root.clone()));
    assert!(verify_chain_with_root(&valid, DOMAIN, time, &root).is_err());
}

#[tokio::test]
async fn a_lost_initial_issuance_response_replays_the_same_csr() {
    recover_committed_initial_issuance(false).await;
}
#[tokio::test]
async fn postcommit_503_preserves_submission_and_replays_the_same_csr() {
    recover_committed_initial_issuance(true).await;
}
#[test]
fn only_documented_precommit_refusals_clear_the_issuance_marker() {
    use crate::cert_server::Error;
    let error = |status, code: &str| Error::Api {
        status,
        code: code.into(),
        message: "test".into(),
    };
    assert!(issuance_definitely_rejected(&error(
        reqwest::StatusCode::PAYMENT_REQUIRED,
        "1428"
    )));
    assert!(issuance_definitely_rejected(&error(
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "1410"
    )));
    for status in [
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        reqwest::StatusCode::REQUEST_TIMEOUT,
    ] {
        assert!(!issuance_definitely_rejected(&error(status, "1412")));
    }
    assert!(!issuance_definitely_rejected(&error(
        reqwest::StatusCode::BAD_REQUEST,
        "9999"
    )));
}

#[test]
fn unified_identity_validates_for_tls_and_signing_and_loads_one_key_pair() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unified-developer");
    let issuer = fs::read_to_string(fixtures.join("issuer.cert.pem")).unwrap();
    let cert_pem = fs::read_to_string(fixtures.join("developer.cert.pem")).unwrap() + &issuer;
    let chain = parse_chain(&cert_pem).unwrap();
    let root = parse_chain(&fs::read_to_string(fixtures.join("root.cert.pem")).unwrap())
        .unwrap()
        .remove(0);
    verify_chain_with_root(&chain, DOMAIN, UnixTime::now(), root.as_ref()).unwrap();
    let anchor = webpki::anchor_from_trusted_cert(&root).unwrap();
    let leaf = webpki::EndEntityCert::try_from(&chain[0]).unwrap();
    for usage in [
        webpki::KeyUsage::server_auth(),
        webpki::KeyUsage::client_auth(),
    ] {
        leaf.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            std::slice::from_ref(&anchor),
            &chain[1..],
            UnixTime::now(),
            usage,
            None,
            None,
        )
        .unwrap();
    }
    let partial =
        parse_chain(&(fs::read_to_string(fixtures.join("partial.cert.pem")).unwrap() + &issuer))
            .unwrap();
    assert!(verify_chain_with_root(&partial, DOMAIN, UnixTime::now(), root.as_ref()).is_err());
    let tmp = tempfile::tempdir().unwrap();
    let p = IdentityProfile::try_from(tmp.path().join("developer")).unwrap();
    fs::create_dir_all(p.ssl_dir()).unwrap();
    fs::write(
        p.ssl_dir().join(dhttp_home::identity::ssl::CERT_FILE_NAME),
        &cert_pem,
    )
    .unwrap();
    save_private(
        &p.ssl_dir().join(dhttp_home::identity::ssl::KEY_FILE_NAME),
        &fs::read(fixtures.join("developer.key.pem")).unwrap(),
    )
    .unwrap();
    let credentials = load_with_root(&p, None, root.as_ref()).unwrap();
    assert_eq!(credentials.cert_pem, cert_pem);
    assert!(
        !directory(&p).exists(),
        "unified signing requires no independent credential directory"
    );
    assert!(load_with_root(&p, Some(999), root.as_ref()).is_err());
    let legacy = directory(&p).join("1");
    fs::create_dir_all(&legacy).unwrap();
    save_private(
        &legacy.join("credentials.json"),
        &serde_json::to_vec(&serde_json::json!({
            "cert_pem":credentials.cert_pem,"key_pem":credentials.key_pem,
        }))
        .unwrap(),
    )
    .unwrap();
    // A valid retired copy cannot hide a broken or missing installed SSL identity.
    save_private(&p.key_path(), fixture("superseded.key.pem").as_bytes()).unwrap();
    assert!(load_with_root(&p, None, root.as_ref()).is_err());
    fs::remove_dir_all(p.ssl_dir()).unwrap();
    assert!(load_with_root(&p, Some(1), root.as_ref()).is_err());
    assert!(legacy.join("credentials.json").exists());
}

#[test]
fn private_credentials_can_be_created_replaced_and_read_on_supported_platforms() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("credentials.json");
    save_private(&file, b"first credential").unwrap();
    save_private(&file, b"replacement credential").unwrap();
    assert_eq!(read_private(&file).unwrap(), b"replacement credential");
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 1);
}
