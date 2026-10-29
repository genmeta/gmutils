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
fn pending_survives_retries_rotates_keys_and_never_overwrites_tls() {
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
#[test]
fn completed_pending_installs_matching_key_certificate_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    let p = profile(tmp.path());
    let _lock = lock(&p).unwrap();
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
    pending.install_with_root(&p, &cert, &root()).unwrap();
    assert!(!directory(&p).join("apply.pending.json").exists());
    let saved: Credentials =
        serde_json::from_slice(&read_private(&directory(&p).join("1/credentials.json")).unwrap())
            .unwrap();
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
        std::os::unix::fs::symlink(tmp.path(), directory(&p).join("1")).unwrap();
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
        let mut posts = 0;
        for step in 0..4 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
                if n == 0 {
                    break;
                }
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
            }
            let request = String::from_utf8(request).unwrap();
            if request.starts_with("POST ") {
                assert_eq!(step, 1);
                posts += 1;
                let body: serde_json::Value =
                    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
                assert_eq!(body["csr"], detail["csr"]);
                if use_server_error {
                    let body = r#"{"error":{"code":1412,"message":"response detail unavailable after commit"}}"#;
                    socket.write_all(format!("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                }
                continue;
            }
            let body = if step == 0 {
                serde_json::json!({"list":[],"pagination":{"page":1,"page_size":100,"total":0}})
            } else if step == 2 {
                serde_json::json!({"list":[{"domain":DOMAIN,"sequence":1,"kind":"primary","status":"active","serial_number":"1000","issued_at":0,"valid_not_after":detail["valid_not_after"],"created_at":0}],"pagination":{"page":1,"page_size":100,"total":1}})
            } else {
                detail.clone()
            };
            let body = serde_json::to_string(&body).unwrap();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
        posts
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
    assert_eq!(mock.await.unwrap(), 1);
    restored
        .install_with_root(&profile, &recovered, &root())
        .unwrap();
    let saved: Credentials = serde_json::from_slice(
        &read_private(&directory(&profile).join("1/credentials.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(saved.key_pem, original_key);
    saved.validate_with_root(DOMAIN, &root()).unwrap();
}

#[tokio::test]
async fn unknown_submission_without_a_listed_certificate_never_posts_again() {
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server =
        crate::cert_server::CertServer::new(format!("http://{}", listener.local_addr().unwrap()))
            .unwrap();
    let mock = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0u8; 4096];
        let n = socket.read(&mut bytes).await.unwrap();
        assert!(
            std::str::from_utf8(&bytes[..n])
                .unwrap()
                .starts_with("GET ")
        );
        let body = r#"{"list":[],"pagination":{"page":1,"page_size":100,"total":0}}"#;
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    });
    let error = pending
        .request_certificate(&profile, &server, "account-token", "test")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("No second issuance"));
    mock.await.unwrap();
    assert!(Pending::prepare(&profile, None).unwrap().issuance_submitted);
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
async fn a_lost_initial_issuance_response_recovers_csr_without_a_second_post() {
    recover_committed_initial_issuance(false).await;
}
#[tokio::test]
async fn postcommit_503_preserves_submission_and_recovers_without_a_second_post() {
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
