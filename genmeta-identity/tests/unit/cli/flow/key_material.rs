use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;

#[derive(Clone, Default)]
struct CountingGenerator {
    key_calls: Arc<AtomicUsize>,
    csr_calls: Arc<AtomicUsize>,
}

impl CountingGenerator {
    fn key_calls(&self) -> usize {
        self.key_calls.load(Ordering::SeqCst)
    }

    fn csr_calls(&self) -> usize {
        self.csr_calls.load(Ordering::SeqCst)
    }
}

impl KeyMaterialGenerator for CountingGenerator {
    fn generate_key(&self) -> Result<String, Error> {
        self.key_calls.fetch_add(1, Ordering::SeqCst);
        Ok("test-key".to_string())
    }

    fn generate_csr(&self, key_pem: &str, full_name: &str) -> Result<String, Error> {
        self.csr_calls.fetch_add(1, Ordering::SeqCst);
        Ok(format!("csr:{key_pem}:{full_name}"))
    }
}

#[test]
fn generated_csr_has_a_valid_p384_signature_and_requested_identity() {
    use x509_parser::{
        extensions::{GeneralName, ParsedExtension},
        prelude::FromDer,
    };

    let generator = P384Generator;
    let key = generator.generate_key().unwrap();
    let name = "alice.smith.dhttp.net";
    let pem = generator.generate_csr(&key, name).unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
            .unwrap();
    csr.verify_signature().unwrap();
    assert_eq!(
        csr.certification_request_info
            .subject
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap(),
        name
    );
    let san = csr
        .requested_extensions()
        .unwrap()
        .find_map(|extension| match extension {
            ParsedExtension::SubjectAlternativeName(san) => Some(san),
            _ => None,
        })
        .unwrap();
    assert_eq!(san.general_names, vec![GeneralName::DNSName(name)]);
    let key = p384::ecdsa::SigningKey::from_pkcs8_pem(&key).unwrap();
    assert_eq!(
        csr.certification_request_info.subject_pki.raw,
        key.verifying_key().to_public_key_der().unwrap().as_bytes()
    );
}

#[test]
fn lazy_material_generates_one_key_and_one_csr_across_retries() {
    let generator = CountingGenerator::default();
    let name = DhttpName::try_from("alice.smith").unwrap();
    let mut material = LazyKeyMaterial::new(name.borrow(), generator.clone());

    let first = material.csr_pem().unwrap().to_string();
    let second = material.csr_pem().unwrap().to_string();

    assert_eq!(first, second);
    assert_eq!(material.key_pem(), Some("test-key"));
    assert_eq!(generator.key_calls(), 1);
    assert_eq!(generator.csr_calls(), 1);
}

#[test]
fn constructing_lazy_material_has_no_crypto_side_effect() {
    let generator = CountingGenerator::default();
    let name = DhttpName::try_from("alice.smith").unwrap();
    let _material = LazyKeyMaterial::new(name.borrow(), generator.clone());

    assert_eq!(generator.key_calls(), 0);
    assert_eq!(generator.csr_calls(), 0);
}

#[tokio::test]
async fn pending_renewal_survives_reload_and_is_removed_after_install() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let home_path = std::env::temp_dir().join(format!(
        "genmeta-pending-renewal-{}-{nonce}",
        std::process::id()
    ));
    let home = DhttpHome::new(home_path.clone());
    let name = DhttpName::try_from("alice.smith").unwrap();
    tokio::fs::create_dir_all(
        home.identity_profile((name.borrow()).as_full())
            .expect("validated identity name")
            .path(),
    )
    .await
    .unwrap();

    let created = PendingRenewal::create(&home, name.borrow(), "primary", 7, "test laptop")
        .await
        .unwrap();
    let loaded = PendingRenewal::load(&home, name.borrow(), "primary", 7)
        .await
        .unwrap()
        .expect("pending renewal should be reloadable");

    assert_eq!(loaded.operation_key(), created.operation_key());
    assert_eq!(loaded.key_pem(), created.key_pem());
    assert_eq!(loaded.csr_pem(), created.csr_pem());
    assert_eq!(loaded.device_name(), "test laptop");

    loaded.remove(&home, name.borrow()).await.unwrap();
    assert!(
        PendingRenewal::load(&home, name.borrow(), "primary", 7)
            .await
            .unwrap()
            .is_none()
    );
    tokio::fs::remove_dir_all(home_path).await.unwrap();
}

#[test]
fn pending_renewal_rejects_an_operation_key_that_is_not_a_header_value() {
    let pending = PendingRenewal {
        target: "alice.smith".to_string(),
        kind: "primary".to_string(),
        sequence: 7,
        device_name: "test laptop".to_string(),
        operation_key: "renew-v1\ninvalid".to_string(),
        key_pem: "test-key".to_string(),
        csr_pem: "test-csr".to_string(),
    };

    let error = pending
        .validate(
            "alice.smith",
            "primary",
            7,
            std::path::Path::new(".renew-pending.json"),
        )
        .unwrap_err();

    assert!(error.to_string().contains("is incomplete"));
}

#[tokio::test]
async fn pending_renewal_can_be_cleared_before_installing_another_chain() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let home_path = std::env::temp_dir().join(format!(
        "genmeta-pending-renewal-clear-{}-{nonce}",
        std::process::id()
    ));
    let home = DhttpHome::new(home_path.clone());
    let name = DhttpName::try_from("alice.smith").unwrap();
    tokio::fs::create_dir_all(
        home.identity_profile((name.borrow()).as_full())
            .expect("validated identity name")
            .path(),
    )
    .await
    .unwrap();

    PendingRenewal::create(&home, name.borrow(), "primary", 7, "test laptop")
        .await
        .unwrap();
    PendingRenewal::remove_for_name(&home, name.borrow())
        .await
        .unwrap();

    assert!(
        PendingRenewal::load(&home, name.borrow(), "secondary", 0)
            .await
            .unwrap()
            .is_none()
    );
    tokio::fs::remove_dir_all(home_path).await.unwrap();
}
