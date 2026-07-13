use std::sync::Arc;

use dhttp::{
    certificate::{CertificateChainKind, DhttpSubjectKeyIdentifier},
    name::DhttpName,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::danger::ClientCertVerifier,
};
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use x509_parser::{
    extensions::GeneralName,
    prelude::{FromDer, X509Certificate},
};

use crate::cert_server::CertificateDetail;

#[derive(Debug, Clone)]
pub(crate) struct InstallExpectation<'a> {
    pub(crate) target: DhttpName<'a>,
    pub(crate) kind: CertificateChainKind,
    pub(crate) sequence: Option<u32>,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(display(
        "certificate response target name {actual} does not match expected target name {expected}"
    ))]
    ResponseTargetName { expected: String, actual: String },
    #[snafu(display(
        "certificate response usage {actual} does not match expected usage {expected}"
    ))]
    ResponseUsage { expected: String, actual: String },
    #[snafu(display(
        "certificate response sequence {actual} does not match expected sequence {expected}"
    ))]
    ResponseSequence { expected: u32, actual: u32 },
    #[snafu(display("certificate response is missing DHTTP certificate metadata"))]
    MissingResponseMetadata,
    #[snafu(display("certificate response contains invalid DHTTP certificate metadata"))]
    InvalidResponseMetadata {
        source: dhttp::certificate::InvalidDhttpSubjectKeyIdentifier,
    },
    #[snafu(display("certificate response DHTTP certificate metadata does not match the leaf"))]
    ResponseMetadataMismatch,
    #[snafu(display("failed to parse certificate PEM chain"))]
    ParseCertificatePem {
        source: rustls::pki_types::pem::Error,
    },
    #[snafu(display("certificate PEM chain is empty"))]
    EmptyCertificateChain,
    #[snafu(display("failed to parse leaf certificate"))]
    ParseLeafCertificate {
        source: x509_parser::nom::Err<x509_parser::error::X509Error>,
    },
    #[snafu(display("failed to parse leaf certificate subject alternative names"))]
    ParseSubjectAlternativeName {
        source: x509_parser::error::X509Error,
    },
    #[snafu(display("leaf certificate does not contain expected target name {target}"))]
    MissingTargetName { target: String },
    #[snafu(display("leaf certificate is missing or has invalid DHTTP certificate metadata"))]
    LeafMetadata {
        source: dhttp::identity::ExtractDhttpSubjectKeyIdentifierError,
    },
    #[snafu(display("leaf DHTTP certificate metadata usage does not match the response"))]
    LeafMetadataUsage,
    #[snafu(display("leaf DHTTP certificate metadata sequence does not match the response"))]
    LeafMetadataSequence,
    #[snafu(display("failed to parse generated private key"))]
    ParsePrivateKey {
        source: rustls::pki_types::pem::Error,
    },
    #[snafu(display("failed to compare generated private key with leaf certificate"))]
    ComparePrivateKey {
        source: crate::local_identity::Error,
    },
    #[snafu(display("leaf certificate does not match the generated private key"))]
    PrivateKeyMismatch,
    #[snafu(display("certificate chain is not trusted by the DHTTP root"))]
    UntrustedCertificate { source: rustls::Error },
    #[snafu(display("failed to install validated identity"))]
    SaveIdentity {
        source: dhttp::home::identity::ssl::SaveIdentityError,
    },
}

fn parse_kind(kind: &str) -> Option<CertificateChainKind> {
    match kind {
        "primary" => Some(CertificateChainKind::Primary),
        "secondary" => Some(CertificateChainKind::Secondary),
        _ => None,
    }
}

pub(crate) fn validate_install(
    detail: &CertificateDetail,
    expected: &InstallExpectation<'_>,
    key_pem: &str,
) -> Result<(), Error> {
    let verifier =
        dhttp::trust::dhttp_client_cert_verifier(dhttp::trust::ClientIdentityPolicy::Required);
    validate_install_with_verifier(detail, expected, key_pem, verifier)
}

fn validate_install_with_verifier(
    detail: &CertificateDetail,
    expected: &InstallExpectation<'_>,
    key_pem: &str,
    verifier: Arc<dyn ClientCertVerifier>,
) -> Result<(), Error> {
    ensure!(
        detail.domain == expected.target.as_full(),
        error::ResponseTargetNameSnafu {
            expected: expected.target.as_full(),
            actual: &detail.domain,
        }
    );

    let detail_kind = parse_kind(&detail.kind).context(error::ResponseUsageSnafu {
        expected: expected.kind.as_str(),
        actual: &detail.kind,
    })?;
    ensure!(
        detail_kind == expected.kind,
        error::ResponseUsageSnafu {
            expected: expected.kind.as_str(),
            actual: &detail.kind,
        }
    );
    if let Some(expected_sequence) = expected.sequence {
        ensure!(
            detail.sequence == expected_sequence,
            error::ResponseSequenceSnafu {
                expected: expected_sequence,
                actual: detail.sequence,
            }
        );
    }

    let response_ski = detail
        .ski
        .as_deref()
        .context(error::MissingResponseMetadataSnafu)?;
    let response_ski =
        DhttpSubjectKeyIdentifier::try_from_subject_key_identifier_bytes(response_ski.as_bytes())
            .context(error::InvalidResponseMetadataSnafu)?;

    let certs = CertificateDer::pem_slice_iter(detail.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context(error::ParseCertificatePemSnafu)?;
    let leaf = certs.first().context(error::EmptyCertificateChainSnafu)?;
    let (_, leaf_certificate) =
        X509Certificate::from_der(leaf.as_ref()).context(error::ParseLeafCertificateSnafu)?;
    let subject_alternative_name = leaf_certificate
        .subject_alternative_name()
        .context(error::ParseSubjectAlternativeNameSnafu)?;
    let has_target_name = subject_alternative_name.as_ref().is_some_and(|extension| {
        extension.value.general_names.iter().any(|name| match name {
            GeneralName::DNSName(candidate) => candidate == &expected.target.as_full(),
            _ => false,
        })
    });
    ensure!(
        has_target_name,
        error::MissingTargetNameSnafu {
            target: expected.target.as_full(),
        }
    );

    let leaf_ski = dhttp::identity::extract_dhttp_subject_key_identifier(&certs)
        .context(error::LeafMetadataSnafu)?;
    ensure!(
        leaf_ski == response_ski,
        error::ResponseMetadataMismatchSnafu
    );
    ensure!(
        leaf_ski.chain().kind() == detail_kind,
        error::LeafMetadataUsageSnafu
    );
    ensure!(
        leaf_ski.chain().sequence().get() == detail.sequence,
        error::LeafMetadataSequenceSnafu
    );

    let private_key =
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).context(error::ParsePrivateKeySnafu)?;
    let key_matches = crate::local_identity::private_key_matches_certificate_der(
        private_key.secret_der(),
        leaf.as_ref(),
    )
    .context(error::ComparePrivateKeySnafu)?;
    ensure!(key_matches, error::PrivateKeyMismatchSnafu);

    verifier
        .verify_client_cert(leaf, &certs[1..], UnixTime::now())
        .context(error::UntrustedCertificateSnafu)?;
    Ok(())
}

pub(crate) async fn validate_and_save(
    dhttp_home: &dhttp::home::DhttpHome,
    detail: &CertificateDetail,
    expected: &InstallExpectation<'_>,
    key_pem: &str,
) -> Result<(), Error> {
    validate_install(detail, expected, key_pem)?;
    dhttp_home
        .identity_profile(expected.target.borrow())
        .save_identity(detail.cert_pem.as_bytes(), key_pem.as_bytes())
        .await
        .context(error::SaveIdentitySnafu)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::{RootCertStore, pki_types::CertificateDer, server::WebPkiClientVerifier};

    use super::*;

    const CHAIN: &str = include_str!("../../../tests/fixtures/install/chain.pem");
    const MALFORMED_SKI_CHAIN: &str =
        include_str!("../../../tests/fixtures/install/malformed-ski-chain.pem");
    const KEY: &str = include_str!("../../../tests/fixtures/install/leaf.key");
    const OTHER_KEY: &str = include_str!("../../../tests/fixtures/install/other.key");
    const ROOT: &[u8] = include_bytes!("../../../tests/fixtures/install/root.crt");
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
            kind: CertificateChainKind::Primary,
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
            kind: CertificateChainKind::Secondary,
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
        let home = dhttp::home::DhttpHome::new(home_path.clone());
        let name = DhttpName::try_from("alice.smith").unwrap();
        let mut invalid = detail();
        invalid.domain = "other.smith.dhttp.net".to_string();

        assert!(
            validate_and_save(&home, &invalid, &expectation(name.borrow()), KEY)
                .await
                .is_err()
        );
        assert!(!home_path.exists());
    }
}
