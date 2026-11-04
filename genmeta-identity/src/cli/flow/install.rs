use std::sync::Arc;

use dhttp_identity::{certificate::DhttpSubjectKeyIdentifier, name::DhttpName};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::danger::ClientCertVerifier,
};
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use x509_parser::{
    extensions::GeneralName,
    prelude::{FromDer, X509Certificate},
};

use super::kind::IdentityKind;
use crate::cert_server::CertificateDetail;

#[derive(Debug, Clone)]
pub(crate) struct InstallExpectation<'a> {
    pub(crate) target: DhttpName<'a>,
    pub(crate) kind: IdentityKind,
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
    #[snafu(display("certificate response status {actual} is not active"))]
    ResponseStatus { actual: String },
    #[snafu(display("certificate response is missing DHTTP certificate metadata"))]
    MissingResponseMetadata,
    #[snafu(display("certificate response contains invalid DHTTP certificate metadata"))]
    InvalidResponseMetadata {
        source: dhttp_identity::certificate::InvalidDhttpSubjectKeyIdentifier,
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
        source: dhttp_identity::identity::ExtractDhttpSubjectKeyIdentifierError,
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
        source: dhttp_home::identity::ssl::SaveIdentityError,
    },
}

fn parse_kind(kind: &str) -> Option<IdentityKind> {
    kind.parse().ok()
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
    ensure!(
        detail.status == "active",
        error::ResponseStatusSnafu {
            actual: &detail.status,
        }
    );

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

    let leaf_ski = dhttp_identity::identity::extract_dhttp_subject_key_identifier(&certs)
        .context(error::LeafMetadataSnafu)?;
    ensure!(
        leaf_ski == response_ski,
        error::ResponseMetadataMismatchSnafu
    );
    ensure!(
        leaf_ski.chain().usage().kind_flag() == detail_kind.ski_flag(),
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
    dhttp_home: &dhttp_home::DhttpHome,
    detail: &CertificateDetail,
    expected: &InstallExpectation<'_>,
    key_pem: &str,
    action: dhttp::log::cert::CertificateAction,
) -> Result<(), Error> {
    validate_install(detail, expected, key_pem)?;
    let profile = dhttp_home
        .identity_profile((expected.target.borrow()).as_full())
        .expect("validated identity name");
    profile
        .save_identity(detail.cert_pem.as_bytes(), key_pem.as_bytes())
        .await
        .context(error::SaveIdentitySnafu)?;
    if let Err(error) = crate::cli::certificate_log::write_after_commit(&profile, action).await {
        tracing::warn!(
            identity = %profile.name(),
            error = %snafu::Report::from_error(&error),
            "failed to append certificate log after identity commit"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/install.rs"]
mod tests;
