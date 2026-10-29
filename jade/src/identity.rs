//! Select existing DHTTP credentials without storing Jade-specific preferences.
use std::io::IsTerminal;

use dhttp_home::{DhttpHome, HomeScope};
use futures::StreamExt;

use crate::error::{Error, Result};

pub(crate) fn home() -> Result<DhttpHome> {
    DhttpHome::load(HomeScope::User).map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))
}

pub(crate) fn normalize(name: &str) -> Result<String> {
    dhttp_home::normalize_name(name).ok_or_else(|| {
        Error::new(
            "E_CONFIG_INVALID",
            format!("Invalid author identity: {name}"),
        )
    })
}

pub(crate) async fn select(
    explicit: Option<&str>,
    configured: Option<&str>,
    machine: bool,
) -> Result<String> {
    let configured = configured.map(normalize).transpose()?;
    let explicit = explicit.map(normalize).transpose()?;
    if let (Some(explicit), Some(configured)) = (&explicit, &configured)
        && explicit != configured
    {
        return Err(Error::new(
            "E_IDENTITY_MISMATCH",
            "--id differs from package.author",
        ));
    }
    let home = home()?;
    let selected = match explicit.or(configured) {
        Some(selected) => Some(selected),
        None => {
            if home.settings_path().try_exists()? {
                let settings = home
                    .load_settings()
                    .await
                    .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
                settings
                    .settings()
                    .default_identity_name()
                    .map(|name| name.as_full().to_owned())
            } else {
                None
            }
        }
    };
    if let Some(selected) = selected {
        developer_credentials(&home, &selected).await?;
        return Ok(selected);
    }
    let names = home.identity_profile_names();
    futures::pin_mut!(names);
    let mut candidates = Vec::new();
    while let Some(name) = names.next().await {
        let name = name.map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
        if developer_credentials(&home, &name).await.is_ok() {
            candidates.push(name);
        }
    }
    candidates.sort();
    candidates.dedup();
    match candidates.len() {
        0 => Err(Error::new(
            "E_IDENTITY_UNAVAILABLE",
            "No usable local developer credentials",
        )
        .hint("Run genmeta identity developer NAME purchase --idempotency-key KEY, pay the invoice, then genmeta identity developer NAME apply")),
        1 => Ok(candidates.remove(0)),
        _ if machine || !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() => Err(
            Error::new("E_IDENTITY_REQUIRED", "Select a signing identity")
                .hint("Run jade build --id NAME"),
        ),
        _ => inquire::Select::new(
            "Signing identity (local credentials available):",
            candidates,
        )
        .prompt()
        .map_err(|e| match e {
            inquire::InquireError::OperationCanceled
            | inquire::InquireError::OperationInterrupted => {
                Error::new("E_CANCELLED", "Identity selection cancelled")
            }
            _ => Error::new("E_IDENTITY_REQUIRED", e).hint("Run jade build --id NAME"),
        }),
    }
}

pub(crate) async fn tls_credentials(
    home: &DhttpHome,
    name: &str,
) -> Result<(
    Vec<qtls::CertificateDer<'static>>,
    qtls::PrivateKeyDer<'static>,
)> {
    let profile = home.resolve_identity_profile(name).await.map_err(|e| {
        Error::new(
            "E_IDENTITY_UNAVAILABLE",
            format!("Cannot find local credentials for {name}: {e}"),
        )
    })?;
    let certs = profile.load_certs().await.map_err(|e| {
        Error::new(
            "E_IDENTITY_UNAVAILABLE",
            format!("Cannot load local credentials for {name}: {e}"),
        )
    })?;
    let key = profile.load_key().await.map_err(|e| {
        Error::new(
            "E_IDENTITY_UNAVAILABLE",
            format!("Cannot load local credentials for {name}: {e}"),
        )
    })?;
    let verifier =
        dhttp::trust::dhttp_client_cert_verifier(dhttp::trust::ClientIdentityPolicy::Required);
    verifier
        .verify_client_cert(
            certs
                .first()
                .ok_or_else(|| Error::new("E_IDENTITY_UNAVAILABLE", "missing TLS certificate"))?,
            &certs[1..],
            rustls::pki_types::UnixTime::now(),
        )
        .map_err(|e| Error::new("E_IDENTITY_MISMATCH", e))?;
    let (_, certificate) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    if certificate.subject_alternative_name().map_err(|e|Error::new("E_IDENTITY_MISMATCH",e))?.is_none_or(|names|!names.value.general_names.iter().any(|entry|matches!(entry,x509_parser::extensions::GeneralName::DNSName(dns) if *dns==name))) {
        return Err(Error::new("E_IDENTITY_MISMATCH","TLS identity certificate differs from the package author"));
    }
    if !certificate.validity().is_valid() {
        return Err(Error::new(
            "E_IDENTITY_UNAVAILABLE",
            format!("TLS identity certificate for {name} is outside its validity period"),
        ));
    }
    let signer = qtls::default_provider()
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    let signature = signer
        .choose_scheme(&[
            qtls::SignatureScheme::RSA_PSS_SHA512,
            qtls::SignatureScheme::ECDSA_NISTP256_SHA256,
            qtls::SignatureScheme::ECDSA_NISTP384_SHA384,
            qtls::SignatureScheme::ED25519,
        ])
        .ok_or_else(|| Error::new("E_IDENTITY_UNAVAILABLE", "Unsupported local signing key"))?
        .sign(b"jade-local-credentials-v1\0")
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    if !dhttp_home::certificate::verify_signature(
        certificate.public_key().raw,
        b"jade-local-credentials-v1\0",
        &signature,
    )
    .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?
    {
        return Err(Error::new(
            "E_IDENTITY_UNAVAILABLE",
            "Local private key does not match its certificate",
        ));
    }
    Ok((certs, key))
}

pub(crate) async fn developer_credentials(
    home: &DhttpHome,
    name: &str,
) -> Result<(
    Vec<qtls::CertificateDer<'static>>,
    qtls::PrivateKeyDer<'static>,
)> {
    developer_credentials_sequence(home, name, None).await
}
pub(crate) async fn developer_credentials_sequence(
    home: &DhttpHome,
    name: &str,
    sequence: Option<u32>,
) -> Result<(
    Vec<qtls::CertificateDer<'static>>,
    qtls::PrivateKeyDer<'static>,
)> {
    let profile = home
        .resolve_identity_profile_exactly(name)
        .await
        .map_err(|_| {
            Error::new(
                "E_IDENTITY_UNAVAILABLE",
                format!("Cannot find local credentials for {name}"),
            )
        })?;
    let credentials=genmeta_identity::code_signing::load(&profile,sequence).map_err(|e|Error::new("E_DEVELOPER_CERTIFICATE_REQUIRED",e).hint("Run genmeta identity developer NAME purchase --idempotency-key KEY, pay the invoice, then genmeta identity developer NAME apply"))?;
    let chain = credentials
        .chain()
        .map_err(|e| Error::new("E_SIGNATURE_INVALID", e))?;
    Ok((
        chain,
        credentials
            .key()
            .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?,
    ))
}
