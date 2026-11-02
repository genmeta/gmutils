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
        .hint("Run genmeta identity developer NAME purchase --idempotency-key KEY, pay the invoice, then genmeta identity apply NAME --developer")),
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
    let credentials=genmeta_identity::code_signing::load(&profile,sequence).map_err(|e|Error::new("E_DEVELOPER_CERTIFICATE_REQUIRED",e).hint("Run genmeta identity developer NAME purchase --idempotency-key KEY, pay the invoice, then genmeta identity apply NAME --developer"))?;
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
