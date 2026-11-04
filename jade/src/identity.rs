//! Resolve package authors without loading credentials or storing Jade preferences.
use dhttp_home::{DhttpHome, HomeScope};

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

/// Validate an explicitly selected development child without rewriting its name.
pub(crate) fn developer_name(name: &str) -> Result<String> {
    let name = normalize(name)?;
    let child = name.strip_suffix(dhttp_home::DHTTP_SUFFIX).unwrap();
    if !child
        .strip_prefix("dev.")
        .is_some_and(|root| root.contains('.'))
    {
        return Err(Error::new(
            "E_IDENTITY_REQUIRED",
            "Select the actual development child with --id, for example dev.alex.chen",
        ));
    }
    Ok(name)
}

pub(crate) async fn select(explicit: Option<&str>, configured: Option<&str>) -> Result<String> {
    let configured = configured.map(normalize).transpose()?;
    let explicit = explicit.map(developer_name).transpose()?;
    if let (Some(explicit), Some(configured)) = (&explicit, &configured)
        && explicit != configured
    {
        return Err(Error::new(
            "E_IDENTITY_MISMATCH",
            "The developer identity selected by --id differs from package.author",
        ));
    }
    if let Some(selected) = explicit.or(configured) {
        return Ok(selected);
    }
    let home = home()?;
    default_developer_name(&home).await
}

/// Only a default main identity selects a child; an existing dev child stays exact.
pub(crate) async fn default_developer_name(home: &DhttpHome) -> Result<String> {
    if home.settings_path().try_exists()? {
        let settings = home
            .load_settings()
            .await
            .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
        if let Some(name) = settings.settings().default_identity_name() {
            return match developer_name(name.as_full()) {
                Ok(name) => Ok(name),
                Err(_) => normalize(&format!("dev.{}", name.as_full())),
            };
        }
    }
    developer_name("dev.zero.ai")
}

#[cfg(test)]
#[path = "../tests/unit/identity.rs"]
mod tests;

/// Exact standard publishers retain the existing API and data namespace.
pub(crate) fn is_standard_author(author: &str) -> bool {
    matches!(author, "std.dhttp.net" | "dev.genmeta.tech.dhttp.net")
}
