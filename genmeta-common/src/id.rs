use std::fmt;

use genmeta_home::{
    GenmetaHome,
    identity::{Identity, InvalidName, Name},
};
use http::Uri;
use snafu::Report;

/// Load identity by a list of (source, name) pairs, and fallback to default identity if all specified identities failed to load.
pub async fn load_identity<'n>(
    genmeta_home: &GenmetaHome,
    load_list: impl IntoIterator<Item = (&dyn fmt::Display, Name<'_>)>,
) -> Option<Identity<'static>> {
    let mut tried_specified = false;
    for (source, name) in load_list {
        tried_specified = true;
        tracing::debug!("Trying to load identity `{name}` specified by `{source}`");
        match genmeta_home.identities().load(name.borrow()).await {
            Ok(identity) => {
                if tried_specified {
                    tracing::warn!("Identity `{name}` specified by `{source}` loaded");
                } else {
                    tracing::debug!("Identity `{name}` specified by `{source}` loaded");
                };
                return Some(identity);
            }
            Err(error) => {
                tracing::warn!(
                    "Failed to load identity `{name}` specified by `{source}`: {}",
                    Report::from_error(error)
                );
                continue;
            }
        }
    }

    // all specified identities failed to load, try to load the default identity
    match genmeta_home.identities().load_default_identity().await {
        Ok(identity) if tried_specified => {
            tracing::warn!(
                "All specified identities failed to load, using default identity `{}`",
                identity.name()
            );
            Some(identity)
        }
        Ok(identity) => {
            tracing::debug!(
                "No identity specified, using default identity `{}`",
                identity.name()
            );
            Some(identity)
        }
        Err(error) if tried_specified => {
            tracing::warn!(
                "All specified identities failed to load, and default identity also failed to load: {}",
                Report::from_error(error)
            );
            None
        }
        Err(error) => {
            tracing::debug!(
                "No identity specified, and default identity failed to load: {}",
                Report::from_error(error)
            );
            None
        }
    }
}

/// Load [`GenmetaHome`] and then attempt to load an [`Identity`] through
/// [`load_identity`].
///
/// When `genmeta_home_required` is `true`, a failure to locate `GENMETA_HOME`
/// is a hard error.  When `false`, the failure is logged as a warning and
/// `Ok(None)` is returned — the caller can still function without an identity.
///
/// Even when no explicit identity is listed in `load_list`, [`load_identity`]
/// will attempt to fall back to the default identity.
pub async fn load_home_and_identity<'n>(
    genmeta_home_required: bool,
    load_list: impl IntoIterator<Item = (&dyn fmt::Display, Name<'n>)>,
) -> Result<Option<Identity<'static>>, genmeta_home::LocateGenmetaHomeError> {
    let genmeta_home = match GenmetaHome::load_from_environment() {
        Ok(home) => home,
        Err(error) if !genmeta_home_required => {
            tracing::warn!(
                error = %Report::from_error(error),
                "Failed to locate GENMETA_HOME, some features may not work"
            );
            return Ok(None);
        }
        Err(error) => return Err(error),
    };

    Ok(load_identity(&genmeta_home, load_list).await)
}

pub fn expand_uri(uri: Uri) -> Result<Uri, InvalidName> {
    let mut uri_parts = uri.into_parts();

    if let Some(authority) = &uri_parts.authority
        && let Some(peer_name) = Name::try_expand_from(authority.host())?
        && peer_name.as_full() != authority.host()
    {
        let user_info_len = authority
            .as_str()
            .split_once('@')
            .map(|(user_info, ..)| user_info.len() + 1)
            .unwrap_or(0);
        let host_len = authority.host().len();

        let authority = format!(
            "{user_info}{host}{port}",
            user_info = &authority.as_str()[..user_info_len],
            host = peer_name,
            port = &authority.as_str()[user_info_len + host_len..]
        );
        uri_parts.authority = Some(
            authority
                .parse()
                .expect("failed to parse authority with expanded identity name"),
        );
    }

    Ok(Uri::from_parts(uri_parts).expect("failed to construct URI with expanded identity name"))
}
