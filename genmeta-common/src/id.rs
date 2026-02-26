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
    let mut tried_sepcified = false;
    for (source, name) in load_list {
        tried_sepcified = true;
        tracing::debug!("Try to load identity `{name}` sepcified by `{source}`");
        match genmeta_home.identities().load(name.borrow()).await {
            Ok(identity) => {
                if tried_sepcified {
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
        Ok(identity) if tried_sepcified => {
            tracing::warn!(
                "All specified identities failed to load, use default identity `{}`",
                identity.name()
            );
            Some(identity)
        }
        Ok(identity) => {
            tracing::debug!(
                "No identity specified, use default identity `{}`",
                identity.name()
            );
            Some(identity)
        }
        Err(error) if tried_sepcified => {
            tracing::warn!(
                "All specified identities failed to load, and default identity failed to load: {}",
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
