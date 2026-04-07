use std::fmt;

use dhttp_home::{
    DhttpHome,
    identity::{IdentityHome, InvalidName, Name},
};
use http::{Uri, uri::InvalidUriParts};
use snafu::{Report, ResultExt, Snafu, whatever};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(whatever)]
    #[snafu(display("{message}"))]
    Whatever {
        message: String,
        #[snafu(source(from(Box<dyn std::error::Error + Send + Sync>, Some)))]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ExpandUriError {
    #[snafu(transparent)]
    InvalidName { source: InvalidName },

    #[snafu(display("failed to parse expanded authority `{authority}`"))]
    ParseAuthority {
        authority: String,
        source: http::uri::InvalidUri,
    },

    #[snafu(display("failed to reconstruct URI with expanded identity name"))]
    ReconstructUri { source: InvalidUriParts },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LoadHomeAndIdentityError {
    #[snafu(transparent)]
    LocateHome {
        source: dhttp_home::LocateDhttpHomeError,
    },
    #[snafu(transparent)]
    LoadIdentity { source: Error },
}

/// Load identity by a list of (source, name) pairs, and fallback to default identity if all specified identities failed to load.
pub async fn load_identity<'n>(
    dhttp_home: &DhttpHome,
    load_list: impl IntoIterator<Item = (&dyn fmt::Display, Name<'_>)>,
) -> Result<Option<IdentityHome>, Error> {
    if let Some((source, name)) = load_list.into_iter().next() {
        tracing::debug!("trying to load identity `{name}` specified by `{source}`");
        match dhttp_home.load_identity(name.borrow()).await {
            Ok(identity) => {
                tracing::debug!("identity `{name}` specified by `{source}` loaded");
                return Ok(Some(identity));
            }
            Err(_error) => {
                whatever!("failed to load identity `{name}` specified by `{source}`");
            }
        }
    }

    // no identity was specified, try to load the default identity
    match dhttp_home.load_default_identity().await {
        Ok(identity) => {
            tracing::debug!(
                "no identity specified, using default identity `{}`",
                identity.name()
            );
            Ok(Some(identity))
        }
        Err(error) => {
            tracing::debug!(
                "no identity specified, and default identity failed to load: {}",
                Report::from_error(error)
            );
            Ok(None)
        }
    }
}

/// Load [`DhttpHome`] and then attempt to load an [`Identity`] through
/// [`load_identity`].
///
/// When `dhttp_home_required` is `true`, a failure to locate `DHTTP_HOME`
/// is a hard error.  When `false`, the failure is logged as a warning and
/// `Ok(None)` is returned — the caller can still function without an identity.
///
/// Even when no explicit identity is listed in `load_list`, [`load_identity`]
/// will attempt to fall back to the default identity.
pub async fn load_home_and_identity<'n>(
    dhttp_home_required: bool,
    load_list: impl IntoIterator<Item = (&dyn fmt::Display, Name<'n>)>,
) -> Result<Option<IdentityHome>, LoadHomeAndIdentityError> {
    let dhttp_home = match DhttpHome::load_from_environment() {
        Ok(home) => home,
        Err(error) if !dhttp_home_required => {
            tracing::warn!(
                error = %Report::from_error(error),
                "failed to locate DHTTP_HOME, some features may not work"
            );
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };

    Ok(load_identity(&dhttp_home, load_list).await?)
}

pub fn expand_uri(uri: Uri) -> Result<Uri, ExpandUriError> {
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
                .context(expand_uri_error::ParseAuthoritySnafu { authority })?,
        );
    }

    Uri::from_parts(uri_parts).context(expand_uri_error::ReconstructUriSnafu)
}
