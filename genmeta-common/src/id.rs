use std::fmt;

use genmeta_home::{
    GenmetaHome,
    identity::{Identity, Name},
};
use snafu::Report;

/// Load identity by a list of (source, name) pairs, and fallback to default identity if all specified identities failed to load.
pub async fn load_id<'n>(
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
