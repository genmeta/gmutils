use std::{sync::Arc, time::Duration};

use dhttp::{
    endpoint::Endpoint,
    h3x::dhttp::message::{MessageReader, MessageWriter},
    home::{DhttpHome, identity::IdentityProfile},
    message::IntoUri,
};
use http::Uri;
use snafu::{IntoError, ResultExt, ensure};

use crate::{
    cli::Options,
    error::{self, Error},
    timing::Timing,
};

#[allow(dead_code)]
pub(crate) struct ClientSession {
    pub(crate) endpoint: Arc<Endpoint>,
    pub(crate) identity_profile: Option<IdentityProfile>,
    pub(crate) connect_timeout: Duration,
}

async fn load_identity_profile(options: &Options) -> Result<Option<IdentityProfile>, Error> {
    if options.anonymous {
        return Ok(None);
    }

    let home = match DhttpHome::load(options.home_scope()) {
        Ok(home) => home,
        Err(source) if options.id.is_none() => {
            tracing::warn!(
                error = %snafu::Report::from_error(&source),
                "failed to load dhttp home, using anonymous endpoint"
            );
            return Ok(None);
        }
        Err(source) => return Err(error::LoadDhttpHomeSnafu.into_error(source)),
    };

    if let Some(name) = &options.id {
        tracing::debug!(%name, "trying to load command line identity");
        return home
            .resolve_identity_profile(name.clone())
            .await
            .context(error::LoadExplicitIdentitySnafu { name: name.clone() })
            .map(Some);
    }

    match home.resolve_default_identity_profile().await {
        Ok(identity) => {
            tracing::debug!(name = %identity.name(), "using default identity");
            Ok(Some(identity))
        }
        Err(source) => {
            tracing::debug!(
                error = %snafu::Report::from_error(&source),
                "failed to load default identity, using anonymous endpoint"
            );
            Ok(None)
        }
    }
}

pub(crate) fn normalize_cli_uri(
    uri: Uri,
    self_name: Option<&dhttp::name::DhttpName<'_>>,
) -> Result<Uri, Error> {
    let uri = uri.into_uri(self_name).context(error::NormalizeUriSnafu)?;

    let mut parts = uri.into_parts();
    if parts.scheme.is_none() && parts.authority.is_some() && parts.path_and_query.is_none() {
        parts.scheme = Some(http::uri::Scheme::HTTPS);
        parts.path_and_query = Some(http::uri::PathAndQuery::from_static("/"));
    }

    Uri::from_parts(parts).context(error::ConstructRequestUriSnafu)
}

pub(crate) async fn setup_client(options: &mut Options) -> Result<ClientSession, Error> {
    let identity_profile = load_identity_profile(options).await?;

    // Normalize DHTTP shorthand in URI using loaded identity (--id > default identity).
    options.uri = normalize_cli_uri(
        options.uri.clone(),
        identity_profile.as_ref().map(|id| id.name()),
    )?;
    ensure!(
        options.uri.authority().is_some(),
        error::MissingAuthoritySnafu
    );

    // TODO(-4/-6): the previous address-family filter here (applied post-
    // expansion on `BindUri`s) was a no-op in practice — it restricted the
    // watcher's "initial known set" but not the actual bindings, and it
    // silently rejected all `iface://` URIs because the predicate only
    // considered `inet://` addresses. Reintroduce this feature at the
    // `Bind` pattern level (e.g. drop binds whose explicit family tag
    // mismatches the requested `-4`/`-6`) rather than post-expansion when
    // it's needed again.
    let identity = match &identity_profile {
        Some(profile) => Some(Arc::new(
            profile
                .load_identity()
                .await
                .context(error::LoadIdentitySslSnafu)?,
        )),
        None => None,
    };

    let mut builder = Endpoint::builder()
        .bind(Arc::new(options.binds.clone()))
        .maybe_identity(identity);
    for scheme in options.dns.iter().copied() {
        builder = builder.dns(scheme);
    }
    let endpoint = Arc::new(builder.build().await.context(error::BuildEndpointSnafu)?);

    let connect_timeout = connect_timeout_from_secs(options.connect_timeout);

    Ok(ClientSession {
        endpoint,
        identity_profile,
        connect_timeout,
    })
}

pub(crate) fn connect_timeout_from_secs(seconds: u64) -> Duration {
    if seconds == 0 {
        Duration::MAX
    } else {
        Duration::from_secs(seconds)
    }
}

pub(crate) async fn connect_and_open_streams(
    session: &ClientSession,
    uri: &Uri,
    timing: &mut Timing,
) -> Result<(MessageReader, MessageWriter), Error> {
    let connect_fut = async {
        session
            .endpoint
            .connect(
                uri.authority()
                    .expect("BUG: URI authority already validated")
                    .clone(),
            )
            .await
            .context(error::ConnectSnafu)
    };
    let connection = match tokio::time::timeout(session.connect_timeout, connect_fut).await {
        Ok(result) => result?,
        Err(_) => return error::TimedoutSnafu.fail(),
    };
    timing.mark_connected();
    connection
        .initial_message_stream()
        .await
        .context(error::InitialMessageStreamSnafu)
}
