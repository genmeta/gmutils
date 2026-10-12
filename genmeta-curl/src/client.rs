use std::time::Duration;

use dhttp_home::{DhttpHome, identity::IdentityProfile};
use http::Uri;
use snafu::{IntoError, ResultExt, ensure};

use crate::{
    cli::Options,
    error::{self, Error},
};

#[allow(dead_code)]
pub(crate) struct ClientSession {
    pub(crate) endpoint: Option<dhttp::Endpoint>,
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
            .resolve_identity_profile((name.clone()).as_full())
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

pub(crate) fn normalize_cli_uri(uri: Uri, self_name: Option<&str>) -> Result<Uri, Error> {
    let uri = dhttp::expand_uri_with_base(self_name, uri).context(error::NormalizeUriSnafu)?;

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

    init_network(&options.dns, &options.binds)
        .await
        .context(error::BuildEndpointSnafu)?;
    let endpoint = match &identity_profile {
        Some(profile) => Some(
            dhttp::Endpoint::load_from_with_ocsp(profile.path())
                .await
                .context(error::BuildEndpointSnafu)?,
        ),
        None => None,
    };

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

async fn init_network(schemes: &[ddns::DnsScheme], binds: &[String]) -> dhttp::Result<()> {
    if binds.iter().any(|bind| bind != "*") {
        return Err(dhttp::Error::InvalidRequest {
            message: "the process-wide DHTTP network currently requires --interface '*'".into(),
        });
    }
    let mdns = ddns::install_resolvers(schemes)?;
    let network = dhttp::DhttpNetwork::init().await?;
    if let Some(mdns) = mdns {
        static MAINTENANCE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
        MAINTENANCE
            .get_or_try_init(|| async {
                mdns.maintain(std::time::Duration::from_secs(1), move || {
                    Ok(network
                        .active_bindings()
                        .map_err(std::io::Error::other)?
                        .into_iter()
                        .filter(|binding| {
                            dhttp::resolve::EndpointAddr::direct(binding.address).scope()
                                == Some(dhttp::Scope::Internal)
                        })
                        .map(|binding| {
                            ddns::mdns::MdnsBinding::new(binding.device, binding.address.ip())
                        })
                        .collect())
                })
                .await?;
                Ok::<(), std::io::Error>(())
            })
            .await?;
    }
    Ok(())
}
