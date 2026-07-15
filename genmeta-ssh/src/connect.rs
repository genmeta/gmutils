use std::{num::NonZeroUsize, sync::Arc};

use dhttp::{
    ddns::resolvers::endpoint_candidates::{
        EndpointCandidates, EndpointLookup, ResolveEndpointCandidates,
    },
    dquic,
    endpoint::Endpoint,
    h3x::{
        connection::{Connection, ConnectionBuilder},
        dhttp::{settings::Settings, webtransport::settings::WebTransportSupport},
    },
};
use snafu::prelude::*;

use crate::config::Config;

type DquicConnection = dquic::connection::Connection;

#[derive(Debug, Snafu)]
#[snafu(module(connect_error))]
pub enum Error {
    #[snafu(display("failed to load identity certificate and key"))]
    LoadIdentitySsl {
        source: dhttp::home::identity::ssl::LoadIdentityError,
    },
    #[snafu(display("failed to build dhttp endpoint"))]
    BuildEndpoint {
        source: dhttp::endpoint::BuildEndpointError,
    },
    #[snafu(display("failed to connect to server"))]
    Connect {
        source: dhttp::endpoint::ConnectError,
    },
    #[snafu(display("failed to wait for peer HTTP/3 settings before dshell webtransport connect"))]
    PeerSettings {
        source: dhttp::h3x::quic::ConnectionError,
    },
    #[snafu(display("failed to open dshell webtransport conversation"))]
    OpenConversation {
        source: dshell::webtransport::ClientConnectConversationError,
    },
    #[snafu(display("missing authority in URI `{uri}`"))]
    MissingAuthority { uri: http::Uri },
    #[snafu(display("failed to choose primary sequence"))]
    ChooseSequence { source: crate::sequence::Error },
    #[snafu(display("endpoint resolver does not support primary sequence discovery"))]
    UnsupportedCandidateLookup,
    #[snafu(display("failed to lookup primary sequence candidates"))]
    LookupCandidates { source: std::io::Error },
    #[snafu(display("failed to rewrite target URI with selected primary sequence"))]
    RewriteSequence { source: crate::config::Error },
    #[snafu(display("failed to construct selected target URI"))]
    ConstructSelectedUri { source: http::uri::InvalidUriParts },
}

pub struct ConnectResult {
    pub endpoint: Arc<Endpoint>,
    pub connection: Arc<Connection<DquicConnection>>,
    pub conversation: dshell::conversation::Conversation,
}

fn connection_settings() -> Arc<Settings> {
    Arc::new(Settings::default().with_all(WebTransportSupport::default()))
}

fn connection_builder() -> Arc<ConnectionBuilder<DquicConnection>> {
    Arc::new(
        ConnectionBuilder::new(connection_settings())
            .protocol(dhttp::h3x::webtransport::WebTransportProtocolFactory),
    )
}

fn connect_path(uri: &http::Uri) -> &str {
    uri.path()
}

fn primary_discovery_lookup() -> EndpointLookup {
    EndpointLookup::all().with_record_limit(NonZeroUsize::MIN)
}

fn needs_primary_discovery(authority: &http::uri::Authority) -> bool {
    crate::config::authority_sequence(authority).is_none()
}

async fn lookup_primary_candidates<R>(
    resolver: &R,
    authority: &str,
) -> std::io::Result<EndpointCandidates>
where
    R: ResolveEndpointCandidates + ?Sized,
{
    resolver
        .lookup_endpoint_candidates(authority, primary_discovery_lookup())
        .await
}

pub async fn build_endpoint(config: &Config) -> Result<Arc<Endpoint>, Error> {
    let identity = match &config.id {
        Some(config) => Some(Arc::new(
            config
                .load_identity()
                .await
                .context(connect_error::LoadIdentitySslSnafu)?,
        )),
        None => None,
    };

    let mut builder = Endpoint::builder()
        .bind(Arc::new(config.binds.clone()))
        .maybe_identity(identity)
        .connection_builder(connection_builder());
    for scheme in config.dns.iter().copied() {
        builder = builder.dns(scheme);
    }
    let endpoint = Arc::new(
        builder
            .build()
            .await
            .context(connect_error::BuildEndpointSnafu)?,
    );
    Ok(endpoint)
}

async fn selected_uri(endpoint: &Endpoint, config: &Config) -> Result<http::Uri, Error> {
    let authority = config.uri.authority().ok_or_else(|| {
        connect_error::MissingAuthoritySnafu {
            uri: config.uri.clone(),
        }
        .build()
    })?;

    if !needs_primary_discovery(authority) {
        return Ok(config.uri.clone());
    }

    let resolver = endpoint.resolver();
    let any = resolver.as_ref() as &dyn std::any::Any;
    let candidates = if let Some(resolvers) = any.downcast_ref::<dhttp::ddns::resolvers::Resolvers>()
    {
        lookup_primary_candidates(resolvers, authority.as_str())
            .await
            .context(connect_error::LookupCandidatesSnafu)?
    } else if let Some(deferred) = any.downcast_ref::<
        dhttp::ddns::resolvers::deferred::DeferredResolver<dhttp::ddns::resolvers::Resolvers>,
    >() {
        lookup_primary_candidates(deferred, authority.as_str())
            .await
            .context(connect_error::LookupCandidatesSnafu)?
    } else {
        return connect_error::UnsupportedCandidateLookupSnafu.fail();
    };

    let certs = crate::sequence::fetch_cert_metadata(authority.host(), config.id.as_ref()).await;
    let rows = crate::sequence::merge_candidates(candidates, certs);
    let sequence = crate::sequence::choose_server_ranked(authority.host(), &rows)
        .context(connect_error::ChooseSequenceSnafu)?;

    let rewritten = crate::config::authority_with_sequence(authority, sequence)
        .context(connect_error::RewriteSequenceSnafu)?;
    let mut parts = config.uri.clone().into_parts();
    parts.authority = Some(rewritten);
    http::Uri::from_parts(parts).context(connect_error::ConstructSelectedUriSnafu)
}

async fn connect_with_endpoint(
    endpoint: Arc<Endpoint>,
    uri: &http::Uri,
) -> Result<ConnectResult, Error> {
    let server = uri
        .authority()
        .ok_or_else(|| connect_error::MissingAuthoritySnafu { uri: uri.clone() }.build())?;
    let connection = endpoint
        .connect(server.clone())
        .await
        .context(connect_error::ConnectSnafu)?;

    connection
        .peer_settings()
        .await
        .context(connect_error::PeerSettingsSnafu)?;

    let conversation = dshell::webtransport::open_client_conversation(
        &connection,
        server,
        connect_path(uri),
        None,
    )
    .await
    .context(connect_error::OpenConversationSnafu)?;

    tracing::debug!(
        server = %server,
        conversation_id = %conversation.id(),
        version = %conversation.peer_version(),
        "dshell webtransport connection established"
    );

    Ok(ConnectResult {
        endpoint,
        connection,
        conversation,
    })
}

pub async fn connect(config: &Config) -> Result<ConnectResult, Error> {
    let endpoint = build_endpoint(config).await?;
    let uri = selected_uri(&endpoint, config).await?;
    connect_with_endpoint(endpoint, &uri).await
}

#[cfg(test)]
mod tests {
    use std::{fmt, sync::Mutex};

    use dhttp::{
        ddns::resolvers::endpoint_candidates::{EndpointCandidateFuture, SequenceQuery},
        dquic::qresolve::{Resolve, ResolveFuture},
    };
    use futures::{FutureExt, StreamExt};

    use super::*;

    #[derive(Debug, Default)]
    struct RecordingResolver {
        requests: Mutex<Vec<(String, EndpointLookup)>>,
    }

    impl fmt::Display for RecordingResolver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("recording resolver")
        }
    }

    impl Resolve for RecordingResolver {
        fn lookup<'a>(&'a self, _name: &'a str) -> ResolveFuture<'a> {
            async { Ok(futures::stream::empty().boxed()) }.boxed()
        }
    }

    impl ResolveEndpointCandidates for RecordingResolver {
        fn lookup_endpoint_candidates<'a>(
            &'a self,
            name: &'a str,
            lookup: EndpointLookup,
        ) -> EndpointCandidateFuture<'a> {
            self.requests
                .lock()
                .unwrap()
                .push((name.to_owned(), lookup));
            async { Ok(EndpointCandidates::default()) }.boxed()
        }
    }

    #[test]
    fn connection_builder_registers_webtransport_protocol_layer() {
        let builder = connection_builder();
        let display = builder.to_string();

        assert!(
            display.contains("WebTransport"),
            "dshell client connections must route WebTransport streams"
        );
        assert!(
            !display.contains("Ssh3"),
            "dshell client connections must not register the legacy DShell stream protocol"
        );
    }

    #[test]
    fn connection_settings_advertise_webtransport_support() {
        let settings = connection_settings();

        assert!(settings.enable_connect_protocol());
        assert!(settings.enable_webtransport());
        assert!(settings.webtransport_flow_control_enabled());
    }

    #[test]
    fn connect_path_uses_uri_path_without_query() {
        let uri: http::Uri = "https://example.test/ssh/yiyue?debug=true"
            .parse()
            .expect("uri should parse");

        assert_eq!(connect_path(&uri), "/ssh/yiyue");
    }

    #[tokio::test]
    async fn primary_discovery_requests_all_sequences_with_one_record_each() {
        let resolver = RecordingResolver::default();

        lookup_primary_candidates(&resolver, "alice.device")
            .await
            .unwrap();

        let requests = resolver.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, "alice.device");
        assert_eq!(requests[0].1.sequences, SequenceQuery::All);
        assert_eq!(requests[0].1.record_limit, Some(NonZeroUsize::MIN));
    }

    #[test]
    fn explicit_sequence_authority_does_not_need_discovery() {
        let authority: http::uri::Authority = "alice.device:7".parse().unwrap();

        assert!(!needs_primary_discovery(&authority));
    }
}
