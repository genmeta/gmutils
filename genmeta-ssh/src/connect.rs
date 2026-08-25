use std::{sync::Arc, time::Duration};

use dhttp::{
    certificate::CertificateSequence,
    dquic,
    endpoint::Endpoint,
    h3x::{
        connection::{Connection, ConnectionBuilder},
        dhttp::{settings::Settings, webtransport::settings::WebTransportSupport},
    },
    identity::RemoteAuthorityCertificateExt as _,
};
use http::uri::Authority;
use snafu::prelude::*;

use crate::config::Config;

type DquicConnection = dquic::connection::Connection;
const SSH_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60);

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
    #[snafu(display("failed to read the connected server identity"))]
    RemoteAuthority {
        source: dhttp::h3x::quic::ConnectionError,
    },
    #[snafu(display("connected server did not provide a certificate identity"))]
    MissingRemoteAuthority,
    #[snafu(display("failed to read the primary sequence from the server certificate"))]
    PeerSequence {
        source: dhttp::identity::ExtractDhttpSubjectKeyIdentifierError,
    },
    #[snafu(display("failed to apply the server certificate sequence to `{authority}`"))]
    ApplyPeerSequence {
        authority: Authority,
        source: http::uri::InvalidUri,
    },
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

fn ssh_client_quic_config() -> dquic::client::ClientQuicConfig {
    let mut config = dhttp::trust::default_client_quic_config();
    config
        .parameters
        .set(
            dquic::qbase::param::ParameterId::MaxIdleTimeout,
            SSH_IDLE_TIMEOUT,
        )
        .expect("SSH idle timeout is a valid QUIC transport parameter");
    config
}

fn connect_path(uri: &http::Uri) -> &str {
    uri.path()
}

fn authority_with_sequence(
    authority: &Authority,
    sequence: CertificateSequence,
) -> Result<Authority, Error> {
    let authority_text = format!("{}:{}", authority.host(), sequence.get());
    authority_text
        .parse()
        .context(connect_error::ApplyPeerSequenceSnafu {
            authority: authority.clone(),
        })
}

async fn conversation_authority(
    connection: &Connection<DquicConnection>,
    requested: &Authority,
) -> Result<Authority, Error> {
    if requested.port().is_some() {
        return Ok(requested.clone());
    }

    let remote = connection
        .remote_authority()
        .await
        .context(connect_error::RemoteAuthoritySnafu)?
        .context(connect_error::MissingRemoteAuthoritySnafu)?;
    let ski = remote
        .dhttp_subject_key_identifier()
        .context(connect_error::PeerSequenceSnafu)?;

    authority_with_sequence(requested, ski.chain().sequence())
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
        .client(ssh_client_quic_config())
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
    let conversation_server = conversation_authority(&connection, server).await?;
    tracing::debug!(
        requested_server = %server,
        conversation_server = %conversation_server,
        "resolved SSH conversation authority from connected peer"
    );

    let conversation = dshell::webtransport::open_client_conversation(
        &connection,
        &conversation_server,
        connect_path(uri),
        None,
    )
    .await
    .context(connect_error::OpenConversationSnafu)?;

    tracing::debug!(
        requested_server = %server,
        conversation_server = %conversation_server,
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
    connect_with_endpoint(endpoint, &config.uri).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn ssh_client_uses_two_minute_idle_timeout() {
        let config = ssh_client_quic_config();

        assert_eq!(
            config
                .parameters
                .get::<Duration>(dquic::qbase::param::ParameterId::MaxIdleTimeout),
            Some(SSH_IDLE_TIMEOUT)
        );
    }

    #[test]
    fn connect_path_uses_uri_path_without_query() {
        let uri: http::Uri = "https://example.test/shell/test-user?debug=true"
            .parse()
            .expect("uri should parse");

        assert_eq!(connect_path(&uri), "/shell/test-user");
    }

    #[test]
    fn authority_with_sequence_applies_ddns_selected_peer_sequence() {
        let authority: Authority = "alice.device.dhttp.net".parse().unwrap();

        let selected = authority_with_sequence(&authority, CertificateSequence::from(2u8))
            .expect("peer sequence applies");

        assert_eq!(selected.as_str(), "alice.device.dhttp.net:2");
    }
}
