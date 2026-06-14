use std::sync::Arc;

use dhttp::{
    dquic,
    endpoint::Endpoint,
    h3x::{
        connection::{Connection, ConnectionBuilder},
        dhttp::{settings::Settings, webtransport::settings::WebTransportSupport},
    },
};
use dssh as ssh3;
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
        source: dhttp::endpoint::InvalidEndpointIdentityError,
    },
    #[snafu(display("failed to connect to server"))]
    Connect {
        source: dhttp::endpoint::ConnectError,
    },
    #[snafu(display("failed to wait for peer HTTP/3 settings before dssh webtransport connect"))]
    PeerSettings {
        source: dhttp::h3x::quic::ConnectionError,
    },
    #[snafu(display("failed to open dssh webtransport conversation"))]
    OpenConversation {
        source: ssh3::webtransport::ClientConnectConversationError,
    },
    #[snafu(display("missing authority in URI `{uri}`"))]
    MissingAuthority { uri: http::Uri },
}

pub struct ConnectResult {
    pub endpoint: Arc<Endpoint>,
    pub connection: Arc<Connection<DquicConnection>>,
    pub conversation: ssh3::conversation::Conversation,
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

pub async fn connect(config: &Config) -> Result<ConnectResult, Error> {
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

    let server = config.uri.authority().ok_or_else(|| {
        connect_error::MissingAuthoritySnafu {
            uri: config.uri.clone(),
        }
        .build()
    })?;
    let connection = endpoint
        .connect(server.clone())
        .await
        .context(connect_error::ConnectSnafu)?;

    connection
        .peer_settings()
        .await
        .context(connect_error::PeerSettingsSnafu)?;

    let conversation = ssh3::webtransport::open_client_conversation(
        &connection,
        server,
        connect_path(&config.uri),
        None,
    )
    .await
    .context(connect_error::OpenConversationSnafu)?;

    tracing::debug!(
        server = %server,
        conversation_id = %conversation.id(),
        version = %conversation.peer_version(),
        "dssh webtransport connection established"
    );

    Ok(ConnectResult {
        endpoint,
        connection,
        conversation,
    })
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
            "dssh client connections must route WebTransport streams"
        );
        assert!(
            !display.contains("Ssh3"),
            "dssh client connections must not register the legacy SSH3 stream protocol"
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
}
