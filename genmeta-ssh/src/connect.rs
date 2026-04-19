use std::sync::Arc;

use bytes::Bytes;
use genmeta_common::h3_client::{self, SetupH3ClientError};
use genmeta_ssh_core as ssh3;
use h3x::{
    connection::{Connection, ConnectionBuilder},
    dquic::prelude,
    endpoint::ConnectError as EndpointConnectError,
    pool::ConnectError,
    qpack::field::Protocol,
    quic::GetStreamIdExt,
    stream_id::StreamId,
};
use http::StatusCode;
use http_body_util::Empty;
use snafu::prelude::*;
use tokio_util::task::AbortOnDropHandle;

use crate::config::Config;

#[derive(Debug, Snafu)]
#[snafu(module(connect_error))]
pub enum Error {
    #[snafu(transparent)]
    SetupH3Client { source: SetupH3ClientError },
    #[snafu(display("failed to connect to server"))]
    Connect {
        source: ConnectError<EndpointConnectError>,
    },
    #[snafu(display("authentication failed (HTTP 401)"))]
    AuthenticationFailed,
    #[snafu(display("server returned unexpected status: `{status}`"))]
    ResponseStatus { status: StatusCode },
    #[snafu(display("missing ssh-version response header"))]
    MissingSshVersion,
    #[snafu(display("server offered unsupported SSH version: `{version}`"))]
    UnsupportedVersion { version: String },
    #[snafu(display("failed to register SSH3 protocol for session"))]
    RegisterProtocol {
        source: ssh3::protocol::RegisterError,
    },
    #[snafu(display("missing authority in URI `{uri}`"))]
    MissingAuthority { uri: http::Uri },
    #[snafu(transparent)]
    Whatever { source: snafu::Whatever },
}

impl snafu::FromString for Error {
    type Source = <snafu::Whatever as snafu::FromString>::Source;

    fn without_source(message: String) -> Self {
        snafu::Whatever::without_source(message).into()
    }

    fn with_source(source: Self::Source, message: String) -> Self {
        snafu::Whatever::with_source(source, message).into()
    }
}

pub struct ConnectResult {
    pub watcher: AbortOnDropHandle<()>,
    pub connection: Arc<Connection<prelude::Connection>>,
    pub conversation: ssh3::conversation::Conversation<ssh3::protocol::ConversationHandle>,
}

pub async fn connect(config: &Config) -> Result<ConnectResult, Error> {
    let dns_schemes: Vec<_> = config.dns.iter().copied().collect();

    let connection_builder = Arc::new(
        ConnectionBuilder::new(Arc::default()).protocol(ssh3::protocol::Ssh3ProtocolFactory),
    );

    let h3_setup = h3_client::setup_h3_client()
        .binds(&config.binds)
        .dns_schemes(&dns_schemes)
        .maybe_identity(config.id.as_ref())
        .connection_builder(connection_builder)
        .call()
        .await?;

    let client = h3_setup.client;
    let watcher = h3_setup.watcher;

    let server = config.uri.authority().ok_or_else(|| {
        connect_error::MissingAuthoritySnafu {
            uri: config.uri.clone(),
        }
        .build()
    })?;
    let connection = client
        .connect(server.clone())
        .await
        .context(connect_error::ConnectSnafu)?;

    let (mut read_stream, mut write_stream) = connection
        .initial_message_stream()
        .await
        .whatever_context::<_, Error>("failed to open initial message stream")?;

    let conversation_id = write_stream
        .stream_id()
        .await
        .whatever_context::<_, Error>("failed to get stream ID")?
        .into_inner();

    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(config.uri.clone())
        .header("ssh-version", ssh3::constants::SSH_VERSION)
        .extension(Protocol::new("ssh3"))
        .body(Empty::<Bytes>::new())
        .whatever_context::<_, Error>("failed to build HTTP request")?;
    tracing::debug!(?request);

    write_stream
        .send_hyper_request(request)
        .await
        .whatever_context::<_, Error>("failed to send Extended CONNECT request")?;

    let mut response = read_stream
        .read_hyper_response_parts()
        .await
        .whatever_context::<_, Error>("failed to read HTTP response")?;

    while response.status.is_informational() {
        response = read_stream
            .read_hyper_response_parts()
            .await
            .whatever_context::<_, Error>("failed to read HTTP response")?;
    }
    tracing::debug!(?response);

    ensure!(
        response.status != StatusCode::UNAUTHORIZED,
        connect_error::AuthenticationFailedSnafu
    );
    ensure!(
        response.status == StatusCode::OK,
        connect_error::ResponseStatusSnafu {
            status: response.status
        }
    );

    let server_version = response
        .headers
        .get("ssh-version")
        .ok_or(Error::MissingSshVersion)?
        .to_str()
        .whatever_context::<_, Error>("invalid ssh-version header value")?
        .to_owned();

    ensure!(
        server_version == ssh3::constants::SSH_VERSION,
        connect_error::UnsupportedVersionSnafu {
            version: server_version
        }
    );

    tracing::debug!(
        server = %server,
        conversation_id,
        version = %server_version,
        "SSH3 connection established"
    );

    let session_id = StreamId::try_from(conversation_id)
        .whatever_context::<_, Error>("invalid stream ID for session")?;

    let handle = connection
        .protocol::<ssh3::protocol::Ssh3Protocol>()
        .whatever_context::<_, Error>("SSH3 protocol not registered on connection")?
        .register(session_id)
        .context(connect_error::RegisterProtocolSnafu)?;

    let control_reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>> =
        Box::pin(read_stream.into_box_reader());
    let control_writer: std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>> =
        Box::pin(write_stream.into_box_writer());

    let conversation = ssh3::conversation::Conversation::new(
        session_id,
        server_version,
        control_reader,
        control_writer,
        handle,
    );

    Ok(ConnectResult {
        watcher,
        connection,
        conversation,
    })
}
