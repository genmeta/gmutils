use std::{sync::Arc, time::Duration};

use genmeta_common::h3_client::{self, SetupH3ClientError};
use h3x::{
    connection::Connection,
    gm_quic::{self, prelude::ConnectServerError},
    message::stream::{InitialMessageStreamError, MessageStreamError, ReadStream, WriteStream},
    pool::ConnectError,
};
use http::Uri;
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
        source: ConnectError<ConnectServerError>,
    },
    #[snafu(display("request stream failed"))]
    RequestStream { source: MessageStreamError },
    #[snafu(display("response stream failed"))]
    ResponseStream { source: MessageStreamError },
    #[snafu(display("failed to send request"))]
    InitialMessageStream { source: InitialMessageStreamError },
    #[snafu(display("missing host in URI `{uri}`"))]
    MissingServerName { uri: Uri },
    #[snafu(display("connection timed out after {}ms for server `{server}`", connect_timeout.as_millis()))]
    Timedout {
        server: String,
        connect_timeout: Duration,
    },
    #[snafu(display("server returned error status: `{status}`"))]
    ResponseStatus { status: http::StatusCode },
    #[snafu(display("missing authority in URI `{uri}`"))]
    MissingAuthority { uri: Uri },
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

pub async fn connect(
    config: &Config,
) -> Result<
    (
        AbortOnDropHandle<()>,
        Arc<Connection<gm_quic::prelude::Connection>>,
        ReadStream,
        WriteStream,
    ),
    Error,
> {
    let dns_schemes: Vec<_> = config.dns.iter().copied().collect();

    let h3_setup = h3_client::setup_h3_client()
        .binds(&config.binds)
        .dns_schemes(&dns_schemes)
        .maybe_identity(config.id.as_ref())
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
        .context(connect_error::InitialMessageStreamSnafu)?;

    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(config.uri.clone())
        .body(())
        .whatever_context::<_, Error>("failed to build HTTP request")?;
    tracing::debug!(?request);
    write_stream
        .send_hyper_request_parts(request.into_parts().0)
        .await
        .context(connect_error::RequestStreamSnafu)?;

    let response = read_stream
        .read_hyper_response_parts()
        .await
        .context(connect_error::ResponseStreamSnafu)?;
    tracing::debug!(?response);
    ensure!(
        response.status == 200,
        connect_error::ResponseStatusSnafu {
            status: response.status
        }
    );

    Ok((watcher, connection, read_stream, write_stream))
}
