use std::{sync::Arc, time::Duration};

use genmeta_common::{
    bind::{self, BindConflictError},
    dns,
};
use genmeta_ssh3_client as ssh3;
use h3x::{
    connection::Connection,
    gm_quic::{self, BuildClientError, H3Client, prelude::ConnectServerError},
    message::stream::{InitialMessageStreamError, MessageStreamError, ReadStream, WriteStream},
    pool::ConnectError,
};
use http::Uri;
use qevent::telemetry::handy::NoopLogger;
use snafu::prelude::*;

use crate::config::Config;

#[derive(Debug, Snafu)]
#[snafu(module(connect_error))]
pub enum Error {
    #[snafu(transparent)]
    BindConflict { source: Box<BindConflictError> },
    #[snafu(display("failed to build DNS resolvers"))]
    BuildDnsResolvers { source: BuildClientError },
    #[snafu(display("failed to build HTTP/3 client"))]
    BuildClient { source: BuildClientError },
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
        Arc<Connection<gm_quic::prelude::Connection>>,
        ReadStream,
        WriteStream,
    ),
    Error,
> {
    let bind_setup = bind::setup_bind_interfaces_with(
        config.binds.clone(),
        dns::handy::ensure_default_mdns_prop,
    )
    .await?;

    let dns_setup = dns::handy::build_resolvers(
        config.dns.iter().copied(),
        &bind_setup.bind_interfaces,
        config.id.as_ref(),
    )
    .context(connect_error::BuildDnsResolversSnafu)?;

    let client = match &config.id {
        Some(id) => H3Client::builder().with_identity(id.name().as_full(), id.certs(), id.key()),
        None => H3Client::builder().without_identity(),
    }
    .context(connect_error::BuildClientSnafu)?
    .with_iface_manager(bind_setup.iface_manager)
    .with_resolver(Arc::new(dns_setup.resolvers))
    .bind(&bind_setup.bind_uris)
    .await
    .with_qlog(Arc::new(NoopLogger))
    .build();

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
        .method(ssh3::proto::v0::METHOD.clone())
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

    Ok((connection, read_stream, write_stream))
}
