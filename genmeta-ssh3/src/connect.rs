use std::{sync::Arc, time::Duration};

use genmeta_common::{
    bind::{self, BindConflictError},
    dns,
};
use genmeta_ssh3_client as ssh3;
use h3x::{
    connection::{Connection, OpenRequestStreamError},
    gm_quic::{self, BuildClientError, H3Client, prelude::ConnectServerError},
    message::stream::{ReadStream, StreamError, WriteStream},
    pool::ConnectError,
};
use http::Uri;
use qevent::telemetry::handy::NoopLogger;
use snafu::prelude::*;

use crate::config::Config;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    BindConflict { source: BindConflictError },
    #[snafu(display("failed to build H3 DNS client"))]
    BuildH3DnsClient { source: BuildClientError },
    #[snafu(display("failed to build H3 client"))]
    BuildClient { source: BuildClientError },
    #[snafu(display("failed to connect to server"))]
    Connect {
        source: ConnectError<ConnectServerError>,
    },
    #[snafu(display("request stream failed"))]
    RequestStream { source: StreamError },
    #[snafu(display("response stream failed"))]
    ResponseStream { source: StreamError },
    #[snafu(display("failed to send request"))]
    OpenRequestStream { source: OpenRequestStreamError },
    #[snafu(display("missing host in URI `{uri}`"))]
    MissingServerName { uri: Uri },
    #[snafu(display("connection timed out after {}ms for server `{server}`", connect_timeout.as_millis()))]
    Timedout {
        server: String,
        connect_timeout: Duration,
    },
    #[snafu(display("server returned error status: `{status}`"))]
    ResponseStatus { status: http::StatusCode },
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
    .context(BuildH3DnsClientSnafu)?;

    let client = match &config.id {
        Some(id) => H3Client::builder().with_identity(id.name().as_full(), id.certs(), id.key()),
        None => H3Client::builder().without_identity(),
    }
    .context(BuildClientSnafu)?
    .with_iface_manager(bind_setup.iface_manager)
    .with_resolver(Arc::new(dns_setup.resolvers))
    .bind(&bind_setup.bind_uris)
    .await
    .with_qlog(Arc::new(NoopLogger))
    .build();

    let server = config.uri.authority().expect("missing authority in URI");
    let connection = client.connect(server.clone()).await.context(ConnectSnafu)?;

    let (mut read_stream, mut write_stream) = connection
        .open_request_stream()
        .await
        .context(OpenRequestStreamSnafu)?;

    let request = http::Request::builder()
        .method(ssh3::proto::v0::METHOD.clone())
        .uri(config.uri.clone())
        .body(())
        .unwrap();
    tracing::debug!(?request);
    write_stream
        .send_hyper_request_parts(request.into_parts().0)
        .await
        .context(RequestStreamSnafu)?;

    let response = read_stream
        .read_hyper_response_parts()
        .await
        .context(ResponseStreamSnafu)?;
    tracing::debug!(?response);
    ensure!(
        response.status == 200,
        ResponseStatusSnafu {
            status: response.status
        }
    );

    Ok((connection, read_stream, write_stream))
}
