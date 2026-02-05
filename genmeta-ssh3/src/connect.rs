use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use genmeta_common::{
    connect::{
        H3ConnectionPool, ReusableConnection, h3,
        prelude::handy,
        qdns::{self, HttpResolver, Resolvers},
    },
    error::Whatever,
    h3_stream,
    h3_stream::{H3Sink, H3Stream},
};
use genmeta_ssh3_client as ssh3;
use http::Uri;
use snafu::prelude::*;
use tokio::io;
use tokio_util::io::StreamReader;

use crate::config::Config;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to create DNS resolver"))]
    CreateDnsResolver {
        schema: &'static str,
        source: io::Error,
    },
    #[snafu(display("missing host in URI `{uri}`"))]
    MissingServerName { uri: Uri },
    #[snafu(display("connection timed out after {}ms for server `{server}`", connect_timeout.as_millis()))]
    Timedout {
        server: String,
        connect_timeout: Duration,
    },
    #[snafu(transparent)]
    Connect { source: Whatever },

    #[snafu(display("h3 request failed"))]
    Request { source: h3::error::StreamError },

    #[snafu(display("h3 response failed"))]
    Response { source: h3::error::StreamError },

    #[snafu(display("server returned error status: `{status}`"))]
    ResponseStatus { status: http::StatusCode },
}

pub async fn connect(
    config: &Config,
) -> Result<
    (
        H3ConnectionPool,
        ReusableConnection,
        StreamReader<H3Stream, Bytes>,
        H3Sink,
    ),
    Error,
> {
    let resolvers = Resolvers::new()
        .with(Arc::new(
            HttpResolver::new(qdns::HTTP_DNS_SERVER)
                .context(CreateDnsResolverSnafu { schema: "http" })?,
        ))
        .with_mdns(qdns::MDNS_SERVICE)
        .0;

    let server_name = config.uri.host().context(MissingServerNameSnafu {
        uri: config.uri.clone(),
    })?;

    let pool = H3ConnectionPool::new(
        config.profile.as_ref(),
        handy::client_parameters(),
        Arc::new(handy::NoopLogger),
    );

    let mut connection = pool
        .connect(server_name, &resolvers, config.connect_timeout)
        .await?;

    let request = http::Request::builder()
        .method(ssh3::proto::v0::METHOD.clone())
        .uri(config.uri.clone())
        .body(())
        .unwrap();
    tracing::debug!(target: "connect", ?request);

    // sending request results in a bidirectional stream,
    // which is also used for receiving response
    let mut stream = connection
        .h3
        .send_request(request)
        .await
        .context(RequestSnafu)?;
    let response = stream.recv_response().await.context(ResponseSnafu)?;
    tracing::debug!(target: "connect", ?response);
    ensure!(
        response.status() == 200,
        ResponseStatusSnafu {
            status: response.status()
        }
    );

    let (sender, recver) = stream.split();
    Ok((
        pool,
        connection,
        StreamReader::new(H3Stream::new(recver)),
        h3_stream::H3Sink::new(sender),
    ))
}
