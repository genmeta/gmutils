use std::{sync::Arc, time::Duration};

use futures::{StreamExt, future, stream::FuturesUnordered};
use genmeta_ssh3_client as ssh3;
use gmdns::{
    H3_DNS_SERVER, HTTP_DNS_SERVER, MDNS_SERVICE,
    resolvers::{H3Resolver, HttpResolver, MdnsInterfaces, MdnsResolver, Resolvers},
};
use h3x::{
    connection::{Connection, OpenRequestStreamError},
    gm_quic::{
        self, BuildClientError, H3Client,
        prelude::{BindUri, ConnectServerError, handy::TracingLogger},
        qdns::SystemResolver,
        qinterface::device::Devices,
    },
    message::stream::{ReadStream, StreamError, WriteStream},
    pool::ConnectError,
};
use http::Uri;
use snafu::prelude::*;
use tokio::io;

use crate::config::Config;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to build H3 DNS client"))]
    BuildDnsClient { source: BuildClientError },
    #[snafu(display("failed to build H3 client"))]
    BuildClient { source: BuildClientError },
    #[snafu(display("failed to connect to server"))]
    Connect {
        source: ConnectError<ConnectServerError>,
    },
    #[snafu(display("request stream failed"))]
    RequestSteam { source: StreamError },
    #[snafu(display("response stream failed"))]
    ResponseSteam { source: StreamError },
    #[snafu(display("failed to send request"))]
    OpenRequestStream { source: OpenRequestStreamError },
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
    let mdns_interfaces = Arc::new(MdnsInterfaces::new());
    let mut resolvers = Resolvers::new()
        .with(mdns_interfaces.clone())
        .with(Arc::new(SystemResolver))
        .with(Arc::new(
            HttpResolver::new(HTTP_DNS_SERVER)
                .context(CreateDnsResolverSnafu { schema: "http" })?,
        ));

    match &config.id {
        Some(id) => {
            let h3_clinet = H3Client::builder()
                .with_identity(id.name().as_full(), id.certs(), id.key())
                .context(BuildDnsClientSnafu)?
                .build();
            // TODO: h3 connect will hang if the server doesn't respond, which will block the client client from starting
            // resolvers = resolvers.with(Arc::new(
            //     H3Resolver::new(H3_DNS_SERVER, h3_clinet)
            //         .context(CreateDnsResolverSnafu { schema: "h3" })?,
            // ));
        }
        None => {
            tracing::warn!("No client identity provided, H3 DNS resolver wll not work")
        }
    };

    let client = match &config.id {
        Some(id) => H3Client::builder().with_identity(id.name().as_full(), id.certs(), id.key()),
        None => H3Client::builder().without_identity(),
    }
    .context(BuildClientSnafu)?
    .with_resolver(Arc::new(resolvers))
    .with_qlog(Arc::new(TracingLogger))
    .build();

    let interfaces = Devices::global().interfaces();

    future::join_all(
        interfaces
            .iter()
            .filter(|(_, iface)| {
                iface.is_up() && (iface.is_physical() || iface.is_tun() || iface.is_loopback())
            })
            .flat_map(|(name, iface)| {
                [
                    iface.has_ipv4().then(|| format!("iface://v4.{name}:0")),
                    iface.has_ipv4().then(|| format!("iface://v6.{name}:0")),
                ]
            })
            .flatten()
            .map(|bind_uri| {
                BindUri::from(bind_uri)
                    .alloc_port()
                    .with_stun_server("1.12.74.4:20004")
            })
            .map(async |bind_uri| {
                let bind_interface = client.quic_clinet().bind(bind_uri.clone()).await;
                match bind_interface.with_components_mut(|components, iface| {
                    components
                        .try_init_with(|| MdnsResolver::from_iface(MDNS_SERVICE, iface))
                        .map(|_| ())
                }) {
                    Ok(()) => {
                        client.quic_clinet().bind(bind_uri).await;
                        mdns_interfaces.insert(bind_interface);
                    },
                    Err(error) => {
                        tracing::debug!(%error, %bind_uri, "Failed to create MDNS resolver for bind interface, skipping")
                    }
                };
            }),
    )
    .await;

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
        .context(RequestSteamSnafu)?;

    let response = read_stream
        .read_hyper_response_parts()
        .await
        .context(ResponseSteamSnafu)?;
    tracing::debug!(?response);
    ensure!(
        response.status == 200,
        ResponseStatusSnafu {
            status: response.status
        }
    );

    Ok((connection, read_stream, write_stream))
}
