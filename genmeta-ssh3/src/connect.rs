use std::{sync::Arc, time::Duration};

use futures::{StreamExt, stream::FuturesUnordered};
use genmeta_common::{
    bind::BindConflictError,
    dns::{self, DnsScheme},
};
use genmeta_ssh3_client as ssh3;
use gmdns::resolvers::{MdnsResolvers, Resolvers};
use h3x::{
    connection::{Connection, OpenRequestStreamError},
    gm_quic::{
        self, BuildClientError, H3Client,
        prelude::{
            ConnectServerError,
            handy::{DEFAULT_IO_FACTORY, TracingLogger},
        },
        qinterface::{device::Devices, manager::InterfaceManager},
    },
    message::stream::{ReadStream, StreamError, WriteStream},
    pool::ConnectError,
};
use http::Uri;
use qevent::telemetry::handy::NoopLogger;
use snafu::prelude::*;
use tokio::io;

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
    RequestSteam { source: StreamError },
    #[snafu(display("response stream failed"))]
    ResponseSteam { source: StreamError },
    #[snafu(display("failed to send request"))]
    OpenRequestStream { source: OpenRequestStreamError },
    #[snafu(display("failed to create DNS resolver"))]
    CreateDnsResolver {
        scheme: &'static str,
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
    let interfaces_monitor = Devices::global().monitor();

    let bind_uris = config
        .binds
        .to_bind_uris(interfaces_monitor.interfaces().keys().map(String::as_str))?;
    let iface_manager = Arc::new(InterfaceManager::new());
    let io_factory = Arc::new(DEFAULT_IO_FACTORY);
    let bind_interfaces = bind_uris
        .iter()
        .map(|bind_uri| iface_manager.bind(bind_uri.clone(), io_factory.clone()))
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;

    let mut resolvers = Resolvers::new();
    let mdns_resolvers = Arc::new(MdnsResolvers::new());
    for dns_scheme in config.dns.iter() {
        match dns_scheme {
            DnsScheme::System => {
                resolvers = resolvers.with(Arc::new(dns::handy::system_resolver()))
            }
            DnsScheme::Mdns => {
                mdns_resolvers.merge(&dns::handy::mdns_resolvers(bind_interfaces.iter().cloned()));
                resolvers = resolvers.with(mdns_resolvers.clone());
            }
            DnsScheme::Http => {
                resolvers = resolvers.with(Arc::new(dns::handy::http_resolver()));
            }
            DnsScheme::H3 => {
                let resolver = Arc::new(resolvers.clone());
                let resolver = dns::handy::h3_resolver(resolver, config.id.as_ref());
                resolvers = resolvers.with(Arc::new(resolver.context(BuildH3DnsClientSnafu)?));
            }
            DnsScheme::Dht => {
                unimplemented!("DHT resolver is not implemented yet");
            }
        }
    }

    let client = match &config.id {
        Some(id) => H3Client::builder().with_identity(id.name().as_full(), id.certs(), id.key()),
        None => H3Client::builder().without_identity(),
    }
    .context(BuildClientSnafu)?
    .with_iface_manager(iface_manager)
    .with_resolver(Arc::new(resolvers))
    .bind(&bind_uris)
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
