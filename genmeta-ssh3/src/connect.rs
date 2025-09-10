use std::{backtrace::Backtrace, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use futures::StreamExt;
use genmeta_common::{h3_stream::H3Stream, *};
use gm_quic::{ConnectServerError, ParameterId, ToCertificate, handy::client_parameters};
use http::Uri;
use qdns::{HttpResolver, MdnsResolver, Resolvers, UdpResolver};
use qtraversal::iface::traversal_factory;
use snafu::prelude::*;
use ssh_config::genmeta::Profile;
use ssh3_proto::mux;
use tokio::{io, time};
use tokio_util::{codec, io::StreamReader};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to create DNS resolver: {source}"))]
    CreateDnsResolver {
        schema: &'static str,
        source: io::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Missing host in URI: {uri}"))]
    MissingServerName { uri: Uri, backtrace: Backtrace },
    #[snafu(display("No endpoints found for server '{server}'"))]
    NoEndpoints {
        server: String,
        backtrace: Backtrace,
    },
    #[snafu(transparent)]
    PickEndpoint {
        source: ConnectServerError,
        backtrace: Backtrace,
    },
    #[snafu(display("Connection timed out after {}ms for server '{server}'", duration.as_millis()))]
    Timedout {
        duration: Duration,
        server: String,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to initialize H3 connection: {source}"))]
    InitialH3 {
        source: h3::error::ConnectionError,
        backtrace: Backtrace,
    },

    #[snafu(display("H3 request failed: {source}"))]
    Request {
        source: h3::error::StreamError,
        backtrace: Backtrace,
    },

    #[snafu(display("H3 response failed: {source}"))]
    Response {
        source: h3::error::StreamError,
        backtrace: Backtrace,
    },

    #[snafu(display("Server returned error status: {status}"))]
    ResponseStatus {
        status: http::StatusCode,
        backtrace: Backtrace,
    },
}

pub type QuicConnection = Arc<gm_quic::Connection>;
pub type H3Connection = h3::client::Connection<h3_shim::QuicConnection, Bytes>;
pub type H3Client = h3::client::SendRequest<h3_shim::OpenStreams, Bytes>;

pub async fn connect(
    uri: &Uri,
    profile: Option<&Profile>,
) -> Result<
    (
        QuicConnection,
        H3Connection,
        H3Client,
        Arc<mux::Mux>,
        mux::Incomings,
    ),
    Error,
> {
    let resolvers = Resolvers::new()
        .with(Arc::new(
            HttpResolver::new(qdns::HTTP_DNS_SERVER)
                .context(CreateDnsResolverSnafu { schema: "http" })?,
        ))
        .with(Arc::new(
            MdnsResolver::new(qdns::MDNS_SERVICE)
                .context(CreateDnsResolverSnafu { schema: "mdns" })?,
        ))
        .with(Arc::new(UdpResolver::new(qdns::UDP_DNS_SERVER)));

    let server_name = uri
        .host()
        .context(MissingServerNameSnafu { uri: uri.clone() })?;

    let mut dns_lookup = resolvers.lookup(server_name);
    let (_source, server_eps) = dns_lookup.next().await.context(NoEndpointsSnafu {
        server: server_name.to_string(),
    })?;

    let quic_client = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ROOT_CERT.to_certificate());

        let factory = traversal_factory(&AGENTS);
        let mut parameters = client_parameters();

        match profile {
            Some(Profile { id, key, cert }) => {
                parameters
                    .set(ParameterId::ClientName, id.to_owned())
                    .unwrap();
                gm_quic::QuicClient::builder()
                    .with_root_certificates(roots)
                    .with_cert(cert.as_slice(), key.as_slice())
            }
            None => gm_quic::QuicClient::builder()
                .with_root_certificates(roots)
                .without_cert(),
        }
        .with_parameters(parameters)
        .with_iface_factory(factory.as_ref().clone())
        .bind(factory.devices().keys().map(|ip| SocketAddr::new(*ip, 0)))
        .enable_sslkeylog()
        .build()
    };

    let (quic_conn, h3_conn, mut h3_client) = {
        tracing::info!(target: "connect", server_name, ?server_eps, "attempt connect to server");
        let quic_connection = quic_client.connect(server_name, server_eps)?;
        tokio::spawn({
            let conn = quic_connection.clone();
            async move {
                let mut server_eps = dns_lookup
                    .map(|(_, server_eps)| futures::stream::iter(server_eps))
                    .flatten();
                while let Some(server_ep) = server_eps.next().await {
                    if conn.add_peer_endpoint(server_ep.into()).is_err() {
                        return;
                    }
                }
            }
        });
        let connect = h3::client::new(h3_shim::QuicConnection::new(quic_connection.clone()));
        let duration = Duration::from_secs(10);
        let (h3_conn, h3_client) = time::timeout(duration, connect)
            .await
            .map_err(|_| {
                quic_connection.close("connect timeout", 0);
                TimedoutSnafu::build(TimedoutSnafu {
                    duration,
                    server: server_name.to_string(),
                })
            })?
            .context(InitialH3Snafu)?;
        (quic_connection, h3_conn, h3_client)
    };

    let request = http::Request::builder()
        .method("PUT")
        .uri(uri)
        .body(())
        .unwrap();
    tracing::info!(target: "connect", ?request, "request");

    // sending request results in a bidirectional stream,
    // which is also used for receiving response
    let mut stream = h3_client
        .send_request(request)
        .await
        .context(RequestSnafu)?;
    let response = stream.recv_response().await.context(ResponseSnafu)?;
    tracing::info!(target: "connect", ?response, "Received");
    ensure!(
        response.status() == 200,
        ResponseStatusSnafu {
            status: response.status()
        }
    );

    let (sender, recver) = stream.split();
    let (mux, incomings) = mux::Mux::new(
        mux::Role::Client,
        codec::FramedRead::new(
            StreamReader::new(H3Stream::new(recver)),
            cbor_codec::CborDecoder::default(),
        ),
        codec::FramedWrite::new(
            h3_stream::H3Sink::new(sender),
            cbor_codec::CborEncoder::default(),
        ),
    );

    Ok((quic_conn, h3_conn, h3_client, mux, incomings))
}
