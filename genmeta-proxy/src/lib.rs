use std::{mem, sync::Arc};

use clap::Parser;
use genmeta_common::{bind, dns, id};
use genmeta_home::identity::Name;
use h3x::gm_quic::{BuildClientError, H3Client, prelude::handy::NoopLogger};
use http_body_util::BodyExt;
use snafu::{ResultExt, Snafu};
use tokio::net::TcpListener;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    /// Proxy listen address
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: std::net::SocketAddr,

    /// Client identity for DHTTP/3 connections
    #[arg(long, value_name = "client_identity")]
    pub id: Option<Name<'static>>,

    /// DNS resolution schemes
    #[arg(long, value_name = "scheme", default_values = ["mdns", "http"], value_delimiter = ',', hide = cfg!(not(debug_assertions)))]
    pub dns: Vec<dns::DnsScheme>,

    /// Bind patterns for DHTTP/3 connections
    #[arg(long = "interface", value_name = "bind", default_value = "*", hide = cfg!(not(debug_assertions)))]
    pub binds: Vec<bind::Bind>,

    /// Show detailed request logging
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    LoadHomeAndIdentity {
        source: id::LoadHomeAndIdentityError,
    },

    #[snafu(transparent)]
    BindConflict { source: bind::BindConflictError },

    #[snafu(display("failed to build DNS resolvers"))]
    BuildDnsResolvers { source: BuildClientError },

    #[snafu(display("failed to build HTTP/3 client"))]
    BuildClient { source: BuildClientError },

    #[snafu(display("failed to bind proxy listener"))]
    BindListener { source: std::io::Error },

    #[snafu(display("failed to connect to tunnel target `{addr}`"))]
    TunnelConnect {
        addr: String,
        source: std::io::Error,
    },

    #[snafu(display("failed to upgrade tunnel connection"))]
    TunnelUpgrade { source: hyper::Error },

    #[snafu(display("failed to connect to `{addr}`"))]
    ForwardConnect {
        addr: String,
        source: std::io::Error,
    },

    #[snafu(display("failed to perform HTTP handshake with `{addr}`"))]
    ForwardHandshake { addr: String, source: hyper::Error },

    #[snafu(display("failed to send HTTP request"))]
    ForwardSendRequest { source: hyper::Error },

    #[snafu(display("missing host in request"))]
    ForwardMissingHost {},

    #[snafu(transparent)]
    Whatever { source: Box<snafu::Whatever> },
}

impl snafu::FromString for Error {
    type Source = <snafu::Whatever as snafu::FromString>::Source;

    fn without_source(message: String) -> Self {
        Error::Whatever {
            source: Box::new(snafu::Whatever::without_source(message)),
        }
    }

    fn with_source(source: Self::Source, message: String) -> Self {
        Error::Whatever {
            source: Box::new(snafu::Whatever::with_source(source, message)),
        }
    }
}
type BoxBody = http_body_util::combinators::UnsyncBoxBody<
    bytes::Bytes,
    Box<dyn std::error::Error + Send + Sync>,
>;

fn full_body(text: &'static str) -> BoxBody {
    http_body_util::Full::new(bytes::Bytes::from(text))
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn box_body<B>(body: B) -> BoxBody
where
    B: http_body_util::BodyExt<Data = bytes::Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    body.map_err(Into::into).boxed_unsync()
}

async fn handle_request(
    req: hyper::Request<hyper::body::Incoming>,
    client: &H3Client,
    router: &route::Router,
) -> Result<hyper::Response<BoxBody>, hyper::Error> {
    let route = router.classify(&req);
    tracing::info!(method = %req.method(), uri = %req.uri(), route = ?route, "proxy request");
    match route {
        route::Route::GenmetaPlainHttp { .. } => match h3_forward::forward_h3(req, client).await {
            Ok(resp) => {
                let (parts, body) = resp.into_parts();
                match body.collect().await {
                    Ok(collected) => {
                        let bytes = collected.to_bytes();
                        Ok(hyper::Response::from_parts(
                            parts,
                            http_body_util::Full::new(bytes)
                                .map_err(|never| match never {})
                                .boxed_unsync(),
                        ))
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "H3 forward body collect failed");
                        Ok(hyper::Response::builder()
                            .status(502)
                            .body(full_body("Bad Gateway"))
                            .expect("valid static response"))
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "H3 forward failed");
                Ok(hyper::Response::builder()
                    .status(502)
                    .body(full_body("Bad Gateway"))
                    .expect("valid static response"))
            }
        },
        route::Route::GenmetaConnect { .. } => Ok(hyper::Response::builder()
            .status(502)
            .body(full_body("HTTPS proxy to .genmeta.net not supported"))
            .expect("valid static response")),
        route::Route::TunnelConnect { authority } => {
            match tunnel::tunnel_connect(req, authority.as_str()).await {
                Ok(resp) => Ok(resp.map(box_body)),
                Err(e) => {
                    tracing::error!(error = %e, "Tunnel connect failed");
                    Ok(hyper::Response::builder()
                        .status(502)
                        .body(full_body("Bad Gateway"))
                        .expect("valid static response"))
                }
            }
        }
        route::Route::StandardForward { .. } => match forward::forward_http(req).await {
            Ok(resp) => Ok(resp.map(box_body)),
            Err(e) => {
                tracing::error!(error = %e, "HTTP forward failed");
                Ok(hyper::Response::builder()
                    .status(502)
                    .body(full_body("Bad Gateway"))
                    .expect("valid static response"))
            }
        },
    }
}

pub async fn run(mut options: Options) -> Result<(), Error> {
    let (stderr, _guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive("netlink_packet_route=error".parse().unwrap()),
        )
        .init();

    let id = id::load_home_and_identity(
        options.id.is_some(),
        options
            .id
            .as_ref()
            .map(|id| (&"command line option" as &dyn std::fmt::Display, id.clone())),
    )
    .await?;

    let bind_setup = bind::setup_bind_interfaces_with(
        bind::Binds::new(mem::take(&mut options.binds)),
        dns::handy::ensure_default_mdns_prop,
    )
    .await?;

    let dns_setup = dns::handy::build_resolvers(
        options.dns.iter().copied(),
        &bind_setup.bind_interfaces,
        id.as_ref(),
    )
    .context(BuildDnsResolversSnafu)?;

    let client = match &id {
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

    let listener = TcpListener::bind(options.listen)
        .await
        .context(BindListenerSnafu)?;

    tracing::info!(addr = %options.listen, "Proxy listening");

    let router = Arc::new(route::Router::new());
    let client = Arc::new(client);

    loop {
        let (stream, addr) = listener.accept().await.context(BindListenerSnafu)?;
        tracing::debug!(%addr, "accepted connection");
        let client = client.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req| {
                        let client = client.clone();
                        let router = router.clone();
                        async move { handle_request(req, &client, &router).await }
                    }),
                )
                .with_upgrades()
                .await
            {
                tracing::error!(error = %e, %addr, "connection error");
            }
        });
    }
}

pub mod forward;
pub mod h3_forward;
pub mod route;
pub mod tunnel;
