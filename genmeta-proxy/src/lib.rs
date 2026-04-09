use std::{io::IsTerminal, mem, net::SocketAddr, sync::Arc};

use clap::Parser;
use dhttp_home::identity::Name;
use genmeta_common::{
    bind, dns,
    h3_client::{self, SetupH3ClientError},
    id,
};
use h3x::dquic::H3Client;
use http_body_util::BodyExt;
use snafu::{Report, ResultExt, Snafu};
use tokio::{net::TcpListener, task::JoinSet};
use tracing::Instrument;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    /// Proxy listen address patterns
    #[arg(long = "listen", value_name = "bind", default_values = ["127.0.0.1:16080", "[::1]:16080"])]
    pub listens: Vec<bind::Bind>,

    /// Client identity for DHTTP/3 connections
    #[arg(short, long, value_name = "client_identity")]
    pub id: Option<Name<'static>>,

    /// Skip identity loading and use anonymous mode
    #[arg(long, conflicts_with = "id")]
    pub anonymous: bool,

    /// DNS resolution schemes
    #[arg(long, value_name = "scheme", default_values = ["mdns", "h3"], value_delimiter = ',', hide = cfg!(not(debug_assertions)))]
    pub dns: Vec<dns::DnsScheme>,

    /// Bind patterns for DHTTP/3 connections
    #[arg(long = "interface", value_name = "bind", default_value = "*", hide = cfg!(not(debug_assertions)))]
    pub binds: Vec<bind::Bind>,

    /// Show detailed request logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Run as daemon (background process)
    #[arg(long)]
    pub daemon: bool,

    /// Log file path (write tracing output to this file instead of stderr)
    #[arg(long, value_name = "path")]
    pub log: Option<std::path::PathBuf>,
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(transparent)]
    LoadHomeAndIdentity {
        source: id::LoadHomeAndIdentityError,
    },

    #[snafu(transparent)]
    SetupH3Client { source: SetupH3ClientError },

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

    #[snafu(display("invalid host header"))]
    ForwardInvalidHost { source: hyper::header::ToStrError },

    #[snafu(display("failed to daemonize"))]
    Daemonize { source: daemonize::Error },

    #[snafu(display("failed to create log file `{}`", path.display()))]
    CreateLogFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },

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
    self_name: Option<&Name<'_>>,
) -> Result<hyper::Response<BoxBody>, hyper::Error> {
    let route = router.classify(&req);
    tracing::info!(method = %req.method(), uri = %req.uri(), route = ?route, "proxy request");
    match route {
        route::Route::GenmetaPlainHttp { .. } => {
            // Expand tilde in URI (e.g., reimu.pilot~ → reimu.pilot.genmeta.net,
            // bare ~ → self identity)
            let mut req = req;
            match id::expand_name_in_uri(req.uri().clone(), self_name) {
                Ok(uri) => *req.uri_mut() = uri,
                Err(e) => {
                    tracing::error!(error = %Report::from_error(&e), "failed to expand name in URI");
                    return Ok(hyper::Response::builder()
                        .status(502)
                        .body(full_body("Bad Gateway"))
                        .expect("valid static response"));
                }
            }
            match h3_forward::forward_h3(req, client).await {
                Ok(resp) => Ok(resp.map(box_body)),
                Err(e) => {
                    tracing::error!(error = %Report::from_error(&e), "h3 forward failed");
                    Ok(hyper::Response::builder()
                        .status(502)
                        .body(full_body("Bad Gateway"))
                        .expect("valid static response"))
                }
            }
        }
        route::Route::GenmetaConnect { .. } => Ok(hyper::Response::builder()
            .status(502)
            .body(full_body("HTTPS proxy to .genmeta.net not supported"))
            .expect("valid static response")),
        route::Route::TunnelConnect { authority } => {
            match tunnel::tunnel_connect(req, authority.as_str()).await {
                Ok(resp) => Ok(resp.map(box_body)),
                Err(e) => {
                    tracing::error!(error = %Report::from_error(&e), "tunnel connect failed");
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
                tracing::error!(error = %Report::from_error(&e), "http forward failed");
                Ok(hyper::Response::builder()
                    .status(502)
                    .body(full_body("Bad Gateway"))
                    .expect("valid static response"))
            }
        },
    }
}

/// Initialize tracing subscriber, optionally writing to a log file.
fn init_tracing(options: &Options) -> Result<tracing_appender::non_blocking::WorkerGuard, Error> {
    let (writer, guard) = if let Some(ref log_path) = options.log
        && !options.daemon
    {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .context(CreateLogFileSnafu {
                path: log_path.clone(),
            })?;
        tracing_appender::non_blocking(file)
    } else {
        tracing_appender::non_blocking(std::io::stderr())
    };
    let use_ansi = (options.log.is_none() || options.daemon) && std::io::stderr().is_terminal();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(use_ansi)
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(writer),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive(
                    "netlink_packet_route=error"
                        .parse()
                        .expect("BUG: static tracing directive is valid"),
                ),
        )
        .init();
    Ok(guard)
}

/// Bind TCP listeners on the configured listen addresses.
async fn bind_listeners(options: &Options) -> Result<Vec<TcpListener>, Error> {
    let mut listeners = Vec::new();
    for b in &options.listens {
        let ip = b.host.as_ip_addr().ok_or_else(|| {
            <Error as snafu::FromString>::without_source(format!(
                "listen bind `{}` must be a concrete IP address",
                b.host
            ))
        })?;
        let addr = SocketAddr::new(ip, b.effective_port());
        let listener = TcpListener::bind(addr).await.context(BindListenerSnafu)?;
        tracing::info!(%addr, "proxy listening");
        listeners.push(listener);
    }
    Ok(listeners)
}

pub async fn run(mut options: Options) -> Result<(), Error> {
    let _guard = init_tracing(&options)?;

    let id = if options.anonymous {
        None
    } else {
        id::load_home_and_identity(
            options.id.is_some(),
            options
                .id
                .as_ref()
                .map(|id| (&"command line option" as &dyn std::fmt::Display, id.clone())),
        )
        .await?
    };

    let binds = bind::Binds::new(mem::take(&mut options.binds));

    let h3_setup = h3_client::setup_h3_client()
        .binds(&binds)
        .dns_schemes(&options.dns)
        .maybe_identity(id.as_ref())
        .call()
        .await?;

    let _watcher = h3_setup.watcher;
    let client = h3_setup.client;

    let self_name = id.as_ref().map(|id| id.name().clone());

    let listeners = bind_listeners(&options).await?;
    let router = Arc::new(route::Router::new());
    let client = Arc::new(client);

    let mut tasks = JoinSet::new();
    for listener in listeners {
        let client = client.clone();
        let router = router.clone();
        let self_name = self_name.clone();
        tasks.spawn(accept_loop(listener, client, router, self_name));
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(()) => tracing::info!("listener task exited"),
            Err(e) => tracing::error!(error = %e, "listener task panicked"),
        }
    }

    Ok(())
}

/// Accept loop for a single TCP listener. Runs until the listener is dropped.
async fn accept_loop(
    listener: TcpListener,
    client: Arc<H3Client>,
    router: Arc<route::Router>,
    self_name: Option<Name<'static>>,
) {
    let self_name = Arc::new(self_name);
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed, retrying");
                continue;
            }
        };
        tracing::debug!(%addr, "accepted connection");
        let client = client.clone();
        let router = router.clone();
        let self_name = self_name.clone();
        let span = tracing::info_span!("conn", %addr);
        tokio::spawn(
            async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(
                        io,
                        hyper::service::service_fn(move |req| {
                            let client = client.clone();
                            let router = router.clone();
                            let self_name = self_name.clone();
                            async move {
                                handle_request(req, &client, &router, self_name.as_ref().as_ref())
                                    .await
                            }
                        }),
                    )
                    .with_upgrades()
                    .await
                {
                    tracing::error!(error = %Report::from_error(&e), %addr, "connection error");
                }
            }
            .instrument(span),
        );
    }
}

pub mod forward;
pub mod h3_forward;
pub mod route;
pub mod tunnel;
