use std::{io::IsTerminal, net::SocketAddr, sync::Arc, time::Duration};

use clap::Parser;
use dhttp::{
    ddns,
    dquic::binds::BindPattern,
    endpoint::Endpoint,
    home::{
        self, DhttpHome,
        identity::{DhttpName, IdentityHome, Name},
    },
};
use http_body_util::BodyExt;
use snafu::{IntoError, Report, ResultExt, Snafu, ensure};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use tracing::Instrument;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    /// Proxy listen address patterns
    #[arg(long = "listen", value_name = "bind", default_values = ["127.0.0.1:16080", "[::1]:16080"])]
    pub listens: Vec<BindPattern>,

    /// Client identity for DHTTP/3 connections
    #[arg(short, long, value_name = "client_identity")]
    pub id: Option<Name<'static>>,

    /// Skip identity loading and use anonymous mode
    #[arg(long, conflicts_with = "id")]
    pub anonymous: bool,

    /// DNS resolution schemes
    #[arg(long, value_name = "scheme", default_values = ["mdns", "h3"], value_delimiter = ',', hide = cfg!(not(debug_assertions)))]
    pub dns: Vec<ddns::DnsScheme>,

    /// Bind patterns for DHTTP/3 connections
    #[arg(long = "interface", value_name = "bind", default_value = "*", hide = cfg!(not(debug_assertions)))]
    pub binds: Vec<BindPattern>,

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
    #[snafu(display("bare `~` requires an identity"))]
    BareTildeWithoutIdentity,

    #[snafu(display("failed to expand identity name in uri"))]
    ExpandNameInUri {
        source: home::identity::ExpandUriError,
    },

    #[snafu(display("failed to parse identity name in uri"))]
    ExpandUriName {
        source: home::identity::InvalidDhttpName,
    },

    #[snafu(display("failed to parse expanded authority `{authority}`"))]
    ParseExpandedAuthority {
        authority: String,
        source: http::uri::InvalidUri,
    },

    #[snafu(display("failed to reconstruct uri with expanded identity name"))]
    ReconstructExpandedUri { source: http::uri::InvalidUriParts },

    #[snafu(display("failed to locate dhttp home"))]
    LocateDhttpHome { source: home::LocateDhttpHomeError },

    #[snafu(display("failed to load explicit identity `{name}`"))]
    LoadExplicitIdentity {
        name: Name<'static>,
        source: home::identity::ssl::LoadIdentityError,
    },

    #[snafu(display("failed to load identity certificate and key"))]
    LoadIdentitySsl {
        source: home::identity::ssl::LoadIdentitySslError,
    },

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
    #[cfg(unix)]
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
    client: &Endpoint,
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
            match expand_uri(req.uri().clone(), self_name) {
                Ok(uri) => *req.uri_mut() = uri,
                Err(e) => {
                    tracing::error!(error = %Report::from_error(&e), "failed to expand name in uri");
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
    for bind in &options.listens {
        let ip = bind.host.as_ip_addr().ok_or_else(|| {
            <Error as snafu::FromString>::without_source(format!(
                "listen bind `{}` must be a concrete ip address",
                bind.host
            ))
        })?;
        let addr = SocketAddr::new(ip, bind.effective_port());
        let listener = TcpListener::bind(addr).await.context(BindListenerSnafu)?;
        tracing::info!(%addr, "proxy listening");
        listeners.push(listener);
    }
    Ok(listeners)
}

fn expand_uri_without_identity(uri: http::Uri) -> Result<http::Uri, Error> {
    let mut parts = uri.into_parts();

    let Some(authority) = &parts.authority else {
        return http::Uri::from_parts(parts).context(ReconstructExpandedUriSnafu);
    };

    let host = authority.host();
    ensure!(host != "~", BareTildeWithoutIdentitySnafu);

    let Some(expanded) = DhttpName::try_expand_from(host).context(ExpandUriNameSnafu)? else {
        return http::Uri::from_parts(parts).context(ReconstructExpandedUriSnafu);
    };

    let expanded = expanded.as_full();
    if expanded != host {
        let user_info_len = authority
            .as_str()
            .split_once('@')
            .map(|(user_info, ..)| user_info.len() + 1)
            .unwrap_or_default();
        let host_len = host.len();
        let authority = format!(
            "{user_info}{host}{port}",
            user_info = &authority.as_str()[..user_info_len],
            host = expanded,
            port = &authority.as_str()[user_info_len + host_len..],
        );
        parts.authority = Some(authority.parse().context(ParseExpandedAuthoritySnafu {
            authority: &authority,
        })?);
    }

    http::Uri::from_parts(parts).context(ReconstructExpandedUriSnafu)
}

fn expand_uri(uri: http::Uri, self_name: Option<&Name<'_>>) -> Result<http::Uri, Error> {
    match self_name {
        Some(name) => name.expand_uri(uri).context(ExpandNameInUriSnafu),
        None => expand_uri_without_identity(uri),
    }
}

async fn load_identity_home(options: &Options) -> Result<Option<IdentityHome>, Error> {
    if options.anonymous {
        return Ok(None);
    }

    let home = match DhttpHome::load_from_environment() {
        Ok(home) => home,
        Err(source) if options.id.is_none() => {
            tracing::warn!(
                error = %snafu::Report::from_error(&source),
                "failed to locate dhttp home, using anonymous endpoint"
            );
            return Ok(None);
        }
        Err(source) => return Err(LocateDhttpHomeSnafu.into_error(source)),
    };

    if let Some(name) = &options.id {
        tracing::debug!(%name, "trying to load command line identity");
        return home
            .load_identity(name.clone())
            .await
            .context(LoadExplicitIdentitySnafu { name: name.clone() })
            .map(Some);
    }

    match home.load_default_identity().await {
        Ok(identity) => {
            tracing::debug!(name = %identity.name(), "using default identity");
            Ok(Some(identity))
        }
        Err(source) => {
            tracing::debug!(
                error = %snafu::Report::from_error(&source),
                "failed to load default identity, using anonymous endpoint"
            );
            Ok(None)
        }
    }
}

pub async fn run(options: Options) -> Result<(), Error> {
    let _guard = init_tracing(&options)?;

    let identity_home = load_identity_home(&options).await?;
    let identity = match &identity_home {
        Some(home) => Some(Arc::new(
            home.identity().await.context(LoadIdentitySslSnafu)?,
        )),
        None => None,
    };

    let mut builder = Endpoint::builder()
        .bind(Arc::new(options.binds.clone()))
        .maybe_identity(identity);
    for scheme in options.dns.iter().copied() {
        builder = builder.dns(scheme);
    }
    let client = Arc::new(builder.build().await);

    let self_name = identity_home.as_ref().map(|id| id.name().clone());

    let listeners = bind_listeners(&options).await?;
    let router = Arc::new(route::Router::new());

    let semaphore = Arc::new(Semaphore::new(1024));
    let mut tasks = JoinSet::new();
    for listener in listeners {
        let client = client.clone();
        let router = router.clone();
        let self_name = self_name.clone();
        let semaphore = semaphore.clone();
        tasks.spawn(accept_loop(listener, client, router, self_name, semaphore));
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(()) => tracing::info!("listener task exited"),
            Err(e) => {
                tracing::error!(error = %snafu::Report::from_error(&e), "listener task panicked")
            }
        }
    }

    Ok(())
}

/// Configure TCP keepalive on a stream to detect dead peers.
///
/// After 60 seconds of idle, sends probes every 10 seconds; 3 consecutive
/// failures trigger a RST (~90 seconds total).
fn configure_tcp_keepalive(stream: &tokio::net::TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10));
    // `with_retries` is only available on platforms that support TCP_KEEPCNT.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_vendor = "apple",
    ))]
    let keepalive = keepalive.with_retries(3);
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        tracing::warn!(error = %e, "failed to set TCP keepalive");
    }
}

/// Accept loop for a single TCP listener. Runs until the listener is dropped.
async fn accept_loop(
    listener: TcpListener,
    client: Arc<Endpoint>,
    router: Arc<route::Router>,
    self_name: Option<Name<'static>>,
    semaphore: Arc<Semaphore>,
) {
    let self_name = Arc::new(self_name);
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %snafu::Report::from_error(&e), "accept failed, retrying");
                tokio::time::sleep(Duration::from_millis(33)).await;
                continue;
            }
        };
        configure_tcp_keepalive(&stream);
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break, // semaphore closed
        };
        tracing::debug!(%addr, "accepted connection");
        let client = client.clone();
        let router = router.clone();
        let self_name = self_name.clone();
        let span = tracing::info_span!("conn", %addr);
        // Inherent termination: TCP keepalive detects dead peers (~90s),
        // header_read_timeout closes idle keep-alive connections (120s).
        tokio::spawn(
            async move {
                let _permit = permit;
                let io = hyper_util::rt::TokioIo::new(stream);
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(Some(Duration::from_secs(120)))
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
