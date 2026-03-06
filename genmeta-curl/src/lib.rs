use std::{
    convert::Infallible,
    mem,
    path::PathBuf,
    pin::pin,
    sync::Arc,
    time::{Duration, Instant},
};

use async_compression::tokio::bufread::{DeflateDecoder, GzipDecoder, ZstdDecoder};
use clap::Parser;
use genmeta_common::{
    bind,
    dns::{self},
    id,
};
use genmeta_home::identity::Name;
use h3x::{
    gm_quic::{
        BuildClientError, H3Client,
        prelude::{ConnectServerError, handy::NoopLogger},
    },
    hyper::SendMesageError,
    message::stream::{InitialMessageStreamError, MessageStreamError},
    pool::ConnectError,
};
use http::{Method, Request, Uri, header::USER_AGENT};
use snafu::{ResultExt, Snafu, ensure};
use tokio::{
    fs,
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
};
use tracing_subscriber::prelude::*;

/// Maximum number of redirects to follow (same default as curl since 8.3.0)
const MAX_REDIRS_DEFAULT: u32 = 30;

/// Supported content encodings for --compressed
const ACCEPT_ENCODING: &str = "deflate, gzip, zstd";

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    /// URL to request
    uri: Uri,

    /// Specify request method to use
    #[arg(short = 'X', long)]
    request: Option<Method>,

    /// Send data in a POST request
    #[arg(short, long, conflicts_with("upload_file"))]
    data: Option<String>,

    /// Transfer local file to destination
    #[arg(short = 'T', long, conflicts_with("data"))]
    upload_file: Option<PathBuf>,

    /// Pass custom header(s) to server
    #[arg(short = 'H', long, value_parser = parse_header)]
    header: Vec<(String, String)>,

    /// Follow redirects
    #[arg(short = 'L', long)]
    location: bool,

    /// Maximum number of redirects to follow
    #[arg(long, default_value_t = MAX_REDIRS_DEFAULT)]
    max_redirs: u32,

    /// Write output to file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Define output format for response metadata
    ///
    /// Supported: %{response_code}, %{http_code}, %{url}, %{method},
    /// %{scheme}, %{http_version}, %{time_total}, %{time_connect},
    /// %{time_starttransfer}, %{size_download}, %{header{name}}
    #[arg(short = 'w', long = "write-out")]
    write_out: Option<String>,

    /// Request compressed response and decompress it
    #[arg(long)]
    compressed: bool,

    /// Disable content decoding; pass raw bytes through
    #[arg(long, conflicts_with("compressed"))]
    raw: bool,

    /// Maximum time allowed for connection in seconds
    #[arg(long)]
    connect_timeout: Option<u64>,

    /// Client identity for DHTTP/3 connections
    #[arg(long, value_name = "client_identity")]
    id: Option<Name<'static>>,

    /// Skip identity loading and use anonymous mode
    #[arg(long, conflicts_with = "id")]
    anonymous: bool,

    /// DNS resolution schemes
    #[arg(long, value_name = "scheme", default_value = "mdns, http", value_delimiter = ',', hide = cfg!(not(debug_assertions)))]
    dns: Vec<dns::DnsScheme>,

    /// Bind patterns for DHTTP/3 connections
    #[arg(long = "interface", value_name = "bind", default_value = "*", hide = cfg!(not(debug_assertions)))]
    binds: Vec<bind::Bind>,

    /// Make the operation more talkative
    #[arg(short, long)]
    verbose: bool,

    /// Suppress progress and error messages
    #[arg(short = 's', long)]
    silent: bool,

    /// Show error messages even when --silent is active
    #[arg(short = 'S', long = "show-error")]
    show_error: bool,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("missing authority in URI"))]
    MissingAuthority {},

    #[snafu(display("failed to expand identity in URI"))]
    ExpandUri {
        source: genmeta_home::identity::InvalidName,
    },

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

    #[snafu(display("failed to connect to server"))]
    Connect {
        source: ConnectError<ConnectServerError>,
    },

    #[snafu(display("connection timed out"))]
    Timedout {},

    #[snafu(display("failed to open request stream"))]
    InitialMessageStream { source: InitialMessageStreamError },

    #[snafu(display("failed to build HTTP request"))]
    BuildRequest { source: http::Error },

    #[snafu(display("failed to send HTTP request"))]
    SendRequest { source: SendMesageError<Infallible> },

    #[snafu(display("failed to open file `{}` to upload", path.display()))]
    OpenUploadFile { path: PathBuf, source: io::Error },

    #[snafu(display("failed to upload file `{}` to server", path.display()))]
    UploadFile { path: PathBuf, source: io::Error },

    #[snafu(display("failed to close request stream"))]
    CloseRequestStream { source: MessageStreamError },

    #[snafu(display("failed to receive response"))]
    ReceiveResponse { source: MessageStreamError },

    #[snafu(display("failed to create output file"))]
    CreateOutputFile { source: io::Error },

    #[snafu(display("failed to read response body or write to output"))]
    ReadResponse { source: io::Error },

    #[snafu(display("failed to flush output"))]
    FlushOutput { source: io::Error },

    #[snafu(display("too many redirects"))]
    TooManyRedirects {},

    #[snafu(display("redirect location is missing or invalid"))]
    InvalidRedirectLocation { source: http::uri::InvalidUri },
}

impl Options {
    fn expand_uri(&mut self) -> Result<(), Error> {
        ensure!(self.uri.authority().is_some(), MissingAuthoritySnafu);
        self.uri = id::expand_uri(self.uri.clone()).context(ExpandUriSnafu)?;
        Ok(())
    }
}

fn parse_header(s: &str) -> Result<(String, String), String> {
    let mut parts = s.splitn(2, ':');
    let key = parts.next().ok_or("missing header key")?.trim().to_string();
    let value = parts
        .next()
        .ok_or("missing header value")?
        .trim()
        .to_string();
    Ok((key, value))
}

/// Timing checkpoints collected during a single request-response cycle.
struct Timing {
    start: Instant,
    connected: Option<Instant>,
    first_byte: Option<Instant>,
}

impl Timing {
    fn new() -> Self {
        Timing {
            start: Instant::now(),
            connected: None,
            first_byte: None,
        }
    }

    fn time_connect(&self) -> f64 {
        self.connected
            .map(|t| t.duration_since(self.start).as_secs_f64())
            .unwrap_or(0.0)
    }

    fn time_starttransfer(&self) -> f64 {
        self.first_byte
            .map(|t| t.duration_since(self.start).as_secs_f64())
            .unwrap_or(0.0)
    }

    fn time_total(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }
}

/// Expand a `--write-out` format string, substituting `%{var}` tokens.
fn expand_write_out(
    fmt: &str,
    status: u16,
    uri: &Uri,
    method: &Method,
    http_version: http::Version,
    timing: &Timing,
    size_download: u64,
    response_headers: &http::HeaderMap,
) -> String {
    let mut out = String::with_capacity(fmt.len());
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('{') => {
                chars.next(); // consume '{'
                let var: String = chars.by_ref().take_while(|&c| c != '}').collect();
                let value = expand_variable(
                    &var,
                    status,
                    uri,
                    method,
                    http_version,
                    timing,
                    size_download,
                    response_headers,
                );
                out.push_str(&value);
            }
            Some('%') => {
                chars.next();
                out.push('%');
            }
            _ => out.push('%'),
        }
    }
    // Replace escape sequences
    out.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r")
}

fn expand_variable(
    var: &str,
    status: u16,
    uri: &Uri,
    method: &Method,
    http_version: http::Version,
    timing: &Timing,
    size_download: u64,
    headers: &http::HeaderMap,
) -> String {
    // Handle %{header{name}} pattern: var == "header{some-header}"
    if let Some(rest) = var.strip_prefix("header{") {
        let header_name = rest.trim_end_matches('}');
        return headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
    }

    match var {
        "response_code" | "http_code" => status.to_string(),
        "url" => uri.to_string(),
        "method" => method.to_string(),
        "scheme" => uri.scheme_str().unwrap_or("").to_string(),
        "http_version" => format!("{http_version:?}").replace("HTTP/", ""),
        "time_total" => format!("{:.6}", timing.time_total()),
        "time_connect" => format!("{:.6}", timing.time_connect()),
        "time_starttransfer" => format!("{:.6}", timing.time_starttransfer()),
        "size_download" => size_download.to_string(),
        _ => String::new(),
    }
}

/// Copy `reader` into `writer`, returning the number of bytes written.
async fn copy_all<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<u64> {
    io::copy(reader, writer).await
}

/// Copy `reader` into `writer`, decompressing based on Content-Encoding.
/// Falls back to pass-through for unknown or identity encoding.
async fn decompress_copy<R, W>(
    reader: R,
    writer: &mut W,
    content_encoding: &str,
) -> Result<u64, Error>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match content_encoding {
        "gzip" | "x-gzip" => {
            let mut dec = GzipDecoder::new(reader);
            copy_all(&mut dec, writer).await.context(ReadResponseSnafu)
        }
        "deflate" => {
            let mut dec = DeflateDecoder::new(reader);
            copy_all(&mut dec, writer).await.context(ReadResponseSnafu)
        }
        "zstd" => {
            let mut dec = ZstdDecoder::new(reader);
            copy_all(&mut dec, writer).await.context(ReadResponseSnafu)
        }
        _ => {
            // identity or unknown encoding — pass through
            let mut r = reader;
            copy_all(&mut r, writer).await.context(ReadResponseSnafu)
        }
    }
}

pub async fn run(mut options: Options) -> Result<(), Error> {
    // Initialize tracing.
    // -s:   suppress all tracing output.
    // -s -S: show errors only (INFO level) but not progress.
    // We approximate -s -S by keeping INFO but note that progress is not
    // separately implemented — tracing output itself is the only stderr content.
    let (stderr, _guard) = tracing_appender::non_blocking(std::io::stderr());
    let level = if options.silent && !options.show_error {
        tracing_subscriber::filter::LevelFilter::OFF
    } else {
        tracing_subscriber::filter::LevelFilter::INFO
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(level.into())
                .from_env_lossy()
                .add_directive("netlink_packet_route=error".parse().unwrap()),
        )
        .init();

    options.expand_uri()?;

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

    let connect_timeout = options
        .connect_timeout
        .map(Duration::from_secs)
        .unwrap_or(Duration::MAX);

    // Determine effective method (may change across redirects).
    let initial_method = options.request.clone().unwrap_or_else(|| match &options {
        o if o.data.is_some() => Method::POST,
        o if o.upload_file.is_some() => Method::PUT,
        _ => Method::GET,
    });

    let mut current_uri = options.uri.clone();
    let mut current_method = initial_method;
    let mut redirect_count: u32 = 0;

    loop {
        let mut timing = Timing::new();

        // Connect
        let connect_fut = async {
            client
                .connect(current_uri.authority().expect("checked").clone())
                .await
                .context(ConnectSnafu)
        };
        let connection = match tokio::time::timeout(connect_timeout, connect_fut).await {
            Ok(result) => result?,
            Err(_) => return TimedoutSnafu.fail(),
        };
        timing.connected = Some(Instant::now());

        let (mut response_stream, mut request_stream) = connection
            .initial_message_stream()
            .await
            .context(InitialMessageStreamSnafu)?;

        let user_agent = format!("genmeta-curl/{}", env!("CARGO_PKG_VERSION"));
        let mut request_builder = Request::builder()
            .uri(current_uri.clone())
            .version(http::Version::HTTP_3)
            .header(USER_AGENT, user_agent)
            .header("Accept", "*/*");

        if options.compressed && !options.raw {
            request_builder = request_builder.header("Accept-Encoding", ACCEPT_ENCODING);
        }

        request_builder = request_builder.method(&current_method);

        for (k, v) in options.header.iter() {
            request_builder = request_builder.header(k, v);
        }

        // Send request body
        let send_body: Result<_, Error> = async {
            // After a redirect to GET/HEAD, skip sending a body
            let skip_body =
                redirect_count > 0 && matches!(current_method, Method::GET | Method::HEAD);

            if skip_body || options.data.is_none() && options.upload_file.is_none() {
                let request = request_builder
                    .body(String::new())
                    .context(BuildRequestSnafu)?;
                request_stream
                    .send_hyper_request(request)
                    .await
                    .context(SendRequestSnafu)?;
            } else if let Some(ref data) = options.data {
                let request = request_builder
                    .body(data.clone())
                    .context(BuildRequestSnafu)?;
                request_stream
                    .send_hyper_request(request)
                    .await
                    .context(SendRequestSnafu)?;
            } else if let Some(ref path) = options.upload_file {
                // File upload only on first attempt (stream cannot be re-read)
                if redirect_count == 0 {
                    let mut stream_writer = pin!(request_stream.as_writer());
                    let mut file = fs::File::open(path)
                        .await
                        .context(OpenUploadFileSnafu { path: path.clone() })?;
                    io::copy(&mut file, &mut stream_writer)
                        .await
                        .context(UploadFileSnafu { path: path.clone() })?;
                    stream_writer
                        .flush()
                        .await
                        .context(UploadFileSnafu { path: path.clone() })?;
                } else {
                    let request = request_builder
                        .body(String::new())
                        .context(BuildRequestSnafu)?;
                    request_stream
                        .send_hyper_request(request)
                        .await
                        .context(SendRequestSnafu)?;
                }
            }

            request_stream
                .close()
                .await
                .context(CloseRequestStreamSnafu)?;
            Ok(())
        }
        .await;
        send_body?;

        // Receive response head
        let response = response_stream
            .read_hyper_response_parts()
            .await
            .context(ReceiveResponseSnafu)?;

        timing.first_byte = Some(Instant::now());

        if options.verbose {
            let formatted = format!("< received response: {response:#?}")
                .lines()
                .collect::<Vec<_>>()
                .join("\n< ");
            eprintln!("{formatted}");
        }

        let status = response.status;
        let response_headers = response.headers.clone();
        let http_version = response.version;

        // Redirect handling
        if options.location && status.is_redirection() && status != http::StatusCode::NOT_MODIFIED {
            if redirect_count >= options.max_redirs {
                return TooManyRedirectsSnafu.fail();
            }

            if let Some(location) = response.headers.get(http::header::LOCATION) {
                let location_str = location.to_str().unwrap_or("");
                let parsed: Uri = location_str.parse().context(InvalidRedirectLocationSnafu)?;

                // Resolve relative redirects against current URI
                let new_uri = if parsed.authority().is_none() {
                    let scheme = current_uri.scheme_str().unwrap_or("https");
                    let authority = current_uri
                        .authority()
                        .map(|a| a.as_str())
                        .unwrap_or_default();
                    let path_q = parsed.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
                    format!("{scheme}://{authority}{path_q}")
                        .parse()
                        .context(InvalidRedirectLocationSnafu)?
                } else {
                    parsed
                };

                // 301/302/303 → switch to GET; 307/308 → keep method
                current_method = match status.as_u16() {
                    301 | 302 | 303 => Method::GET,
                    _ => current_method,
                };
                current_uri = new_uri;
                redirect_count += 1;

                // Drain response body so the QUIC stream is cleanly closed
                let mut body_reader = pin!(response_stream.as_reader());
                io::copy(&mut body_reader, &mut io::sink()).await.ok();

                tracing::debug!(
                    redirect_count,
                    location = location_str,
                    "Following redirect"
                );
                continue;
            }
        }

        // --- Final response: stream body to output ---

        let content_encoding = response_headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let decompress = options.compressed && !options.raw;

        let size_download: u64 = if let Some(ref output_path) = options.output {
            tracing::debug!("Dumping output to {}", output_path.display());
            let mut file = fs::File::create(output_path)
                .await
                .context(CreateOutputFileSnafu)?;

            let n = if decompress {
                let body_reader = pin!(response_stream.as_reader());
                decompress_copy(body_reader, &mut file, &content_encoding).await?
            } else {
                let mut body_reader = pin!(response_stream.as_reader());
                copy_all(&mut body_reader, &mut file)
                    .await
                    .context(ReadResponseSnafu)?
            };
            file.flush().await.context(FlushOutputSnafu)?;
            n
        } else {
            tracing::debug!("Dumping output to stdout");
            let mut stdout = io::stdout();

            let n = if decompress {
                let body_reader = pin!(response_stream.as_reader());
                decompress_copy(body_reader, &mut stdout, &content_encoding).await?
            } else {
                let mut body_reader = pin!(response_stream.as_reader());
                copy_all(&mut body_reader, &mut stdout)
                    .await
                    .context(ReadResponseSnafu)?
            };
            stdout.flush().await.context(FlushOutputSnafu)?;
            n
        };

        // --write-out: print format string after body, to stdout, no trailing newline
        if let Some(ref fmt) = options.write_out {
            let expanded = expand_write_out(
                fmt,
                status.as_u16(),
                &current_uri,
                &current_method,
                http_version,
                &timing,
                size_download,
                &response_headers,
            );
            print!("{expanded}");
            io::stdout().flush().await.context(FlushOutputSnafu)?;
        }

        break;
    }

    Ok(())
}
