use std::{convert::Infallible, mem, path::PathBuf, pin::pin, sync::Arc, time::Duration};

use clap::Parser;
use genmeta_common::{
    bind,
    dns::{self},
    id,
};
use genmeta_home::identity::Name;
use h3x::{
    connection::OpenRequestStreamError,
    gm_quic::{
        BuildClientError, H3Client,
        prelude::{ConnectServerError, handy::NoopLogger},
    },
    hyper::SendMesageError,
    message::stream::StreamError,
    pool::ConnectError,
};
use http::{Method, Request, Uri, header::USER_AGENT};
use snafu::{ResultExt, Snafu, ensure};
use tokio::{
    fs,
    io::{self, AsyncWrite, AsyncWriteExt},
};
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    /// URL to request
    uri: Uri,

    /// HTTP POST data
    #[arg(short, long, conflicts_with("upload_file"))]
    data: Option<String>,

    /// Transfer local FILE to destination
    #[arg(short = 'T', long, conflicts_with("data"))]
    upload_file: Option<PathBuf>,

    /// Write to file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Specify request method to use
    #[arg(short = 'X', long)]
    request: Option<Method>,
    //
    // /// Follow redirects
    // #[arg(short = 'L', long, help = "Follow redirects")]
    // location: bool,
    //
    /// Pass custom header(s) to server
    #[arg(short = 'H', long, value_parser = parse_header)]
    header: Vec<(String, String)>,
    //
    // /// User agent
    // #[arg(
    //     short = 'A',
    //     long = "user-agent",
    //     help = "User Agent to send to server"
    // )]
    // user_agent: Option<String>,
    //
    // /// Basic auth
    // #[arg(
    //     short = 'u',
    //     long = "user",
    //     help = "Server user and password (user:password)"
    // )]
    // user: Option<String>,
    //
    /// Client identity
    #[arg(long, value_name = "client_identity")]
    id: Option<Name<'static>>,

    /// DNS resolution schemes to connect to the remote.
    #[arg(long, value_name = "scheme", default_value = "system, mdns, http")]
    dns: Vec<dns::DnsScheme>,

    /// Bind patterns to specify which local interfaces and ports to bind for DHTTP/3 connections.
    #[arg(long = "interface", value_name = "bind", default_value = "*")]
    binds: Vec<bind::Bind>,

    /// Maximum time allowed for connection in seconds
    #[arg(long)]
    connect_timeout: Option<u64>,
    // /// Request timeout
    // #[arg(long, help = "Maximum time allowed for the transfer in seconds")]
    // max_time: Option<u64>,
    //
    /// Make the operation more talkative
    #[arg(short, long)]
    verbose: bool,
    //
    // /// Silent mode
    // #[arg(
    //     short = 's',
    //     long,
    //     help = "Silent mode, don't show progress or error messages"
    // )]
    // silent: bool,
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
    LocateGenmetaHome {
        source: genmeta_home::LocateGenmetaHomeError,
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
    OpenRequestStream { source: OpenRequestStreamError },

    #[snafu(display("failed to build HTTP request"))]
    BuildRequest { source: http::Error },

    #[snafu(display("failed to send HTTP request"))]
    SendRequest { source: SendMesageError<Infallible> },

    #[snafu(display("failed to open file `{}` to upload", path.display()))]
    OpenUploadFile {
        path: PathBuf,
        source: io::Error,
    },

    #[snafu(display("failed to upload file `{}` to server", path.display()))]
    UploadFile {
        path: PathBuf,
        source: io::Error,
    },

    #[snafu(display("failed to close request stream"))]
    CloseRequestStream { source: StreamError },

    #[snafu(display("failed to receive response"))]
    ReceiveResponse { source: StreamError },

    #[snafu(display("failed to create output file"))]
    CreateOutputFile { source: io::Error },

    #[snafu(display("failed to read response body or write to output"))]
    ReadResponse { source: io::Error },

    #[snafu(display("failed to flush output"))]
    FlushOutput { source: io::Error },
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
                .from_env_lossy(),
        )
        .init();
    options.expand_uri()?;

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

    let timeout = options
        .connect_timeout
        .map(Duration::from_secs)
        .unwrap_or(Duration::MAX);

    let connect = async {
        client
            .connect(options.uri.authority().expect("checked").clone())
            .await
            .context(ConnectSnafu)
    };
    let connection = match tokio::time::timeout(timeout, connect).await {
        Ok(result) => result?,
        Err(_) => return TimedoutSnafu.fail(),
    };

    let (mut response_stream, mut request_stream) = connection
        .open_request_stream()
        .await
        .context(OpenRequestStreamSnafu)?;

    let user_agent = format!("genmeta-curl/{}", env!("CARGO_PKG_VERSION"));
    let mut request_builder = Request::builder()
        .uri(options.uri.clone())
        .version(http::Version::HTTP_3)
        .header(USER_AGENT, user_agent)
        .header("Accept", "*/*");

    let method = options.request.as_ref().unwrap_or(match &options {
        options if options.data.is_some() => &Method::POST,
        options if options.upload_file.is_some() => &Method::PUT,
        _ => &Method::GET,
    });

    request_builder = request_builder.method(method);

    for (k, v) in options.header.iter() {
        request_builder = request_builder.header(k, v);
    }

    let send_request_body = async {
        if let Some(data) = options.data {
            let request = request_builder.body(data).context(BuildRequestSnafu)?;
            request_stream
                .send_hyper_request(request)
                .await
                .context(SendRequestSnafu)?;
        } else if let Some(path) = options.upload_file {
            let mut stream_writer = pin!(request_stream.as_writer());
            let mut file = fs::File::open(&path)
                .await
                .context(OpenUploadFileSnafu { path: path.clone() })?;

            io::copy(&mut file, &mut stream_writer)
                .await
                .context(UploadFileSnafu { path: path.clone() })?;
            stream_writer
                .flush()
                .await
                .context(UploadFileSnafu { path })?;
        }

        request_stream
            .close()
            .await
            .context(CloseRequestStreamSnafu)?;

        Result::<_, Error>::Ok(())
    };
    let receive_response = async {
        let response = response_stream
            .read_hyper_response_parts()
            .await
            .context(ReceiveResponseSnafu)?;

        tracing::debug!("Response: {response:#?}");
        if options.verbose {
            let output = format!("< received response: {response:#?}")
                .lines()
                .collect::<Vec<_>>()
                .join("\n< ");
            println!("{output}")
        }

        let dst: &mut (dyn AsyncWrite + Unpin) = if let Some(output) = options.output {
            tracing::debug!("Dump output to {}", output.display());
            &mut fs::File::create(output)
                .await
                .context(CreateOutputFileSnafu)?
        } else {
            tracing::debug!("Dump output to stdio");
            &mut io::stdout()
        };

        let mut stream_reader = pin!(response_stream.as_reader());
        io::copy(&mut stream_reader, dst)
            .await
            .context(ReadResponseSnafu)?;
        dst.flush().await.context(FlushOutputSnafu)?;

        Result::<_, Error>::Ok(())
    };

    tokio::try_join!(send_request_body, receive_response)?;

    Ok(())
}
