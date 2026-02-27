use std::{mem, path::PathBuf, pin::pin, sync::Arc, time::Duration};

use clap::Parser;
use genmeta_common::{
    bind,
    dns::{self},
    error::Whatever,
    id,
};
use genmeta_home::identity::Name;
use h3x::gm_quic::{H3Client, prelude::handy::NoopLogger};
use http::{Method, Request, Uri, header::USER_AGENT};
use snafu::{ResultExt, whatever};
use tokio::{
    fs,
    io::{self, AsyncWrite, AsyncWriteExt},
};

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

impl Options {
    fn expand_uri(&mut self) -> Result<(), Whatever> {
        if self.uri.authority().is_none() {
            whatever!("missing authority in URI")
        }

        self.uri = id::expand_uri(self.uri.clone())
            .whatever_context("expanded identity name in URI is invalid")?;
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

pub async fn run(mut options: Options) -> Result<(), Whatever> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();
    options.expand_uri()?;

    let id = id::load_home_and_identity(
        options.id.is_some(),
        options
            .id
            .as_ref()
            .map(|id| (&"command line option" as &dyn std::fmt::Display, id.clone())),
    )
    .await
    .whatever_context("failed to locate `GENMETA_HOME` while it's required")?;

    let bind_setup = bind::setup_bind_interfaces_with(
        bind::Binds::new(mem::take(&mut options.binds)),
        dns::handy::ensure_default_mdns_prop,
    )
    .await
    .whatever_context("failed to resolve bind interfaces to bind uris")?;

    let dns_setup = dns::handy::build_resolvers(
        options.dns.iter().copied(),
        &bind_setup.bind_interfaces,
        id.as_ref(),
    )
    .whatever_context("failed to build DNS resolvers")?;

    let client = match &id {
        Some(id) => H3Client::builder().with_identity(id.name().as_full(), id.certs(), id.key()),
        None => H3Client::builder().without_identity(),
    }
    .whatever_context("failed to build DHTTP/3 client")?
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
            .whatever_context("failed to connect to server")
    };
    let connection = match tokio::time::timeout(timeout, connect).await {
        Ok(result) => result?,
        Err(_) => whatever!("connection timed out"),
    };

    let (mut response_stream, mut request_stream) = connection
        .open_request_stream()
        .await
        .whatever_context("failed to open request stream")?;

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
            let request = request_builder
                .body(data)
                .whatever_context("failed to build http request")?;
            request_stream
                .send_hyper_request(request)
                .await
                .whatever_context("failed to send http request")?;
        } else if let Some(path) = options.upload_file {
            let mut stream_writer = pin!(request_stream.as_writer());
            let mut file = fs::File::open(&path).await.whatever_context(format!(
                "failed to open file `{}` to upload",
                path.display()
            ))?;

            io::copy(&mut file, &mut stream_writer)
                .await
                .whatever_context(format!(
                    "failed to upload file `{}` to server",
                    path.display()
                ))?;
            stream_writer.flush().await.whatever_context(format!(
                "failed to upload file `{}` to server",
                path.display()
            ))?;
        }

        request_stream
            .close()
            .await
            .whatever_context("failed to close request stream")?;

        Result::<_, Whatever>::Ok(())
    };
    let receive_response = async {
        let response = response_stream
            .read_hyper_response_parts()
            .await
            .whatever_context("failed to receive response")?;

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
                .whatever_context("failed to create output file")?
        } else {
            tracing::debug!("Dump output to stdio");
            &mut io::stdout()
        };

        let mut stream_reader = pin!(response_stream.as_reader());
        io::copy(&mut stream_reader, dst)
            .await
            .whatever_context("failed to read response body or write to output")?;
        dst.flush()
            .await
            .whatever_context("failed to flush output")?;

        Result::<_, Whatever>::Ok(())
    };

    tokio::try_join!(send_request_body, receive_response)?;

    Ok(())
}
