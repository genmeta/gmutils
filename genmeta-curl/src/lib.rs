use std::{path::PathBuf, sync::Arc, time::Duration};

use bytes::{Buf, BytesMut};
use clap::Parser;
use genmeta_common::{
    connect::{
        H3ConnectionPool,
        prelude::handy,
        qdns::{self, HttpResolver, Resolvers},
    },
    error::Whatever,
    identity::{ClientName, expand_id},
};
use http::{Method, Request, Uri, header::USER_AGENT};
use snafu::{OptionExt, ResultExt, whatever};
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWrite, AsyncWriteExt},
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
    id: Option<ClientName>,

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
    fn complete_uri(&mut self) -> Result<(), Whatever> {
        let mut uri_parts = self.uri.clone().into_parts();

        let Some(authority) = uri_parts.authority else {
            whatever!("missing authority in URI")
        };

        let host = expand_id(authority.host());
        uri_parts.authority = Some(
            host.parse()
                .whatever_context(format!("failed to parse authority `{host}`"))?,
        );

        self.uri = Uri::from_parts(uri_parts).whatever_context("failed to complete URI")?;
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
    options.complete_uri()?;
    let resolvers = Resolvers::new()
        .with(Arc::new(
            HttpResolver::new(qdns::HTTP_DNS_SERVER)
                .whatever_context("cannot create HTTP resolver")?,
        ))
        .with_mdns(qdns::MDNS_SERVICE)
        .0;
    let server_name = options.uri.host().whatever_context("missing host in uri")?;

    let profile = match &options.id {
        Some(id) => Some(
            genmeta_common::identity::config::read_config(id, None)
                .await
                .whatever_context(format!("failed to read profile for `{id}`"))?,
        ),
        None => None,
    };

    let parameters = handy::client_parameters();
    let qlogger = Arc::new(handy::NoopLogger);
    let mut h3_pool = H3ConnectionPool::new(profile.as_ref(), parameters, qlogger);
    if options.verbose {
        h3_pool = h3_pool.verbose();
    }

    let timeout = options
        .connect_timeout
        .map(Duration::from_secs)
        .unwrap_or(Duration::MAX);
    let mut h3_client = h3_pool.connect(server_name, &resolvers, timeout).await?.h3;

    let user_agent = format!("genmeta-curl/{}", env!("CARGO_PKG_VERSION"));
    let mut request_builder = Request::builder()
        .uri(options.uri.clone())
        .version(http::Version::HTTP_3)
        .header("Host", server_name)
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

    let request = request_builder
        .body(())
        .whatever_context("failed to build request")?;

    let request_stream = h3_client
        .send_request(request)
        .await
        .whatever_context("failed to send request")?;

    let (mut send_stream, mut recv_stream) = request_stream.split();

    let send_request_body = async {
        if let Some(data) = options.data {
            send_stream
                .send_data(Vec::from(data).into())
                .await
                .whatever_context("failed to send request body")?;
        }

        if let Some(path) = options.upload_file {
            let mut file = fs::File::open(&path)
                .await
                .whatever_context(format!("failed to open file {} to upload", path.display()))?;
            loop {
                let mut buf = BytesMut::with_capacity(1 << 20);
                file.read_buf(&mut buf).await.whatever_context(format!(
                    "failed to read file {} to upload",
                    path.display()
                ))?;
                if buf.is_empty() {
                    break;
                }
                send_stream
                    .send_data(buf.freeze())
                    .await
                    .whatever_context("failed to send request body")?;
            }
        }

        send_stream
            .finish()
            .await
            .whatever_context("failed to finish request stream")?;

        Result::<_, Whatever>::Ok(())
    };
    let receive_response = async {
        let response = recv_stream
            .recv_response()
            .await
            .whatever_context("failed to receive response")?;

        tracing::debug!(target: "request", "response: {response:#?}");
        if options.verbose {
            let output = format!("< received response: {response:#?}")
                .lines()
                .collect::<Vec<_>>()
                .join("\n< ");
            println!("{output}")
        }

        let dst: &mut (dyn AsyncWrite + Unpin) = if let Some(output) = options.output {
            tracing::debug!(target: "request", "dump output to {}", output.display());
            &mut fs::File::create(output)
                .await
                .whatever_context("failed to create output file")?
        } else {
            tracing::debug!(target: "request", "dump output to stdio");
            &mut io::stdout()
        };

        while let Some(mut data) = recv_stream
            .recv_data()
            .await
            .whatever_context("failed to receive data")?
        {
            while data.has_remaining() {
                let chunk = data.chunk();
                dst.write_all(chunk)
                    .await
                    .whatever_context("failed to write data to output")?;
                data.advance(chunk.len());
            }
        }
        dst.flush()
            .await
            .whatever_context("failed to flush output")?;

        Result::<_, Whatever>::Ok(())
    };

    tokio::try_join!(send_request_body, receive_response)?;

    Ok(())
}
