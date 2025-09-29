use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use bytes::{Buf, BytesMut};
use clap::Parser;
use futures::StreamExt;
use genmeta_common::{
    AGENTS, ROOT_CERT,
    connect::lookup,
    error::Whatever,
    id::{ClientName, expand_id},
};
use gm_quic::{ParameterId, ToCertificate};
use http::{Method, Request, Uri};
use qdns::{HttpResolver, MdnsResolver, Resolvers, UdpResolver};
use qtraversal::iface::traversal_factory;
use snafu::{FromString, OptionExt, ResultExt, whatever};
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time,
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
            whatever!("Missing authority in URI")
        };

        let host = expand_id(authority.host());
        uri_parts.authority = Some(
            host.parse()
                .whatever_context(format!("Failed to parse authority `{host}`"))?,
        );

        self.uri = Uri::from_parts(uri_parts).whatever_context("Failed to complete URI")?;
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
                .whatever_context("Cannot create HTTP resolver")?,
        ))
        .with(Arc::new(
            MdnsResolver::new(qdns::MDNS_SERVICE)
                .whatever_context("Cannot create mDNS resolver")?,
        ))
        .with(Arc::new(UdpResolver::new(qdns::UDP_DNS_SERVER)));
    let server_name = options.uri.host().whatever_context("missing host in uri")?;

    let mut lookup = lookup(&resolvers, server_name)
        .await
        .whatever_context(format!(
            "Failed to lookup endpoint addresses for `{server_name}`"
        ))?;

    let (_, server_eps) = lookup
        .next()
        .await
        .expect("lookup never return before lookup successy");

    tracing::debug!("resolved {server_name} to address: {server_eps:?}");
    if options.verbose {
        eprintln!("* resolved {server_name} to address: {server_eps:?}");
    }

    let profile = match &options.id {
        Some(id) => Some(
            genmeta_common::id::config::read_config(id, None)
                .await
                .whatever_context(format!("Failed to read profile for `{id}`"))?,
        ),
        None => None,
    };

    let quic_client = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ROOT_CERT.to_certificate());

        let factory = traversal_factory(&AGENTS);

        let mut parameters = gm_quic::handy::client_parameters();

        match profile {
            Some(genmeta_common::id::config::Profile { id, key, cert }) => {
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

    let (_quic_conn, mut h3_conn, mut h3_client) = {
        tracing::debug!(target: "connect", server_name, ?server_eps, "Attempt connect to server");
        let quic_connection = quic_client
            .connect(server_name, server_eps)
            .whatever_context("Cannot connect to server")?;
        tokio::spawn({
            let conn = quic_connection.clone();
            async move {
                while let Some((_, server_eps)) = lookup.next().await {
                    for server_ep in server_eps {
                        if conn.add_peer_endpoint(server_ep.into()).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let connect = h3::client::new(h3_shim::QuicConnection::new(quic_connection.clone()));
        let connect_timeout = options
            .connect_timeout
            .map_or(Duration::MAX, Duration::from_secs);
        let (h3_conn, h3_client) = time::timeout(connect_timeout, connect)
            .await
            .map_err(|_| {
                if let Err(error) = quic_connection
                    .validate()
                    .whatever_context("QUIC Connection failed")
                {
                    return error;
                };
                _ = quic_connection.close("Connect timeouted", 0);
                Whatever::without_source("Connect timeouted".to_string())
            })?
            .whatever_context("Cannot connect to server")?;
        (quic_connection, h3_conn, h3_client)
    };
    if options.verbose {
        eprintln!("* establish http3 connection to {server_name}");
    }
    tracing::debug!(target: "connect", "http3 connection established");
    tokio::spawn(async move { h3_conn.wait_idle().await });

    let mut request_builder = Request::builder()
        .uri(options.uri.clone())
        .version(http::Version::HTTP_3)
        .header("Host", server_name)
        .header(
            "User-Agent",
            format!("genmeta-curl/{}", env!("CARGO_PKG_VERSION")),
        )
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
        .whatever_context("Failed to build request")?;

    // Host and User Agent header

    if options.verbose {
        let output = format!("> send request: {request:#?}")
            .lines()
            .collect::<Vec<_>>()
            .join("\n> ");
        println!("{output}",)
    }

    tracing::debug!(target: "request", "build request: {request:?}");

    let request_stream = h3_client
        .send_request(request)
        .await
        .whatever_context("Failed to send request")?;

    let (mut send_stream, mut recv_stream) = request_stream.split();

    let send_request_body = async {
        if let Some(data) = options.data {
            send_stream
                .send_data(Vec::from(data).into())
                .await
                .whatever_context("Failed to send request body")?;
        }

        if let Some(path) = options.upload_file {
            let mut file = fs::File::open(&path)
                .await
                .whatever_context(format!("Failed to open file {} to upload", path.display()))?;
            loop {
                let mut buf = BytesMut::with_capacity(1 << 20);
                file.read_buf(&mut buf).await.whatever_context(format!(
                    "Failed to read file {} to upload",
                    path.display()
                ))?;
                if buf.is_empty() {
                    break;
                }
                send_stream
                    .send_data(buf.freeze())
                    .await
                    .whatever_context("Failed to send request body")?;
            }
        }

        send_stream
            .finish()
            .await
            .whatever_context("Failed to finish request stream")?;

        Result::<_, Whatever>::Ok(())
    };
    let receive_response = async {
        let response = recv_stream
            .recv_response()
            .await
            .whatever_context("Failed to receive response")?;

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
                .whatever_context("Failed to create output file")?
        } else {
            tracing::debug!(target: "request", "dump output to stdio");
            &mut io::stdout()
        };

        while let Some(mut data) = recv_stream
            .recv_data()
            .await
            .whatever_context("Failed to receive data")?
        {
            while data.has_remaining() {
                let chunk = data.chunk();
                dst.write_all(chunk)
                    .await
                    .whatever_context("Failed to write data to output")?;
                data.advance(chunk.len());
            }
        }
        dst.flush()
            .await
            .whatever_context("Failed to flush output")?;

        Result::<_, Whatever>::Ok(())
    };

    tokio::try_join!(send_request_body, receive_response)?;

    Ok(())
}
