use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use bytes::{Buf, BytesMut};
use clap::Parser;
use futures::StreamExt;
use genmeta_common::{AGENTS, ROOT_CERT};
use gm_quic::ToCertificate;
use http::{Method, Request, Uri};
use qdns::{HttpResolver, MdnsResolver, Resolvers, UdpResolver};
use qtraversal::iface::traversal_factory;
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
    #[arg(short, long, help = "HTTP POST data", conflicts_with("upload_file"))]
    data: Option<String>,

    /// Upload file
    #[arg(
        short = 'T',
        long,
        help = "Transfer local FILE to destination",
        conflicts_with("data")
    )]
    upload_file: Option<PathBuf>,

    /// Output file
    #[arg(short, long, help = "Write to file instead of stdout")]
    output: Option<PathBuf>,

    /// HTTP Method
    #[arg(short = 'X', long, help = "Specify request method to use")]
    request: Option<Method>,
    //
    // /// Follow redirects
    // #[arg(short = 'L', long, help = "Follow redirects")]
    // location: bool,
    //
    /// Custom headers
    #[arg(short = 'H', long, help = "Pass custom header(s) to server", value_parser = parse_header)]
    header: Vec<(String, String)>,

    /// User agent
    // #[arg(
    //     short = 'A',
    //     long = "user-agent",
    //     help = "User Agent to send to server"
    // )]
    // user_agent: Option<String>,

    /// Basic auth
    // #[arg(
    //     short = 'u',
    //     long = "user",
    //     help = "Server user and password (user:password)"
    // )]
    // user: Option<String>,

    /// Connection timeout
    #[arg(long, help = "Maximum time allowed for connection in seconds")]
    connect_timeout: Option<u64>,
    // /// Request timeout
    // #[arg(long, help = "Maximum time allowed for the transfer in seconds")]
    // max_time: Option<u64>,
    //
    /// Verbose output
    #[arg(short, long, help = "Make the operation more talkative")]
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
    fn complete_uri(&mut self) -> Result<(), Error> {
        let mut uri_parts = self.uri.clone().into_parts();

        uri_parts.authority = match uri_parts.authority {
            Some(authority) => {
                let host = authority.host().replacen("~", ".genmeta.net", 1);
                Some(host.parse().map_err(|e| {
                    format!("Failed to parse authority '{host}' as URI authority: {e}")
                })?)
            }
            None => return Err("Missing authority in URI".into()),
        };

        self.uri =
            Uri::from_parts(uri_parts).map_err(|e| format!("Failed to complete URI: {e}"))?;
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

type Error = Box<dyn core::error::Error + Send + Sync>;

pub async fn run(mut options: Options) -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::OFF.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();
    let resolvers = Resolvers::new()
        .with(Arc::new(HttpResolver::new(qdns::HTTP_DNS_SERVER)?))
        .with(Arc::new(MdnsResolver::new(qdns::MDNS_SERVICE)?))
        .with(Arc::new(UdpResolver::new(qdns::UDP_DNS_SERVER)));
    options.complete_uri()?;
    let server_name = options.uri.host().ok_or("missing host in uri")?;

    let mut dns_lookup = resolvers.lookup(server_name);
    let (_source, server_eps) = dns_lookup
        .next()
        .await
        .ok_or(format!("No endpoints found for server: {server_name}"))?;

    tracing::info!("resolved {server_name} to address: {server_eps:?}");
    if options.verbose {
        eprintln!("* resolved {server_name} to address: {server_eps:?}");
    }

    let quic_client = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ROOT_CERT.to_certificate());

        let factory = traversal_factory(&AGENTS);
        gm_quic::QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .with_parameters(client_parameters(Duration::from_secs(
                options.connect_timeout.unwrap_or_default(),
            )))
            .with_iface_factory(factory.as_ref().clone())
            .bind(factory.devices().keys().map(|ip| SocketAddr::new(*ip, 0)))
            .enable_sslkeylog()
            .build()
    };

    let (_quic_conn, mut h3_conn, mut h3_client) = {
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
        #[rustfmt::skip] // https://github.com/rust-lang/rustfmt/issues/6564
        let (h3_conn, h3_client) = time::timeout(Duration::from_secs(10), connect)
            .await
            .map_err(|_| {
                quic_connection.close("connect timeout", 0);
                "connect timeout"
        })??;
        (quic_connection, h3_conn, h3_client)
    };
    if options.verbose {
        eprintln!("* establish http3 connection to {server_name}");
    }
    tracing::info!(target: "connect", "http3 connection established");
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
        .map_err(|e| format!("failed to build request: {e:?}"))?;

    // Host and User Agent header

    if options.verbose {
        let output = format!("> send request: {request:#?}")
            .lines()
            .collect::<Vec<_>>()
            .join("\n> ");
        println!("{output}",)
    }

    tracing::info!(target: "request", "build request: {request:?}");

    let request_stream = h3_client
        .send_request(request)
        .await
        .map_err(|e| format!("failed to send request: {e:?}"))?;

    let (mut send_stream, mut recv_stream) = request_stream.split();

    let send_request_body = async {
        if let Some(data) = options.data {
            send_stream
                .send_data(Vec::from(data).into())
                .await
                .map_err(|e| format!("failed to send request body: {e:?}"))?;
        }

        if let Some(file) = options.upload_file {
            let mut file = fs::File::open(file)
                .await
                .map_err(|e| format!("failed to open file for upload: {e:?}"))?;
            loop {
                let mut buf = BytesMut::with_capacity(1 << 20);
                file.read_buf(&mut buf)
                    .await
                    .map_err(|e| format!("failed to read file to upload: {e:?}"))?;
                if buf.is_empty() {
                    break;
                }
                send_stream
                    .send_data(buf.freeze())
                    .await
                    .map_err(|e| format!("failed to send request body: {e:?}"))?;
            }
        }

        send_stream.finish().await?;

        Result::<_, Error>::Ok(())
    };
    let receive_response = async {
        let response = recv_stream
            .recv_response()
            .await
            .map_err(|e| format!("failed to receive response: {e:?}"))?;

        tracing::info!(target: "request", "response: {response:#?}");
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
                .map_err(|e| format!("failed to create output file: {e:?}"))?
        } else {
            tracing::debug!(target: "request", "dump output to stdio");
            &mut io::stdout()
        };

        while let Some(mut data) = recv_stream.recv_data().await? {
            while data.has_remaining() {
                let chunk = data.chunk();
                dst.write_all(chunk).await?;
                data.advance(chunk.len());
            }
        }
        dst.flush().await?;

        Result::<_, Error>::Ok(())
    };

    tokio::try_join!(send_request_body, receive_response)?;

    Ok(())
}

fn client_parameters(timeout: Duration) -> gm_quic::ClientParameters {
    let mut params = gm_quic::handy::client_parameters();
    _ = params.set(gm_quic::ParameterId::MaxIdleTimeout, timeout);
    params
}
