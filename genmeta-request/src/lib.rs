use std::{net::SocketAddr, path::PathBuf, time::Duration};

use bytes::{Buf, BytesMut};
use clap::Parser;
use genmeta_common::{AGENTS, ROOT_CERT, Resolvers};
use gm_quic::ToCertificate;
use http::{Method, Request, Uri};
use qdns::{Resolve, UdpResolver};
use qtraversal::iface::TraversalFactory;
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

pub async fn run(options: Options) -> Result<(), Error> {
    let resolvers = Resolvers::new()
        // .with(HttpResolver::new("http://127.0.0.1:20004/v1/dns/")?)
        .with(UdpResolver::new(Resolvers::UDP_DNS_SERVER));
    let server_name = options.uri.host().ok_or("missing host in uri")?;
    let server_addrs = resolvers
        .lookup(server_name)
        .await
        .map_err(|e| format!("failed to resolve host {server_name}: {e:?}"))?;

    tracing::info!("resolved {server_name} to address: {server_addrs:?}");
    if options.verbose {
        eprintln!("* resolved {server_name} to address: {server_addrs:?}");
    }

    let quic_client = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ROOT_CERT.to_certificate());

        let factory = TraversalFactory::with(&AGENTS);
        let binds = factory
            .devices()
            .keys()
            .map(|device_ip| SocketAddr::new(*device_ip, 0))
            .collect::<Vec<_>>();
        gm_quic::QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .with_alpns(["h3"])
            .with_iface_factory(factory)
            .with_parameters(client_parameters(Duration::from_secs(
                options.connect_timeout.unwrap_or_default(),
            )))
            .enable_sslkeylog()
            .reuse_address()
            .bind(&binds[..])
            .inspect_err(|e| {
                tracing::error!(target: "connect", "bind addrs {binds:?} failed: {e:?}");
            })?
            .build()
    };

    let (_quic_conn, mut h3_conn, mut h3_client) = {
        tracing::info!(target: "connect", server_name, ?server_addrs, "attempt connect to server");
        let mut connect_result = Result::Err(Error::from("Dns not found"));
        for server_addr in server_addrs {
            let attempt = async {
                let quic_conn = quic_client.connect(server_name, server_addr)?;
                let connect = async {
                    h3::client::new(h3_shim::QuicConnection::new(quic_conn.clone())).await
                };
                #[rustfmt::skip] // https://github.com/rust-lang/rustfmt/issues/6564
                    let (h3_conn, h3_client) = time::timeout(Duration::from_secs(3), connect)
                        .await
                        .map_err(|_| {
                            quic_conn.close("connect timeout".into(), 0);
                            "connect timeout"
                    })??;
                Result::<_, Error>::Ok((quic_conn, h3_conn, h3_client))
            };
            match attempt.await {
                Ok(connect) => {
                    connect_result = Ok(connect);
                    break;
                }
                Err(error) => {
                    tracing::error!(target: "connect", "attempt connect to server {server_addr} failed: error");
                    connect_result = Err(error)
                }
            }
        }
        connect_result?
    };
    if options.verbose {
        eprintln!("* establish http3 connection to {server_name}");
    }
    tracing::info!(target: "connect", "http3 connection established");
    tokio::spawn(async move { h3_conn.wait_idle().await });

    let mut request_builder = Request::builder().uri(options.uri.clone());

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
    let mut params = gm_quic::ClientParameters::default();

    params.set_initial_max_streams_bidi(100u32);
    params.set_initial_max_streams_uni(100u32);
    params.set_initial_max_data(1u32 << 20);
    params.set_initial_max_stream_data_uni(1u32 << 20);
    params.set_initial_max_stream_data_bidi_local(1u32 << 20);
    params.set_initial_max_stream_data_bidi_remote(1u32 << 20);
    params.set_max_idle_timeout(timeout);

    params
}
