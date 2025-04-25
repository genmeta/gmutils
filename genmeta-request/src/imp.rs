use std::{net::SocketAddr, path::PathBuf};

use bytes::{Buf, BytesMut};
use gateway::{Resolver, dns::UdpResolver, localhost::TraversalFactory};
use gm_quic::ToCertificate;
use http::{Method, Request, Uri};

use clap::Parser;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
};

#[derive(Parser, Debug)]
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
    output: Option<String>,

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
    // /// Verbose output
    // #[arg(short, long, help = "Make the operation more talkative")]
    // verbose: bool,
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
    let resolver = UdpResolver::new("1.12.74.4:5300".parse().unwrap());
    let server_name = options.uri.host().ok_or("missing host in uri")?;
    let addrs = resolver.look_up(server_name).await?;

    tracing::info!("resolved {server_name} to address: {addrs:?}");

    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(include_bytes!("../../root.crt").to_certificate());

    // NAT Traversal
    let agents = [
        "1.12.74.4:20004".parse().unwrap(),
        "[2402:4e00:c011:1700:8624:7e0:5c9a:2]:20004"
            .parse()
            .unwrap(),
    ];

    let factory = TraversalFactory::with(&agents[..]);

    let mut binds = Vec::new();

    for device_ip in factory.devices().keys() {
        let device_ip = match device_ip.parse() {
            Ok(ip) => ip,
            Err(e) => {
                tracing::error!("Invalid device IP {}: {:?}", device_ip, e);
                continue;
            }
        };
        // TODO 此处使用 0 端口, 测试通过, 但不太确定是否有什么问题
        binds.push(SocketAddr::new(device_ip, 0));
    }

    let quic_client = ::gm_quic::QuicClient::builder()
        .with_root_certificates(roots)
        .without_cert()
        .with_alpns(["h3"])
        .with_iface_factory(factory)
        .with_parameters(client_parameters())
        .enable_sslkeylog()
        .bind(&binds[..])
        .inspect_err(|e| {
            tracing::error!("bind addrs: {binds:?}  err {e:?}");
        })?
        .build();

    let quic_connection = quic_client
        .connect(server_name, addrs[0])
        .map_err(|e| format!("failed to create quic connection: {e:?}"))?;
    tracing::warn!("aaa");
    let (mut h3_connection, mut send_request) =
        h3::client::new(h3_shim::QuicConnection::new(quic_connection).await)
            .await
            .map_err(|e| format!("failed to failed to establish http3 connection: {e:?}"))?;
    tracing::info!("http3 connection established");
    tokio::spawn(async move { h3_connection.wait_idle().await });

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

    tracing::info!("build request: {request:?}");

    let request_stream = send_request
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
        let dst: &mut (dyn AsyncWrite + Unpin) = if let Some(output) = options.output {
            &mut fs::File::create(output)
                .await
                .map_err(|e| format!("failed to create output file: {e:?}"))?
        } else {
            &mut tokio::io::stdout()
        };

        while let Some(mut data) = recv_stream.recv_data().await? {
            while data.has_remaining() {
                let chunk = data.chunk();
                dst.write_all(chunk).await?;
                data.advance(chunk.len());
            }
        }

        Result::<_, Error>::Ok(())
    };

    tokio::try_join!(send_request_body, receive_response)?;

    Ok(())
}

fn client_parameters() -> gm_quic::ClientParameters {
    let mut params = gm_quic::ClientParameters::default();

    params.set_initial_max_streams_bidi(100u32);
    params.set_initial_max_streams_uni(100u32);
    params.set_initial_max_data(1u32 << 20);
    params.set_initial_max_stream_data_uni(1u32 << 20);
    params.set_initial_max_stream_data_bidi_local(1u32 << 20);
    params.set_initial_max_stream_data_bidi_remote(1u32 << 20);

    params
}
