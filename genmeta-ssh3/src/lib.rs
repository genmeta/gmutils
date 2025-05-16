use std::{
    fmt::Debug,
    io::Read,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

mod socks;

use bytes::Bytes;
use clap::Parser;
use crossterm::terminal;
use futures::{Sink, SinkExt, Stream, StreamExt, TryStream, TryStreamExt, channel::mpsc};
use genmeta_common::{
    AGENTS, ROOT_CERT, Resolvers, cbor_codec,
    h3_stream::{self, H3StreamReader},
    map_sink::MapSinkExt,
};
use gm_quic::{QuicClient, ToCertificate};
use http::Uri;
use qdns::{Resolve, UdpResolver};
use qtraversal::iface::TraversalFactory;
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    time,
};
use tokio_util::{codec, io::StreamReader, task::AbortOnDropHandle};

// 定义客户端与服务器通信的消息结构
#[derive(Serialize, Debug)]
enum ClientMessage {
    WindowSize { rows: u16, cols: u16 },
    Terminal { sequence: Bytes },
    Socks(socks::ClientSocksMessage),
    Heartbeat,
}

#[derive(Deserialize, Debug)]
enum ServerMessage {
    Terminal { sequence: Bytes },
    Socks(socks::ServerSocksMessage),
    Heartbeat,
}

const URI_LONG_HELP: &str = "Example: `developer@ssh3.test.genmeta.net`
Scheme is optional, only `ssh3` is accepted.
Username is optional, if not present, use current user.
Password is optional, if not present, prompt for it.
Path is optional, if not present, use `/ssh` as default.";

const DYNAMIC_FORWARD_LONG_HELP: &str = "Example: `12345`, `127.0.0.1:12335`
Specify a local address port, which will forward the accepted TCP connection to the server's SOCKS server.
You can specify just the port, and the bind_address defaults to 127.0.0.1.";

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    #[arg(value_name = "[ssh3://][[username][:password]@]host[:port][path]", long_help = URI_LONG_HELP)]
    uri: Uri,
    #[arg(short = 'D', value_name = "[bind_address:]port", long_help = DYNAMIC_FORWARD_LONG_HELP)]
    dynamic_forward: Option<String>,
}

impl Options {
    fn complete_uri(self) -> Result<Self, Error> {
        let mut uri_parts = self.uri.into_parts();
        uri_parts.scheme = match uri_parts.scheme {
            Some(ref scheme) if scheme.as_str() == "ssh3" => uri_parts.scheme,
            None => Some("ssh3".parse().unwrap()),
            Some(scheme) => {
                let message = format!(
                    "Unsupported scheme `{scheme}` for ssh. Scheme in uri is must not be present or be `ssh3`"
                );
                return Err(message.into());
            }
        };
        uri_parts.path_and_query = match uri_parts.path_and_query {
            root if root.as_ref().is_none_or(|path| path == "/") => {
                tracing::warn!("Path is empty, using `/ssh` as default");
                Some("/ssh".parse().unwrap())
            }
            path_and_query => path_and_query,
        };
        Ok(Self {
            uri: Uri::from_parts(uri_parts)?,
            ..self
        })
    }

    fn username_password(&self) -> (String, Option<String>) {
        let try_from_uri = |username_password: &str| {
            username_password
                .split_once(':')
                .map(|(username, password)| (username.to_string(), Some(password.to_string())))
                .unwrap_or((username_password.to_string(), None))
        };
        self.uri
            .authority()
            .and_then(|authority| authority.as_str().rsplit_once('@'))
            .map(|(username_password, _host)| try_from_uri(username_password))
            .unwrap_or_else(|| (whoami::username(), None))
    }

    fn dynamic_forward_server(&self) -> Option<Result<SocketAddr, Error>> {
        let bind_address = self.dynamic_forward.as_ref()?;
        match bind_address.parse::<SocketAddr>().ok().or_else(|| {
            bind_address
                .parse::<u16>()
                .map(|port| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))
                .ok()
        }) {
            Some(bind_address) => Some(Ok(bind_address)),
            None => Some(Err(format!(
                "Invalid bind address argument `{bind_address}` provide:"
            )
            .into())),
        }
    }
}

type Error = Box<dyn core::error::Error + Send + Sync>;

struct TerminalGuard(());
impl TerminalGuard {
    pub fn new() -> Self {
        terminal::enable_raw_mode().expect("Failed to enable raw mode");
        TerminalGuard(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        terminal::disable_raw_mode().expect("Failed to disable raw mode");
    }
}

pub async fn run(options: Options) -> Result<(), Error> {
    let options = options
        .complete_uri()
        .map_err(|e| format!("Failed to complete URI: {e:?}"))?;

    let dynamic_forward_server = match options.dynamic_forward_server().transpose()? {
        Some(bind_addr) => Some(
            TcpListener::bind(bind_addr)
                .await
                .map_err(|e| format!("Failed to bind local dynamic forward server: {e:?}"))?,
        ),
        None => None,
    };

    let resolvers = Resolvers::new()
        // .with(HttpResolver::new("http://127.0.0.1:20004/v1/dns/")?)
        .with(UdpResolver::new(Resolvers::UDP_DNS_SERVER));
    // let resolver = UdpResolver::new("1.12.74.4:5300".parse().unwrap());
    let server_name = options.uri.host().ok_or("Missing host in uri")?;
    let server_addrs = resolvers
        .lookup(server_name)
        .await
        .map_err(|e| format!("failed to resolve host {server_name}: {e:?}"))?;

    tracing::info!("resolved {} to address: {:?}", server_name, server_addrs);

    let quic_client = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ROOT_CERT.to_certificate());

        let factory = TraversalFactory::with(&AGENTS);
        let binds = factory
            .devices()
            .keys()
            .map(|device_ip| SocketAddr::new(*device_ip, 0))
            .collect::<Vec<_>>();
        QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .with_alpns(["h3"])
            .with_iface_factory(factory)
            .with_parameters(client_parameters())
            .enable_sslkeylog()
            .reuse_address()
            .bind(&binds[..])
            .inspect_err(|e| {
                tracing::error!("bind addrs {binds:?} failed: {e:?}");
            })?
            .build()
    };

    let (quic_conn, mut h3_conn, mut h3_client) = {
        tracing::info!(server_name, ?server_addrs, "connect to server");
        let mut connect_result = Result::Err(Error::from("Dns not found"));
        for server_addr in server_addrs {
            let attempt = async {
                let quic_conn = quic_client.connect(server_name, server_addr)?;
                let connect = async {
                    h3::client::new(h3_shim::QuicConnection::new(quic_conn.clone()).await).await
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
                    tracing::error!("attempt connect to server {server_addr} failed: error");
                    connect_result = Err(error)
                }
            }
        }
        connect_result?
    };

    // 构建 Basic Auth 头
    let basic_auth = {
        use base64::Engine;
        let credentials = match options.username_password() {
            (username, Some(password)) => {
                format!("{username}:{password}")
            }
            (username, None) => username,
        };
        base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
    };

    tracing::info!(%options.uri, "request");
    let request = http::Request::builder()
        .method("PUT")
        .uri(options.uri)
        .header("Authorization", format!("Basic {basic_auth}"))
        .body(())?;

    // sending request results in a bidirectional stream,
    // which is also used for receiving response
    let mut stream = h3_client.send_request(request).await?;
    let response = stream.recv_response().await?;
    tracing::info!(?response, "received");
    if response.status() != 200 {
        return Err(format!("Server response status: {}", response.status()).into());
    }

    let (mut sender, mut receiver) = stream.split();

    let message_sender = codec::FramedWrite::new(
        h3_stream::H3StreamWriter::new(&mut sender),
        cbor_codec::CborEncoder::default(),
    );

    let message_recver = codec::FramedRead::new(
        StreamReader::new(H3StreamReader::new(&mut receiver)),
        cbor_codec::CborDecoder::default(),
    );

    let (mut tx, pending_messages) = mpsc::channel::<ClientMessage>(32);

    let _dynamic_forward_task;
    let socks_forward_server = match dynamic_forward_server {
        Some(listener) => {
            let message_sender = tx
                .clone()
                .mapped(|message| Ok(ClientMessage::Socks(message)));
            let server = Arc::new(socks::SocksForwardServer::new(message_sender));
            _dynamic_forward_task = AbortOnDropHandle::new(tokio::spawn({
                let server = server.clone();
                async move { server.listen(listener).await }
            }));
            Some(server)
        }
        None => None,
    };

    // 初始化终端
    let _guard = TerminalGuard::new();

    tokio::select! {
        // read and encode messages from stdin
        _ = handle_stdin(tx.clone()) => (),
        // handle window resize events
        _ = handle_winresize(tx.clone())=> (),
        // write messages to the stream
        _ = send_messages(message_sender, pending_messages) => (),
        // receive data from the stream and write to stdout
        _ = recv_messages(message_recver, socks_forward_server) => (),
        // send heartbeat messages to keep ssh connection alive
        _ = heartbeat(tx.clone()) => (),
        // wait for the quic connection to be terminated
        _ = quic_conn.terminated() => (),
        // wait for the h3 connection to be closed
        _ = h3_conn.wait_idle() => (),
    }

    // 清理
    terminal::disable_raw_mode()?;
    tx.close_channel();
    quic_conn.close("Bye bye".into(), h3::error::Code::H3_NO_ERROR.value());

    Ok(())
}

async fn send_messages(
    mut sender: impl Sink<ClientMessage, Error: Debug> + Unpin,
    mut rx: impl Stream<Item = ClientMessage> + Unpin,
) {
    while let Some(message) = rx.next().await {
        if let Err(send_error) = sender.send(message).await {
            tracing::error!("Failed to send message: {send_error:?}");
            break;
        }
    }
}

async fn recv_messages<S>(
    mut message_recver: impl TryStream<Ok = ServerMessage, Error: Debug> + Unpin,
    socks_forward_server: Option<Arc<socks::SocksForwardServer<S>>>,
) where
    S: Sink<socks::ClientSocksMessage, Error: Debug + Send> + Clone + Send + Unpin + 'static,
{
    loop {
        let message: ServerMessage = match message_recver.try_next().await {
            Ok(Some(message)) => message,
            Ok(None) => {
                tracing::info!("Peer closed the stream");
                break;
            }
            Err(recv_error) => {
                tracing::error!("Read from peer error: {recv_error:?}");
                break;
            }
        };

        match message {
            ServerMessage::Terminal { sequence } => {
                // 不知为何往tokio::stdin写时会缺少一行输出，所以
                let write_to_stdout = tokio::task::spawn_blocking(move || {
                    use std::io::Write;
                    let mut stdout = std::io::stdout().lock();
                    stdout.write_all(&sequence)?;
                    stdout.flush()
                });

                if let Err(e) = write_to_stdout.await {
                    tracing::error!("Write to stdout error: {e}");
                    break;
                }
            }
            ServerMessage::Socks(server_socks_message) => {
                if let Some(socks_forward_server) = &socks_forward_server {
                    match server_socks_message {
                        socks::ServerSocksMessage::Data { token, data } => {
                            socks_forward_server.receive(token, data).await;
                        }
                        socks::ServerSocksMessage::Error { token, error } => {
                            let _ = error; //TODO
                            socks_forward_server.close(token);
                        }
                    }
                }
            }
            ServerMessage::Heartbeat => {}
        }
    }
}

async fn handle_winresize(mut tx: mpsc::Sender<ClientMessage>) {
    let mut update_winsize = async || {
        let message = match terminal::size() {
            Ok((cols, rows)) => ClientMessage::WindowSize { rows, cols },
            Err(e) => {
                return Err(Error::from(format!("Failed to get terminal size: {e}")));
            }
        };
        if tx.send(message).await.is_err() {
            return Err("Event channel closed".into());
        }
        Ok(())
    };

    if let Err(e) = update_winsize().await {
        tracing::error!("Failed to update terminal size: {e}");
    };

    let mut signal_listener = match signal(SignalKind::window_change()) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("Failed to create signal handler for SIGWINCH: {e}");
            return;
        }
    };

    while let Some(()) = signal_listener.recv().await {
        if let Err(e) = update_winsize().await {
            tracing::error!("Failed to update terminal size: {e}");
        };
    }
}

async fn handle_stdin(mut tx: mpsc::Sender<ClientMessage>) {
    // tokio::io::stdin() 不适合交互使用，读文档了解详情
    let tracing_span = tracing::Span::current();
    let (sequence_tx, mut sequence_rx) = tokio::sync::mpsc::channel(32);
    std::thread::spawn(move || {
        let _entered = tracing_span.entered();
        loop {
            let mut buf = [0; 4096];
            match std::io::stdin().read(&mut buf) {
                Ok(nread) => {
                    if sequence_tx
                        .blocking_send(buf[..nread].to_vec().into())
                        .is_err()
                    {
                        return;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to read from stdin: {e}");
                    break;
                }
            }
        }
    });

    while let Some(sequence) = sequence_rx.recv().await {
        let message = ClientMessage::Terminal { sequence };
        if tx.send(message).await.is_err() {
            tracing::error!("Event channel closed");
            return;
        }
    }
}

async fn heartbeat(mut tx: mpsc::Sender<ClientMessage>) {
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    loop {
        interval.tick().await;
        let message = ClientMessage::Heartbeat;
        if tx.send(message).await.is_err() {
            return;
        }
    }
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
