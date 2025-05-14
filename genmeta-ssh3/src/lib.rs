use std::{io::Read, net::SocketAddr, time::Duration};

use bytes::{Buf, Bytes};
use clap::Parser;
use crossterm::terminal;
use futures::{SinkExt, StreamExt, channel::mpsc};
use genmeta_common::{AGENTS, ROOT_CERT, Resolvers};
use gm_quic::{QuicClient, ToCertificate};
use http::Uri;
use qdns::{Resolve, UdpResolver};
use qtraversal::iface::TraversalFactory;
use serde::Serialize;
use tokio::{
    signal::unix::{SignalKind, signal},
    time,
};

// 定义客户端与服务器通信的消息结构
#[derive(Serialize, Debug)]
enum TerminalMessage {
    WindowSize { rows: u16, cols: u16 },
    Terminal { sequence: Vec<u8> },
    // ControlSequence(String),
    Heartbeat,
}

const URI_HELP: &str = "Example: `ssh3://user:password@host:port/ssh`.
    Scheme is optional, only `ssh3` is accepted.
    Username is optional, if not present, use current user.
    Password is optional, if not present, prompt for it.
    Path is optional, if not present, use `/ssh` as default.";

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    #[arg(help = URI_HELP)]
    uri: Uri,
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

    // 创建通道用于异步通信
    let (mut tx, rx) = mpsc::channel::<TerminalMessage>(32);

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

    let (sender, receiver) = stream.split();

    // 初始化终端
    // execute!(std::io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    let _guard = TerminalGuard::new();

    tokio::select! {
        // read and encode messages from stdin
        _ = handle_stdin(tx.clone()) => (),
        // handle window resize events
        _ = handle_winresize(tx.clone())=> (),
        // write messages to the stream
        _ = tokio::spawn(send(sender, rx)) => (),
        // receive data from the stream and write to stdout
        _ = tokio::spawn(recv(receiver)) => (),
        // send heartbeat messages to keep ssh connection alive
        _ = tokio::spawn(heartbeat(tx.clone())) => (),
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

async fn send(
    mut sender: h3::client::RequestStream<h3_shim::SendStream<Bytes>, Bytes>,
    mut rx: mpsc::Receiver<TerminalMessage>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            msg = rx.next() => match msg {
                Some(msg) => {
                    let serialized = serde_cbor::to_vec(&msg).unwrap();
                    if let Err(e) = sender.send_data(serialized.into()).await {
                        tracing::error!("Send to peer error: {e}");
                        break;
                    }
                }
                None => {
                    if let Err(e) = sender.finish().await {
                        tracing::error!("Finish stream error: {e}");
                    }
                    break;
                }
            },
            _ = interval.tick() => {
                let serialized = serde_cbor::to_vec(&TerminalMessage::Heartbeat).unwrap();
                if let Err(e) = sender.send_data(serialized.into()).await {
                    tracing::error!("Send heartbeat error: {e}");
                    break;
                }
            }
        }
    }
}

async fn recv(mut receiver: h3::client::RequestStream<h3_shim::RecvStream, Bytes>) {
    loop {
        match receiver.recv_data().await {
            Ok(Some(mut data)) => {
                // 不知为何往tokio::stdin写时会缺少一行输出
                let write_result = tokio::task::spawn_blocking(move || {
                    use std::io::Write;
                    let mut stdout = std::io::stdout().lock();
                    while data.has_remaining() {
                        let chunk = data.chunk();
                        stdout.write_all(chunk)?;
                        data.advance(chunk.len());
                    }
                    stdout.flush()
                })
                .await;

                if let Err(e) = write_result.unwrap() {
                    tracing::error!("Write to stdout error: {e}");
                    receiver.stop_sending(h3::error::Code::H3_NO_ERROR);
                    break;
                }
            }
            Ok(None) => {
                tracing::info!("Peer closed the stream");
                break;
            }
            Err(e) => {
                tracing::error!("Read from peer error: {e}");
                receiver.stop_sending(h3::error::Code::H3_NO_ERROR);
                break;
            }
        }
    }
}

async fn handle_winresize(mut tx: mpsc::Sender<TerminalMessage>) {
    let mut update_winsize = async || {
        let message = match terminal::size() {
            Ok((cols, rows)) => TerminalMessage::WindowSize { rows, cols },
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

async fn handle_stdin(mut tx: mpsc::Sender<TerminalMessage>) {
    // tokio::io::stdin() 不适合交互使用，读文档了解详情
    let tracing_span = tracing::Span::current();
    let (sequence_tx, mut sequence_rx) = tokio::sync::mpsc::channel(32);
    std::thread::spawn(move || {
        let _entered = tracing_span.entered();
        loop {
            let mut buf = [0; 4096];
            match std::io::stdin().read(&mut buf) {
                Ok(nread) => {
                    if sequence_tx.blocking_send(buf[..nread].to_vec()).is_err() {
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
        let message = TerminalMessage::Terminal { sequence };
        if tx.send(message).await.is_err() {
            tracing::error!("Event channel closed");
            return;
        }
    }
}

async fn heartbeat(mut tx: mpsc::Sender<TerminalMessage>) {
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    loop {
        interval.tick().await;
        let message = TerminalMessage::Heartbeat;
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
