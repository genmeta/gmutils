use std::{fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};

mod auth;
mod mux;
mod socks;
mod terminal;

use clap::Parser;
use futures::{Sink, SinkExt, Stream, StreamExt, TryStream, TryStreamExt, channel::mpsc};
use genmeta_common::{
    AGENTS, ROOT_CERT, Resolvers, cbor_codec,
    h3_stream::{self, H3StreamReader},
};
use gm_quic::{QuicClient, ToCertificate};
use http::Uri;
use mux::ChannelMessage;
use qdns::{Resolve, UdpResolver};
use qtraversal::iface::TraversalFactory;
use tokio::{net::TcpListener, time};
use tokio_util::{codec, io::StreamReader, task::AbortOnDropHandle};

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

    #[arg(short = 'o', value_delimiter = ',')]
    options: Vec<String>,

    #[arg(
        short = 'T',
        default_value_t = true,
        action = clap::ArgAction::SetFalse,
        help = "Disable pseudo-terminal allocation."
    )]
    pseudo: bool,

    #[arg(
        trailing_var_arg = true,
        value_name = "[command [argument ...]]",
        help = "Command to execute on the remote server"
    )]
    commands: Vec<String>,
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
}

type Error = Box<dyn core::error::Error + Send + Sync>;

struct TerminalGuard(());

impl TerminalGuard {
    pub fn new() -> Self {
        crossterm::terminal::enable_raw_mode().expect("Failed to enable raw mode");
        TerminalGuard(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        crossterm::terminal::disable_raw_mode().expect("Failed to disable raw mode");
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

    let command = options.command().await?;

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

    let request = http::Request::builder()
        .method("PUT")
        .uri(options.uri.clone())
        .body(())?;
    tracing::info!(?request, "request");

    // sending request results in a bidirectional stream,
    // which is also used for receiving response
    let mut stream = h3_client.send_request(request).await?;
    let response = stream.recv_response().await?;
    tracing::info!(?response, "received");
    if response.status() != 200 {
        return Err(format!("Server response status: {}", response.status()).into());
    }

    let (message_sender, pending_messages) = mpsc::channel::<mux::ChannelMessage>(32);
    let mux = Arc::new(mux::Mux::new(message_sender, mux::Role::Client));

    let (mut sender, mut recver) = stream.split();
    let send_messages = AbortOnDropHandle::new(tokio::spawn(async move {
        let message_sender = codec::FramedWrite::new(
            h3_stream::H3StreamWriter::new(&mut sender),
            cbor_codec::CborEncoder::default(),
        );
        send_messages(message_sender, pending_messages).await
    }));

    let message_handler = mux.clone();
    let recv_messages = AbortOnDropHandle::new(tokio::spawn(async move {
        let message_recver = codec::FramedRead::new(
            StreamReader::new(H3StreamReader::new(&mut recver)),
            cbor_codec::CborDecoder::default(),
        );
        recv_messages(message_recver, message_handler).await
    }));

    let run = async move {
        let (username, password) = options.username_password();

        auth::login(&mux, &username, password.as_deref())
            .await
            .map_err(|e| format!("Failed to login: {e:?}"))?;

        // 初始化终端。guard自动释放
        let _guard = TerminalGuard::new();

        let run_command = AbortOnDropHandle::new(tokio::spawn({
            let mux = mux.clone();
            async move {
                if let Err(e) = command.run(&mux, options.pseudo).await {
                    tracing::error!("Failed to run command: {e:?}");
                }
            }
        }));

        let _dynamic_forward_task;
        if let Some(socks_listener) = dynamic_forward_server {
            let server = Arc::new(socks::SocksForwardServer::new(mux.clone()));
            _dynamic_forward_task = AbortOnDropHandle::new(tokio::spawn({
                let server = server.clone();
                async move {
                    let error = server.listen(socks_listener).await;
                    tracing::error!(target: "socks", "Socks forward server error: {error:?}");
                }
            }));
        }

        _ = run_command.await;
        tracing::info!("Command finished");

        Result::<(), Error>::Ok(())
    };

    let error = tokio::select! {
        // write messages to the stream
        _ = send_messages => None,
        // receive data from the stream and write to stdout
        _ = recv_messages => None,
        // send heartbeat messages to keep ssh connection alive
        Err(error) = run => Some(error),
        // wait for the quic connection to be terminated
        _ = quic_conn.terminated() => None,
        // wait for the h3 connection to be closed
        _ = h3_conn.wait_idle() => None,
    };

    // 清理
    quic_conn.close("Bye bye".into(), h3::error::Code::H3_NO_ERROR.value());

    error.map_or(Ok(()), Err)
}

async fn send_messages(
    mut message_sender: impl Sink<ChannelMessage, Error: Debug> + Unpin,
    mut pending_messages: impl Stream<Item = ChannelMessage> + Unpin,
) {
    while let Some(message) = pending_messages.next().await {
        if let Err(send_error) = message_sender.send(message).await {
            tracing::error!("Failed to send message: {send_error:?}");
            break;
        }
    }
}

async fn recv_messages(
    mut message_recver: impl TryStream<Ok = ChannelMessage, Error: Debug> + Unpin,
    mux: Arc<mux::Mux>,
) {
    loop {
        let message: ChannelMessage = match message_recver.try_next().await {
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

        tracing::trace!(?message, "Received message");
        if let Err(e) = mux.receive(message).await {
            tracing::error!("Failed to receive message: {e:?}");
        }
    }
}

// async fn recv_messages<S>(
//     mut message_recver: impl TryStream<Ok = ServerMessage, Error: Debug> + Unpin,
//     socks_forward_server: Option<Arc<socks::SocksForwardServer<S>>>,
// ) where
//     S: Sink<socks::ClientSocksMessage, Error: Debug + Send> + Clone + Send + Unpin + 'static,
// {
//     loop {
//         let message: ServerMessage = match message_recver.try_next().await {
//             Ok(Some(message)) => message,
//             Ok(None) => {
//                 tracing::info!("Peer closed the stream");
//                 break;
//             }
//             Err(recv_error) => {
//                 tracing::error!("Read from peer error: {recv_error:?}");
//                 break;
//             }
//         };

//         match message {
//             ServerMessage::Terminal { sequence } => {
//                 // 不知为何往tokio::stdin写时会缺少一行输出，所以
//                 let write_to_stdout = tokio::task::spawn_blocking(move || {
//                     use std::io::Write;
//                     let mut stdout = std::io::stdout().lock();
//                     stdout.write_all(&sequence)?;
//                     stdout.flush()
//                 });

//                 if let Err(e) = write_to_stdout.await {
//                     tracing::error!("Write to stdout error: {e}");
//                     break;
//                 }
//             }
//             ServerMessage::Socks(server_socks_message) => {
//                 if let Some(socks_forward_server) = &socks_forward_server {
//                     match server_socks_message {
//                         socks::ServerSocksMessage::Data { token, data } => {
//                             socks_forward_server.receive(token, data).await;
//                         }
//                         socks::ServerSocksMessage::Error { token, error } => {
//                             let _ = error; //TODO
//                             socks_forward_server.close(token);
//                         }
//                     }
//                 }
//             }
//             ServerMessage::Heartbeat => {}
//         }
//     }
// }

// async fn handle_winresize(mut tx: mpsc::Sender<ClientMessage>) {
//     let mut update_winsize = async || {
//         let message = match terminal::size() {
//             Ok((cols, rows)) => ClientMessage::WindowSize { rows, cols },
//             Err(e) => {
//                 return Err(Error::from(format!("Failed to get terminal size: {e}")));
//             }
//         };
//         if tx.send(message).await.is_err() {
//             return Err("Event channel closed".into());
//         }
//         Ok(())
//     };

//     if let Err(e) = update_winsize().await {
//         tracing::error!("Failed to update terminal size: {e}");
//     };

//     let mut signal_listener = match signal(SignalKind::window_change()) {
//         Ok(listener) => listener,
//         Err(e) => {
//             tracing::error!("Failed to create signal handler for SIGWINCH: {e}");
//             return;
//         }
//     };

//     while let Some(()) = signal_listener.recv().await {
//         if let Err(e) = update_winsize().await {
//             tracing::error!("Failed to update terminal size: {e}");
//         };
//     }
// }

// async fn handle_stdin(mut tx: mpsc::Sender<ClientMessage>) {
//     // tokio::io::stdin() 不适合交互使用，读文档了解详情
//     let tracing_span = tracing::Span::current();
//     let (sequence_tx, mut sequence_rx) = tokio::sync::mpsc::channel(32);
//     std::thread::spawn(move || {
//         let _entered = tracing_span.entered();
//         loop {
//             let mut buf = [0; 4096];
//             match std::io::stdin().read(&mut buf) {
//                 Ok(nread) => {
//                     if sequence_tx
//                         .blocking_send(buf[..nread].to_vec().into())
//                         .is_err()
//                     {
//                         return;
//                     }
//                 }
//                 Err(e) => {
//                     tracing::error!("Failed to read from stdin: {e}");
//                     break;
//                 }
//             }
//         }
//     });

//     while let Some(sequence) = sequence_rx.recv().await {
//         let message = ClientMessage::Terminal { sequence };
//         if tx.send(message).await.is_err() {
//             tracing::error!("Event channel closed");
//             return;
//         }
//     }
// }

// async fn heartbeat(mut tx: mpsc::Sender<ClientMessage>) {
//     let mut interval = tokio::time::interval(Duration::from_secs(20));
//     loop {
//         interval.tick().await;
//         let message = ClientMessage::Heartbeat;
//         if tx.send(message).await.is_err() {
//             return;
//         }
//     }
// }

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
