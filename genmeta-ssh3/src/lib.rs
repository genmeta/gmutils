use std::{fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};

mod auth;
mod config;
mod forward;
mod session;
mod socks;
use clap::Parser;
use futures::{FutureExt, StreamExt};
use genmeta_common::{
    AGENTS, ROOT_CERT, cbor_codec,
    h3_stream::{self, H3Stream},
};
use gm_quic::{ToCertificate, handy::client_parameters};
use http::Uri;
use qdns::{HttpResolver, MdnsResolver, Resolvers, UdpResolver};
use qtraversal::iface::traversal_factory;
use ssh3_proto::{listener, messages, mux};
use tokio::time;
use tokio_util::{codec, io::StreamReader};

const URI_LONG_HELP: &str = "Example: `my-remote-dev`, `developer@ssh3.test.genmeta.net`
If this argument matches the ssh configuration file, \
the HostName and User of the matched Host will be used. \
Otherwise the argument will be parsed as a URI. URIs follow these rules: \
Scheme is optional, only `ssh3` is accepted. \
Username is optional, if not present, use current user. \
Password is optional, if not present, prompt for it. \
Path is optional, if not present, use `/ssh` as default.";

const OPTIONS_LONG_HELP: &str =
    "Set options for the SSH connection, currently all options are ignored.";

const DYNAMIC_FORWARD_LONG_HELP: &str = "Example: `12345`, `127.0.0.1:12335`
Start a Socks server on the specified local port, forward the connection to the server and decide which address \
the server should connect to based on the application protocol.\
You can specify just the port, while an empty address or `*` indicates that the port should be available from all interfaces.";

const LOCAL_FORWARDING_LONG_HELP: &str = "
Specifies that connections to the given TCP port or Unix \
socket on the local (client) host are to be forwarded to \
the given host and port, or Unix socket, on the remote \
side.
This works by allocating a socket to listen to \
either a TCP port on the local side, optionally bound to \
the specified bind_address, or to a Unix socket.  Whenever \
a connection is made to the local port or socket, the \
connection is forwarded over the secure channel, and a \
connection is made to either host port hostport, or the \
Unix socket remote_socket, from the remote machine.";

const REMOTE_FORWARDING_LONG_HELP: &str = "
Specifies that connections to the given TCP port or Unix socket on the remote (server) host \
are to be forwarded to the local side.
This works by allocating a socket to listen to either a \
TCP port or to a Unix socket on the remote side.  Whenever \
a connection is made to this port or Unix socket, the \
connection is forwarded over the secure channel, and a \
connection is made from the local machine to either an \
explicit destination specified by host port hostport, or \
local_socket, or, if no explicit destination was \
specified, ssh will act as a SOCKS 4/5 proxy and forward \
connections to the destinations requested by the remote \
SOCKS client.";

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    #[arg(value_name = "HOST/URI", long_help = URI_LONG_HELP)]
    uri: Uri,

    #[arg(
        short = 'o',
        value_name = "option",
        value_delimiter = ',',
        long_help = OPTIONS_LONG_HELP
    )]
    options: Vec<String>,

    #[arg(
        short = 'T',
        default_value_t = true,
        action = clap::ArgAction::SetFalse,
        help = "Disable pseudo-terminal allocation."
    )]
    pseudo: bool,

    #[arg(
        short = 'l',
        value_name = "login_name",
        help = "Specifies the user to log in as on the remote machine."
    )]
    login_name: Option<String>,

    #[arg(short = 'D', value_name = "[bind_address:]port", long_help = DYNAMIC_FORWARD_LONG_HELP)]
    dynamic_forward: Vec<String>,

    #[arg(
        short = 'L',
        value_name = "[bind_address:]port:host:hostport / [bind_address:]port:remote_socket / local_socket:host:hostport / local_socket:remote_socket",
        long_help = LOCAL_FORWARDING_LONG_HELP
    )]
    local_forwards: Vec<String>,

    // TODO：不二次处理，在解析中直接处理好
    #[arg(
        short = 'R',
        value_name = "[bind_address:]port:host:hostport / [bind_address:]port:local_socket / remote_socket:host:hostport / remote_socket:local_socket / [bind_address:]port",
        long_help = REMOTE_FORWARDING_LONG_HELP
    )]
    remote_forwards: Vec<String>,

    #[arg(
        trailing_var_arg = true,
        value_name = "command [argument ...]",
        help = "Command to execute on the remote server."
    )]
    commands: Vec<String>,
}

// TODO: 使用Snafu
type Error = Box<dyn core::error::Error + Send + Sync>;

struct TerminalGuard(());

impl TerminalGuard {
    pub fn new() -> Self {
        tracing::info!(target: "session", "Enable raw mode");
        crossterm::terminal::enable_raw_mode().expect("Failed to enable raw mode");
        TerminalGuard(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        tracing::info!(target: "session", "Disable raw mode(RAII)");
        crossterm::terminal::disable_raw_mode().expect("Failed to disable raw mode");
    }
}

pub async fn run(options: Options) -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::OFF.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();
    let config = options.config().await?;
    tracing::info!(target: "config", ?config, "Parsed config");

    let dynamic_forward_endpoints = options.dynamic_forward_endpoints().await?;
    let local_forward_rules = options.local_forward_rules()?;
    let remote_forward_rules = options.remote_forward_rules()?;

    tracing::info!(target: "config", ?dynamic_forward_endpoints, ?local_forward_rules, ?remote_forward_rules, "Forwards");

    let dynamic_forward_listeners =
        {
            let mut listeners = Vec::new();
            for &local_addr in &dynamic_forward_endpoints {
                listeners.push((listener::Listener::bind(local_addr.into()).await).map_err(
                    |e| format!("Failed to bind to dynamic forward endpoint`{local_addr}`: {e:?}"),
                )?);
            }
            listeners
        };
    let local_forwards = {
        let mut forwards = Vec::new();
        for (local_endpoint, remote_endpoint) in local_forward_rules {
            let listener =
                (listener::Listener::bind(local_endpoint.clone()).await).map_err(|e| {
                    format!("Failed to bind to local forward endpoint `{local_endpoint}`: {e:?}")
                })?;
            forwards.push((local_endpoint, listener, remote_endpoint));
        }
        forwards
    };

    let resolvers = Resolvers::new()
        .with(Arc::new(HttpResolver::new(qdns::HTTP_DNS_SERVER)?))
        .with(Arc::new(MdnsResolver::new(qdns::MDNS_SERVICE)?))
        .with(Arc::new(UdpResolver::new(qdns::UDP_DNS_SERVER)));
    // let resolver = UdpResolver::new("1.12.74.4:5300".parse().unwrap());
    let server_name =
        (config.uri.host()).ok_or_else(|| format!("Host missing in URI: {}", config.uri))?;

    let mut dns_lookup = resolvers.lookup(server_name);
    let (_source, server_eps) = dns_lookup
        .next()
        .await
        .ok_or(format!("No endpoints found for server: {server_name}"))?;

    let quic_client = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ROOT_CERT.to_certificate());

        let factory = traversal_factory(&AGENTS);
        gm_quic::QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .with_parameters(client_parameters())
            .with_iface_factory(factory.as_ref().clone())
            .bind(factory.devices().keys().map(|ip| SocketAddr::new(*ip, 0)))
            .enable_sslkeylog()
            .build()
    };

    let (quic_conn, mut h3_conn, mut h3_client) = {
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

    let request = http::Request::builder()
        .method("PUT")
        .uri(config.uri)
        .body(())?;
    tracing::info!(target: "connect", ?request, "request");

    // sending request results in a bidirectional stream,
    // which is also used for receiving response
    let mut stream = h3_client.send_request(request).await?;
    let response = stream.recv_response().await?;
    tracing::info!(target: "connect", ?response, "Received");
    if response.status() != 200 {
        return Err(format!("Server response status: {}", response.status()).into());
    }

    let (sender, recver) = stream.split();
    let (mux, mut incomings) = mux::Mux::new(
        mux::Role::Client,
        codec::FramedRead::new(
            StreamReader::new(H3Stream::new(recver)),
            cbor_codec::CborDecoder::default(),
        ),
        codec::FramedWrite::new(
            h3_stream::H3Sink::new(sender),
            cbor_codec::CborEncoder::default(),
        ),
    );

    let remote_forwarders = Arc::new(forward::RemoteForwardAcceptor::new(mux.clone()));

    let recv_requests = {
        let remote_forwarders = remote_forwarders.clone();
        async move {
            while let Some(message) = incomings.next().await {
                let Ok(new_channel) = message else {
                    return Err("Failed to parse message from server, check the version?".into());
                };
                match new_channel.request {
                    messages::OpenChannel::Forwarded { listen, to } => {
                        if let Some(remote_forward_task) = remote_forwarders
                            .accpet(listen, to, new_channel.recver, new_channel.sender)
                            .await?
                        {
                            tokio::spawn(async move {
                                if let Err(e) = remote_forward_task.await {
                                    tracing::error!(target: "remote_forward", "Error in remote forward task: {e:?}");
                                }
                            });
                        }
                    }
                    _ => {
                        return Err(Error::from(format!(
                            "Unexpected message from server: {:?}",
                            new_channel.request
                        )));
                    }
                }
            }
            Result::<_, Error>::Ok(())
        }
    };

    let run = async move {
        let (username, password) = (config.username, config.password);

        auth::login(&mux, &username, password.as_deref())
            .await
            .map_err(|e| format!("Failed to login: {e:?}"))?;

        let session = tokio::spawn({
            let mux = mux.clone();
            let command = options.command();
            async move {
                // 初始化终端。guard自动释放
                let raw_terminal_guard = TerminalGuard::new();
                match command.run(&mux, options.pseudo).await {
                    Ok(code) => {
                        drop(raw_terminal_guard); // 在退出之前恢复终端
                        std::process::exit(code)
                    }
                    Err(e) => {
                        tracing::error!(target: "session", "Failed to run command: {e:?}");
                        Err(e)
                    }
                }
            }
        });

        for (local, listener, remote) in local_forwards {
            let forwarder =
                forward::Forwarder::new(mux.clone(), messages::OpenChannel::Direct { to: remote });
            let listen_task =
                listener.listen(move |reader, writer| forwarder.forward(reader, writer).boxed());
            tokio::spawn(async move {
                let error = listen_task.await;
                tracing::error!(target: "local_forward", "Local forward server listen on {local} error: {error:?}");
            });
        }

        for (local, remote) in remote_forward_rules {
            let forward_task = remote_forwarders.forward(local, remote.clone()).await?;
            let forward_task = async move {
                if let Err(error) = forward_task.await {
                    tracing::error!(target: "remote_forward", "Remote server failed to accpet connections from {remote}: {error:?}");
                }
            };
            tokio::spawn(forward_task);
        }

        for dynamic_forward_listener in dynamic_forward_listeners {
            let listen_task = socks::listen_dynamic_forward(mux.clone(), dynamic_forward_listener);
            tokio::spawn({
                async move {
                    let error = listen_task.await;
                    tracing::error!(target: "socks", "Socks forward server error: {error:?}");
                }
            });
        }

        session.await??;

        Result::<(), Error>::Ok(())
    };

    let error = tokio::select! {
        // send heartbeat messages to keep ssh connection alive
        result = async { tokio::try_join!(recv_requests, run) } => result.err(),
        // wait for the quic connection to be terminated
        _ = quic_conn.terminated() => None,
        // wait for the h3 connection to be closed
        _ = h3_conn.wait_idle() => None,
    };

    // 清理
    quic_conn.close("Bye bye", h3::error::Code::H3_NO_ERROR.value());

    error.map_or(Ok(()), Err)
}
