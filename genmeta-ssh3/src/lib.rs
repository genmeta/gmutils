use std::{fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};

mod auth;
mod config;
mod forward;
mod session;
mod socks;
use clap::Parser;
use futures::{FutureExt, StreamExt};
use genmeta_common::{
    AGENTS, ROOT_CERT, Resolvers, cbor_codec,
    h3_stream::{self, H3Stream},
};
use gm_quic::{QuicClient, ToCertificate};
use http::Uri;
use qdns::{Resolve, UdpResolver};
use qtraversal::iface::TraversalFactory;
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
    server: Uri,

    #[arg(
        short = 'o',
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

    #[arg(short = 'D', value_name = "[bind_address:]port", long_help = DYNAMIC_FORWARD_LONG_HELP)]
    dynamic_forward: Vec<String>,

    #[arg(
        short = 'L',
        value_name = "[bind_address:]port:host:hostport / [bind_address:]port:remote_socket / local_socket:host:hostport / local_socket:remote_socket",
        long_help = LOCAL_FORWARDING_LONG_HELP
    )]
    local_forwards: Vec<String>,

    #[arg(
        short = 'R',
        value_name = "[bind_address:]port:host:hostport / [bind_address:]port:local_socket / remote_socket:host:hostport / remote_socket:local_socket / [bind_address:]port",
        long_help = REMOTE_FORWARDING_LONG_HELP
    )]
    remote_forwards: Vec<String>,

    #[arg(
        trailing_var_arg = true,
        value_name = "[command [argument ...]]",
        help = "Command to execute on the remote server."
    )]
    commands: Vec<String>,
}

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
    let config = options.profile().await?;

    let dynamic_forward_endpoints = options.dynamic_forward_endpoints().await?;
    let local_forward_rules = options.local_forward_rules()?;
    let remote_forward_rules = options.remote_forward_rules()?;

    tracing::info!(target: "config", ?dynamic_forward_endpoints, ?local_forward_rules, ?remote_forward_rules);

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
        // .with(HttpResolver::new("http://127.0.0.1:20004/v1/dns/")?)
        .with(UdpResolver::new(Resolvers::UDP_DNS_SERVER));
    // let resolver = UdpResolver::new("1.12.74.4:5300".parse().unwrap());
    let server_name =
        (config.uri.host()).ok_or_else(|| format!("Host missing in URI: {}", config.uri))?;

    let server_addrs = resolvers
        .lookup(server_name)
        .await
        .map_err(|e| format!("failed to resolve host {server_name}: {e:?}"))?;

    tracing::info!(target: "connect", "Resolved {} to address: {:?}", server_name, server_addrs);

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
                tracing::error!(target: "connect", "Bind addrs {binds:?} failed: {e:?}");
            })?
            .build()
    };

    let (quic_conn, mut h3_conn, mut h3_client) = {
        tracing::info!(target: "connect", server_name, ?server_addrs, "Attempt connect to server");
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
                    tracing::error!(target: "connect", "Attempt connect to server {server_addr} failed: error");
                    connect_result = Err(error)
                }
            }
        }
        connect_result?
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
            while let Some(Ok(mux::NewChannel {
                token: _,
                request,
                sender,
                recver,
            })) = incomings.next().await
            {
                match request {
                    messages::OpenChannel::Forwarded { listen, to } => {
                        if let Some(remote_forward_task) =
                            remote_forwarders.accpet(listen, to, recver, sender).await?
                        {
                            tokio::spawn(async move {
                                if let Err(e) = remote_forward_task.await {
                                    tracing::error!(target: "remote_forward", "Error in remote forward task: {e:?}");
                                }
                            });
                        }
                    }
                    _ => {
                        return Err(format!("Unexpected message from server: {request:?}").into());
                    }
                }
            }
            Result::<_, Error>::Ok(())
        }
    };

    let run = async move {
        let (username, password) = (config.user, config.password);

        auth::login(&mux, &username, password.as_deref())
            .await
            .map_err(|e| format!("Failed to login: {e:?}"))?;

        let session = tokio::spawn({
            let mux = mux.clone();
            let command = options.command();
            async move {
                // 初始化终端。guard自动释放
                let _raw_terminal_guard = TerminalGuard::new();
                match command.run(&mux, options.pseudo).await {
                    Ok(code) => std::process::exit(code),
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
    quic_conn.close("Bye bye".into(), h3::error::Code::H3_NO_ERROR.value());

    error.map_or(Ok(()), Err)
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
