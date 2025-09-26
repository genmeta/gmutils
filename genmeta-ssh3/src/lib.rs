use std::{fmt::Debug, sync::Arc};

mod auth;
mod config;
mod connect;
mod error;
mod forward;
mod session;
mod socks;
use clap::Parser;
pub use error::Error;
use error::*;
use forward::*;
use futures::{FutureExt, StreamExt};
use genmeta_common::id::ClientName;
use snafu::{Report, ResultExt};
use ssh3_proto::{
    listener, messages,
    mux::{self, NewChannel},
};
use tokio::task::JoinHandle;
use tracing::Instrument;

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
    host: String,

    #[arg(
        short = 'o',
        value_name = "option",
        value_delimiter = ',',
        long_help = OPTIONS_LONG_HELP
    )]
    options: Vec<String>,

    /// Client identity
    #[arg(short = 'i', long, value_name = "client_identity")]
    id: Option<ClientName>,

    /// Disable pseudo-terminal allocation.
    #[arg(
        short = 'T',
        default_value_t = true,
        action = clap::ArgAction::SetFalse,
    )]
    pseudo: bool,

    /// Specifies the user to log in as on the remote machine.
    #[arg(short = 'l', value_name = "login_name")]
    login_name: Option<String>,

    #[arg(short = 'D', value_name = "[bind_address:]port", long_help = DYNAMIC_FORWARD_LONG_HELP)]
    dynamic_forward: Vec<DynamicForwardEndpoint>,

    #[arg(
        short = 'L',
        value_name = "[bind_address:]port:host:hostport / [bind_address:]port:remote_socket / local_socket:host:hostport / local_socket:remote_socket",
        long_help = LOCAL_FORWARDING_LONG_HELP
    )]
    local_forwards: Vec<LocalForwardRule>,

    #[arg(
        short = 'R',
        value_name = "[bind_address:]port:host:hostport / [bind_address:]port:local_socket / remote_socket:host:hostport / remote_socket:local_socket / [bind_address:]port",
        long_help = REMOTE_FORWARDING_LONG_HELP
    )]
    remote_forwards: Vec<RemoteForwardRule>,

    /// Command to execute on the remote server.
    #[arg(trailing_var_arg = true, value_name = "command [argument ...]")]
    commands: Vec<String>,
}

pub async fn run(options: Options) -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = options.config().await?;
    tracing::debug!(target: "config", ?config);

    let dynamic_forward_listeners = {
        let mut listeners = Vec::new();
        for &local_addr in options
            .dynamic_forward
            .iter()
            .flat_map(|endpoint| endpoint.addresses())
        {
            let listener = listener::Listener::bind(local_addr.into()).await.context(
                BindDynamicForwardSnafu {
                    endpoint: local_addr,
                },
            )?;
            listeners.push((local_addr, listener));
        }
        listeners
    };

    let local_forwards = {
        let mut forwards = Vec::new();
        for (local, remote) in options.local_forwards.iter().flat_map(|rule| rule.pairs()) {
            let listener =
                listener::Listener::bind(local.clone())
                    .await
                    .context(BindLocalForwardSnafu {
                        local: local.clone(),
                        remote: remote.clone(),
                    })?;
            forwards.push((local, listener, remote));
        }
        forwards
    };

    let (quic_conn, mut h3_conn, _h3_client, mux, mut incomings) =
        connect::connect(&config).await?;

    let remote_forwarders = Arc::new(forward::RemoteForwardAcceptor::new(mux.clone()));
    let handle_request = async |NewChannel {
                                    token: _token,
                                    request,
                                    sender,
                                    recver,
                                }| {
        match request.clone() {
            messages::OpenChannel::Forwarded { listen, to } => {
                let accept_forward = remote_forwarders
                    .accept(listen, to.clone(), recver, sender)
                    .await;
                let remote_forward_task = match accept_forward {
                    Ok(Some(forward_task)) => forward_task,
                    Ok(None) => {
                        tracing::debug!(
                            target: "remote_forward",
                            "Unknown token {listen}, reject forward request"
                        );
                        return Ok(());
                    }
                    Err(connect_local) => {
                        tracing::debug!(
                            target: "remote_forward",
                            "Failed to connect to local: {}", Report::from_error(connect_local)
                        );
                        return Ok(());
                    }
                };
                let future = async move {
                    if let Err(e) = remote_forward_task.await {
                        tracing::debug!(
                            target: "remote_forward",
                            "Error in remote forward task: {}", Report::from_error(&e)
                        );
                    }
                };
                tokio::spawn(future.in_current_span());
                Ok(())
            }
            _ => UnexpectedMessageSnafu { request }.fail(),
        }
    };

    let recv_requests = async move {
        while let Some(new_request) = incomings.next().await.transpose()? {
            let span = tracing::info_span!(
                target: "session", "handle_request", request=%new_request.request
            );
            handle_request(new_request).instrument(span).await?;
        }
        Result::<_, error::Error>::Ok(())
    };

    let run = async {
        let (username, password) = (config.username, config.password);

        auth::login(&mux, &username, password.as_deref()).await?;

        let session = {
            let mux = mux.clone();
            let command = options.command();
            async move {
                // 初始化终端。guard自动释放
                let code = command.run(&mux, options.pseudo).await?;
                std::process::exit(code)
            }
        };
        let session: JoinHandle<Result<(), session::Error>> =
            tokio::spawn(session.in_current_span());

        for (local, listener, remote) in local_forwards {
            let request = messages::OpenChannel::Direct { to: remote.clone() };
            let forwarder = forward::LocalForwarder::new(mux.clone(), request);
            let listen_task =
                listener.listen(move |reader, writer| forwarder.forward(reader, writer).boxed());

            let listen_task = async move {
                tracing::error!(
                    target: "local_forward",
                    "Failed to accept incoming connection to local: {}",
                    Report::from_error(listen_task.await)
                );
            };
            let span = tracing::info_span!(target: "local_forward", "listen", %local, %remote);
            tokio::spawn(listen_task.instrument(span));
        }

        for (local, remote) in options.remote_forwards.iter().flat_map(|rule| rule.pairs()) {
            // 远程转发，本地打开一个channel且不发送任何数据，仅仅保持channel存在
            // 对端凭借这个channel的token来将数据从远端转发到本地，而不知道本地的地址是啥（除非是动态远程转发）
            let keep_task = remote_forwarders
                .initial_forward(local.clone(), remote.clone())
                .await
                .context(OpenRemoteForwardChannelSnafu {
                    local: local.clone(),
                    remote: remote.clone(),
                })?;

            let span = tracing::info_span!(target: "remote_forward", "remote_forward", local = local.map_or("<dynamic address>".to_string(), |addr| addr.to_string()), %remote);
            let keep_task = async move {
                if let Err(error) = keep_task.await {
                    tracing::error!(
                        target: "remote_forward",
                        "Channel closed by peer with error: {}",
                        Report::from_error(&error)
                    );
                }
            };
            tokio::spawn(keep_task.instrument(span));
        }

        for (local, dynamic_forward_listener) in dynamic_forward_listeners {
            let listen_task = socks::listen_dynamic_forward(mux.clone(), dynamic_forward_listener);
            let listen_task = async move {
                tracing::error!(
                    target: "local_forward",
                    "Failed to accept incoming connection to local: {}",
                    Report::from_error(listen_task.await)
                );
            };
            let span = tracing::info_span!(target: "socks", "dynamic_forward", %local);
            tokio::spawn(listen_task.instrument(span));
        }

        Ok(session.await.expect("Never panic")?)
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
    _ = quic_conn.close("Bye bye~", h3::error::Code::H3_NO_ERROR.value());

    error.map_or(Ok(()), Err)
}
