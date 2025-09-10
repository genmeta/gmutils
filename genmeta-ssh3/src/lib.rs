use std::{fmt::Debug, sync::Arc};

mod auth;
mod config;
mod connect;
mod error;
mod forward;
mod session;
mod socks;
use clap::Parser;
use error::*;
use forward::*;
use futures::{FutureExt, StreamExt};
use http::Uri;
use snafu::{Backtrace, prelude::*};
use ssh3_proto::{listener, messages, mux};

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

    /// Client identity
    #[arg(short = 'i', long, value_name = "client_identity")]
    id: Option<String>,

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

pub async fn run(options: Options) -> Result<(), error::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::WARN.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = options.config().await?;
    tracing::info!(target: "config", ?config, "Parsed config");

    let dynamic_forward_listeners = {
        let mut listeners = Vec::new();
        for &local_addr in options
            .dynamic_forward
            .iter()
            .flat_map(|endpoint| endpoint.addresses())
        {
            listeners.push(listener::Listener::bind(local_addr.into()).await.context(
                DynamicForwardBindSnafu {
                    endpoint: local_addr,
                },
            )?);
        }
        listeners
    };

    let local_forwards = {
        let mut forwards = Vec::new();
        for (local_endpoint, remote_endpoint) in
            options.local_forwards.iter().flat_map(|rule| rule.pairs())
        {
            let listener = listener::Listener::bind(local_endpoint.clone())
                .await
                .context(LocalForwardBindSnafu {
                    endpoint: local_endpoint.clone(),
                })?;
            forwards.push((local_endpoint, listener, remote_endpoint));
        }
        forwards
    };

    let (quic_conn, mut h3_conn, _h3_client, mux, mut incomings) =
        connect::connect(&config.uri, config.profile.as_ref()).await?;

    let remote_forwarders = Arc::new(forward::RemoteForwardAcceptor::new(mux.clone()));

    let recv_requests = {
        let remote_forwarders = remote_forwarders.clone();
        async move {
            while let Some(new_channel) = incomings.next().await.transpose()? {
                match new_channel.request {
                    messages::OpenChannel::Forwarded { listen, to } => {
                        let accept_forward = remote_forwarders
                            .accept(listen, to.clone(), new_channel.recver, new_channel.sender)
                            .await;
                        let remote_forward_task = match accept_forward {
                            Ok(Some(forward_task)) => forward_task,
                            Ok(None) => {
                                tracing::warn!(target: "remote_forward", "No remote forward request with {listen:?} to {to:?}");
                                continue;
                            }
                            Err(connect_local) => {
                                tracing::error!(target: "remote_forward", "Failed to accept remote forward connection: {connect_local}");
                                continue;
                            }
                        };
                        tokio::spawn(async move {
                            if let Err(e) = remote_forward_task.await {
                                tracing::error!(target: "remote_forward", "Error in remote forward task: {e:?}");
                            }
                        });
                    }
                    _ => {
                        return UnexpectedMessageSnafu {
                            message: format!("{:?}", new_channel.request),
                        }
                        .fail();
                    }
                }
            }
            Result::<_, error::Error>::Ok(())
        }
    };

    let run = async move {
        let (username, password) = (config.username, config.password);

        auth::login(&mux, &username, password.as_deref()).await?;

        let session = tokio::spawn({
            let mux = mux.clone();
            let command = options.command();
            async move {
                // 初始化终端。guard自动释放
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
            let forwarder = forward::LocalForwarder::new(
                mux.clone(),
                messages::OpenChannel::Direct { to: remote },
            );
            let listen_task =
                listener.listen(move |reader, writer| forwarder.forward(reader, writer).boxed());
            tokio::spawn(async move {
                let error = listen_task.await;
                tracing::error!(target: "local_forward", "Local forward server listen on {local} error: {error:?}");
            });
        }

        for (local, remote) in options.remote_forwards.iter().flat_map(|rule| rule.pairs()) {
            let forward_task = remote_forwarders
                .initial_forward(local, remote.clone())
                .await
                .context(ForwardChannelOpenSnafu)?;
            let forward_task = async move {
                if let Err(error) = forward_task.await {
                    tracing::error!(target: "remote_forward", "Remote server failed to accept connections from {remote}: {error:?}");
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
    quic_conn.close("Bye bye~", h3::error::Code::H3_NO_ERROR.value());

    error.map_or(Ok(()), Err)
}
