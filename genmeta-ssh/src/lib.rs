use std::{
    fmt::Debug,
    io::{IsTerminal, Read},
    sync::Arc,
};

mod config;
mod connect;
pub mod forward;
pub mod ssh_config;

use clap::Parser;
use dhttp_home::identity::Name;
use forward::*;
use genmeta_common::{bind, dns};
use genmeta_ssh_core as ssh3;
use h3x::error::Code;
use snafu::{FromString, Report, ResultExt, Snafu};
use tracing::Instrument;
use tracing_subscriber::prelude::*;

const URI_LONG_HELP: &str = "If this argument matches the ssh configuration file, \
the HostName and User of the matched Host will be used. \
Otherwise the argument will be parsed as a URI. URIs follow these rules: \
Only `https` scheme is accepted. If not present, `https` is used. \
Username is optional, if not present, use current user. \
Path is optional, if not present, use `/ssh` as default.";

const OPTIONS_LONG_HELP: &str =
    "Set options for the SSH connection, currently all options are ignored.";

const DYNAMIC_FORWARD_LONG_HELP: &str = "Start a Socks server on the specified local port, forward the connection to the server and decide which address \
the server should connect to based on the application protocol.\
You can specify just the port, while an empty address or `*` indicates that the port should be available from all interfaces.";

const LOCAL_FORWARDING_LONG_HELP: &str =
    "Specifies that connections to the given TCP port or Unix \
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

const REMOTE_FORWARDING_LONG_HELP: &str =
    "Specifies that connections to the given TCP port or Unix socket on the remote (server) host \
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
    /// User to log in as on the remote machine
    #[arg(short = 'l', value_name = "login_name")]
    login_name: Option<String>,

    /// Client identity
    #[arg(short = 'i', long, value_name = "client_identity")]
    id: Option<Name<'static>>,

    /// Skip identity loading and use anonymous mode
    #[arg(long, conflicts_with = "id")]
    anonymous: bool,

    /// Disable pseudo-terminal allocation
    #[arg(
        short = 'T',
        default_value_t = true,
        action = clap::ArgAction::SetFalse,
    )]
    pseudo: bool,

    /// Set SSH options
    #[arg(
        short = 'o',
        value_name = "option",
        value_delimiter = ',',
        long_help = OPTIONS_LONG_HELP
    )]
    options: Vec<String>,

    /// Dynamic port forwarding (SOCKS proxy)
    #[arg(short = 'D', value_name = "[bind_address:]port", long_help = DYNAMIC_FORWARD_LONG_HELP)]
    dynamic_forward: Vec<DynamicForward>,

    /// Local port forwarding
    #[arg(
        short = 'L',
        value_name = "[bind_address:]port:host:hostport / ...",
        long_help = LOCAL_FORWARDING_LONG_HELP
    )]
    local_forwards: Vec<LocalForward>,

    /// Remote port forwarding
    #[arg(
        short = 'R',
        value_name = "[bind_address:]port:host:hostport / ...",
        long_help = REMOTE_FORWARDING_LONG_HELP
    )]
    remote_forwards: Vec<RemoteForward>,

    /// DNS resolution schemes
    #[arg(long, value_name = "scheme", default_value = "mdns,h3", value_delimiter = ',', hide = cfg!(not(debug_assertions)))]
    dns: Vec<dns::DnsScheme>,

    /// Bind patterns for DHTTP/3 connections
    #[arg(long = "interface", value_name = "bind", default_value = "*", hide = cfg!(not(debug_assertions)))]
    binds: Vec<bind::Bind>,

    #[arg(value_name = "HOST/URI", long_help = URI_LONG_HELP)]
    host: String,

    /// Command to execute on the remote server
    #[arg(trailing_var_arg = true, value_name = "command [argument ...]")]
    commands: Vec<String>,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    Config { source: config::Error },
    #[snafu(transparent)]
    Connect { source: connect::Error },
    #[snafu(transparent)]
    Session { source: SessionError },
    #[snafu(transparent)]
    Forward { source: ForwardError },
}

#[derive(Debug, Snafu)]
#[snafu(module(session_error))]
pub enum SessionError {
    #[snafu(display("failed to open session channel"))]
    OpenChannel { source: snafu::Whatever },

    #[snafu(display("failed to set up PTY"))]
    SetupPty {
        source: ssh3::session::client::SetupError,
    },

    #[snafu(display("failed to send exec request"))]
    Exec {
        source: ssh3::session::client::SetupError,
    },

    #[snafu(display("failed to send shell request"))]
    Shell {
        source: ssh3::session::client::SetupError,
    },

    #[snafu(display("session IO relay failed"))]
    Run {
        source: ssh3::session::client::RunError,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module(forward_error))]
pub enum ForwardError {
    #[snafu(display("failed to bind local forward listener"))]
    BindLocalForward {
        source: ssh3::forward::client::BindLocalForwardError,
    },

    #[snafu(display("failed to request remote forward"))]
    RequestRemoteForward {
        source: ssh3::forward::client::RequestRemoteForwardError,
    },

    #[snafu(display("failed to bind dynamic forward listener"))]
    BindDynamicForward { source: std::io::Error },
}

fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (stderr, guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive(
                    "netlink_packet_route=error"
                        .parse()
                        .expect("BUG: static tracing directive is valid"),
                ),
        )
        .init();
    guard
}

pub async fn run(options: Options) -> Result<(), Error> {
    let _guard = init_tracing();

    let config = options.config().await?;
    tracing::debug!(?config);

    let commands = match options.commands.as_slice() {
        [] => None,
        commands => Some(commands.join(" ")),
    };

    let connect_result = connect::connect(&config).await?;
    let _watcher = connect_result.watcher;
    let connection = connect_result.connection;
    let conversation = Arc::new(connect_result.conversation);

    // Start port forwarding tasks before opening the session channel.
    let mut forward_tasks = tokio::task::JoinSet::new();

    // -L local forwards
    for spec in &config.local_forwards {
        let conv = conversation.clone();
        let spec = spec.clone();
        let label = spec.to_string();
        forward_tasks.spawn(async move {
            let Err(e) = spec
                .run(conv)
                .instrument(tracing::info_span!("local_forward", %label))
                .await;
            tracing::error!(error = %snafu::Report::from_error(&e), "local forward failed");
        });
    }

    // -R remote forwards
    let mut remote_mappings: Vec<ssh3::forward::client::RemoteForwardEstablished> = Vec::new();
    for spec in &config.remote_forwards {
        let established = spec
            .request(&conversation)
            .await
            .context(forward_error::RequestRemoteForwardSnafu)?;
        remote_mappings.push(established);
    }
    if !remote_mappings.is_empty() {
        let conv = conversation.clone();
        forward_tasks.spawn(
            ssh3::forward::client::accept_forwarded_channels(conv, remote_mappings)
                .instrument(tracing::info_span!("channel_acceptor")),
        );
    }

    // -D dynamic SOCKS5 forwards
    for spec in &config.dynamic_forwards {
        let conv = conversation.clone();
        let spec = spec.clone();
        let label = spec.to_string();
        forward_tasks.spawn(async move {
            let Err(e) = run_dynamic_forward(spec, conv)
                .instrument(tracing::info_span!("dynamic_forward", %label))
                .await;
            tracing::error!(error = %snafu::Report::from_error(&e), "dynamic forward failed");
        });
    }

    // Open a session channel on a dedicated QUIC stream.
    let (ch_reader, ch_writer) = conversation
        .open_channel(
            &ssh3::forward::SessionChannelOpen,
            ssh3::constants::DEFAULT_MAX_MESSAGE_SIZE,
        )
        .await
        .map_err(|e| SessionError::OpenChannel {
            source: snafu::Whatever::without_source(e.to_string()),
        })?;

    let channel = ssh3::conversation::channel::SshChannel::new(ch_reader, ch_writer);
    let mut session = ssh3::session::client::ClientSession::new(channel);

    // PTY request
    if options.pseudo {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        let pty_req = ssh3::session::PtyRequest {
            term_type: "xterm-256color".into(),
            width_cols: h3x::varint::VarInt::from(cols as u32),
            height_rows: h3x::varint::VarInt::from(rows as u32),
            width_px: h3x::varint::VarInt::from_u32(0),
            height_px: h3x::varint::VarInt::from_u32(0),
            terminal_modes: ssh3::codec::SshBytes::from(Vec::new()),
        };
        session
            .request_pty(&pty_req)
            .await
            .context(session_error::SetupPtySnafu)?;
    }

    // Exec or shell
    match commands.as_deref() {
        Some(cmd) => {
            session
                .exec(cmd.as_bytes())
                .await
                .context(session_error::ExecSnafu)?;
        }
        None => {
            session.shell().await.context(session_error::ShellSnafu)?;
        }
    }

    // IO relay — use a dedicated OS thread for stdin to avoid blocking
    // tokio runtime shutdown (tokio::io::stdin uses spawn_blocking which
    // cannot be cancelled and hangs the runtime Drop).
    let interactive = options.pseudo && std::io::stdin().is_terminal();
    let _raw_guard = if interactive {
        crossterm::terminal::enable_raw_mode()
            .map(|()| RawModeGuard)
            .ok()
    } else {
        None
    };

    let exit_result = if interactive {
        let resize = sigwinch_stream();
        session
            .run_interactive(
                ThreadedStdin::new(),
                tokio::io::stdout(),
                tokio::io::stderr(),
                resize,
            )
            .await
            .context(session_error::RunSnafu)?
    } else {
        session
            .run(
                ThreadedStdin::new(),
                tokio::io::stdout(),
                tokio::io::stderr(),
            )
            .await
            .context(session_error::RunSnafu)?
    };

    drop(_raw_guard);

    // If forwarding tasks are running (-L/-R/-D), keep the connection alive
    // until they finish or a termination signal arrives. This is required
    // for VSCode Remote SSH which uses -D alongside the session.
    if !forward_tasks.is_empty() {
        tracing::info!(
            active_forwards = forward_tasks.len(),
            "session ended, keeping connection alive for port forwarding"
        );
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received interrupt, shutting down forwarding");
            }
            // All forward tasks completed on their own (unlikely for listeners,
            // but handles the case where they all fail).
            _ = async {
                while forward_tasks.join_next().await.is_some() {}
            } => {
                tracing::info!("all forwarding tasks completed");
            }
        }
    }

    connection.close(Code::H3_NO_ERROR, "");

    let exit_code = match exit_result {
        Some(ssh3::session::client::ExitResult::Status(code)) => {
            tracing::debug!(exit_code = code, "remote process exited");
            i32::try_from(code).unwrap_or(1)
        }
        Some(ssh3::session::client::ExitResult::Signal {
            signal_name,
            core_dumped,
        }) => {
            tracing::warn!(
                signal = %signal_name,
                core_dumped,
                "remote process killed by signal"
            );
            128
        }
        None => {
            tracing::debug!("remote channel closed without exit status");
            0
        }
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Run a dynamic SOCKS5 forward: bind a local TCP listener and, for each
/// accepted connection, open a "socks5" channel to the server. The server
/// handles SOCKS5 negotiation and connects to the final destination.
async fn run_dynamic_forward<M>(
    spec: DynamicForward,
    conversation: Arc<ssh3::conversation::Conversation<M>>,
) -> Result<std::convert::Infallible, ForwardError>
where
    M: ssh3::conversation::ManageSessionStream + 'static,
    M::StreamReader: 'static,
    M::StreamWriter: 'static,
{
    let bind_addr = match spec.host.as_str() {
        "" | "*" => "0.0.0.0",
        other => other,
    };
    let listener = tokio::net::TcpListener::bind((bind_addr, spec.port))
        .await
        .context(forward_error::BindDynamicForwardSnafu)?;
    tracing::info!(
        bind = %listener.local_addr().unwrap_or_else(|_| "?".parse().unwrap()),
        "dynamic SOCKS5 forward listening"
    );

    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %Report::from_error(&e), "accept failed");
                continue;
            }
        };
        let conv = conversation.clone();
        tasks.spawn(
            async move {
                let channel_result = conv
                    .open_channel(
                        &ssh3::forward::Socks5ChannelOpen,
                        ssh3::constants::DEFAULT_MAX_MESSAGE_SIZE,
                    )
                    .await;

                let (ch_reader, ch_writer) = match channel_result {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(
                            error = %snafu::Report::from_error(&e),
                            "socks5 channel open failed"
                        );
                        return;
                    }
                };

                let (local_reader, local_writer) = stream.into_split();
                let s2ch =
                    tokio::spawn(ssh3::forward::relay(local_reader, ch_writer).in_current_span());
                let ch2s =
                    tokio::spawn(ssh3::forward::relay(ch_reader, local_writer).in_current_span());
                let _ = tokio::join!(s2ch, ch2s);
            }
            .instrument(tracing::info_span!("socks5_conn", %peer)),
        );
    }
}

// ---------------------------------------------------------------------------
// ThreadedStdin — non-blocking stdin that won't block runtime shutdown
// ---------------------------------------------------------------------------

/// Reads stdin on a dedicated OS thread and exposes it as [`tokio::io::AsyncRead`].
///
/// Unlike [`tokio::io::stdin`], the reader thread lives outside tokio's
/// blocking pool, so an in-progress `read(2)` does not prevent the runtime
/// from shutting down.
struct ThreadedStdin {
    rx: tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    pending: Vec<u8>,
    pos: usize,
}

impl ThreadedStdin {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        std::thread::Builder::new()
            .name("stdin-reader".into())
            .spawn(move || {
                let stdin = std::io::stdin();
                let mut buf = vec![0u8; 8192];
                loop {
                    match stdin.lock().read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if tx.blocking_send(Ok(buf[..n].to_vec())).is_err() {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            let _ = tx.blocking_send(Err(e));
                            break;
                        }
                    }
                }
            })
            .expect("failed to spawn stdin reader thread");
        Self {
            rx,
            pending: Vec::new(),
            pos: 0,
        }
    }
}

impl tokio::io::AsyncRead for ThreadedStdin {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();

        // Drain buffered data first.
        if me.pos < me.pending.len() {
            let n = buf.remaining().min(me.pending.len() - me.pos);
            buf.put_slice(&me.pending[me.pos..me.pos + n]);
            me.pos += n;
            if me.pos == me.pending.len() {
                me.pending.clear();
                me.pos = 0;
            }
            return std::task::Poll::Ready(Ok(()));
        }

        // Receive the next chunk from the reader thread.
        match me.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(Ok(data))) => {
                let n = buf.remaining().min(data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    me.pending = data;
                    me.pos = n;
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// RawModeGuard — RAII guard for terminal raw mode
// ---------------------------------------------------------------------------

/// Restores terminal cooked mode on drop.
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

// ---------------------------------------------------------------------------
// SIGWINCH → (cols, rows) stream
// ---------------------------------------------------------------------------

/// Create an async stream that yields `(cols, rows)` on every `SIGWINCH`.
fn sigwinch_stream() -> impl futures::Stream<Item = (u16, u16)> + Unpin + Send {
    let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        .expect("failed to register SIGWINCH handler");

    futures::stream::poll_fn(move |cx| match sig.poll_recv(cx) {
        std::task::Poll::Ready(Some(())) => {
            let size = crossterm::terminal::size().ok();
            std::task::Poll::Ready(size)
        }
        std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
        std::task::Poll::Pending => std::task::Poll::Pending,
    })
}
