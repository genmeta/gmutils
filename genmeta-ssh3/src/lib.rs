use std::{fmt::Debug, io::IsTerminal};

mod config;
mod connect;
pub mod forward;
pub mod ssh_config;

use clap::Parser;
use forward::*;
use genmeta_common::{bind, dns};
use genmeta_home::identity::Name;
use genmeta_ssh as ssh3;
use h3x::{
    codec::{SinkWriter, StreamReader},
    error::Code,
};
use snafu::{ResultExt, Snafu};
use tracing_subscriber::prelude::*;

const URI_LONG_HELP: &str = "If this argument matches the ssh configuration file, \
the HostName and User of the matched Host will be used. \
Otherwise the argument will be parsed as a URI. URIs follow these rules: \
Scheme is optional, only `ssh3` is accepted. \
Username is optional, if not present, use current user. \
Password is optional, if not present, prompt for it. \
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
    #[arg(long, value_name = "scheme", default_value = "mdns,http", value_delimiter = ',', hide = cfg!(not(debug_assertions)))]
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
}

#[derive(Debug, Snafu)]
#[snafu(module(session_error))]
pub enum SessionError {
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

pub async fn run(options: Options) -> Result<(), Error> {
    let (stderr, _guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
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

    let config = options.config().await?;
    tracing::debug!(?config);

    let commands = match options.commands.as_slice() {
        [] => None,
        commands => Some(commands.join(" ")),
    };

    let (_watcher, connection, read_stream, write_stream) = connect::connect(&config).await?;
    let reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>> =
        Box::pin(StreamReader::new(read_stream.into_bytes_stream()));
    let writer: std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>> =
        Box::pin(SinkWriter::new(write_stream.into_bytes_sink()));

    let result = run_session(reader, writer, commands.as_deref(), options.pseudo).await;
    connection.close(Code::H3_NO_ERROR, "");

    let exit_code = result?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

async fn run_session(
    reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    writer: std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>,
    commands: Option<&str>,
    pseudo: bool,
) -> Result<i32, SessionError> {
    use session_error::*;
    use ssh3::{
        conversation::channel::SshChannel,
        session::{PtyRequest, client::ClientSession},
    };

    // The version negotiation in SSH3 happens at the HTTP header level
    // during the CONNECT upgrade, not on the byte stream. The server
    // already validated the version. We skip stream-level negotiation here.

    // Create a session channel directly from the upgraded message streams.
    // The session channel data flows on these streams.
    let channel = SshChannel::new(reader, writer);
    let mut session = ClientSession::new(channel);

    // PTY request.
    if pseudo {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        let pty_req = PtyRequest {
            term_type: "xterm-256color".into(),
            width_cols: h3x::varint::VarInt::from(cols as u32),
            height_rows: h3x::varint::VarInt::from(rows as u32),
            width_px: h3x::varint::VarInt::from_u32(0),
            height_px: h3x::varint::VarInt::from_u32(0),
            terminal_modes: ssh3::codec::SshBytes::from(Vec::new()),
        };
        session.request_pty(&pty_req).await.context(SetupPtySnafu)?;
    }

    // Exec or shell.
    match commands {
        Some(cmd) => {
            session.exec(cmd.as_bytes()).await.context(ExecSnafu)?;
        }
        None => {
            session.shell().await.context(ShellSnafu)?;
        }
    }

    // IO relay.
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let stderr = tokio::io::stderr();

    let exit_result = session.run(stdin, stdout, stderr).await.context(RunSnafu)?;

    match exit_result {
        Some(ssh3::session::client::ExitResult::Status(code)) => {
            tracing::debug!(exit_code = code, "remote process exited");
            Ok(i32::try_from(code).unwrap_or(1))
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
            Ok(128)
        }
        None => {
            tracing::debug!("remote channel closed without exit status");
            Ok(0)
        }
    }
}
