use std::fmt::Debug;

// mod auth;
mod config;
mod connect;
use clap::Parser;
use genmeta_common::{bind, dns};
use genmeta_home::identity::Name;
use genmeta_ssh3_client as ssh3;
use h3x::{
    codec::{SinkWriter, StreamReader},
    error::Code,
};
use snafu::Snafu;
use ssh3::forward::*;
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
    dynamic_forward: Vec<DynamicForwardEndpoint>,

    /// Local port forwarding
    #[arg(
        short = 'L',
        value_name = "[bind_address:]port:host:hostport / [bind_address:]port:remote_socket / local_socket:host:hostport / local_socket:remote_socket",
        long_help = LOCAL_FORWARDING_LONG_HELP
    )]
    local_forwards: Vec<LocalForwardRule>,

    /// Remote port forwarding
    #[arg(
        short = 'R',
        value_name = "[bind_address:]port:host:hostport / [bind_address:]port:local_socket / remote_socket:host:hostport / remote_socket:local_socket / [bind_address:]port",
        long_help = REMOTE_FORWARDING_LONG_HELP
    )]
    remote_forwards: Vec<RemoteForwardRule>,

    /// DNS resolution schemes
    #[arg(long, value_name = "scheme", default_value = "system, mdns, http")]
    dns: Vec<dns::DnsScheme>,

    /// Bind patterns for DHTTP/3 connections
    #[arg(long = "interface", value_name = "bind", default_value = "*")]
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
    Ssh3 { source: ssh3::Error },
}

pub async fn run(options: Options) -> Result<(), Error> {
    // todo: enable ASNI with `atty` crate
    let (stderr, _guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let config = options.config().await?;
    tracing::debug!(?config);

    let commands = match options.commands.as_slice() {
        [] => None,
        commands => Some(commands.join(" ")),
    };
    let options = ssh3::Options {
        username: &config.username,
        commands: commands.as_deref(),
        pseudo: options.pseudo,
        dynamic_forward: &options.dynamic_forward,
        local_forwards: &options.local_forwards,
        remote_forwards: &options.remote_forwards,
    };

    let (connection, reader, writer) = connect::connect(&config).await?;
    let reader = Box::pin(StreamReader::new(reader.into_bytes_stream()));
    let writer = Box::pin(SinkWriter::new(writer.into_bytes_sink()));

    let result = ssh3::run(options, reader, writer).await;
    connection.close(&Code::H3_NO_ERROR);

    Ok(result?)
}
