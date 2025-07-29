use std::{backtrace::Backtrace, io, net::SocketAddr};

use snafu::prelude::*;
use ssh3_proto::{messages::BindAddress, mux};

use crate::{auth, config, connect, session};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Configuration error: {source}"))]
    Config {
        source: config::Error,
        backtrace: Backtrace,
    },

    // === Connect Error ===
    #[snafu(transparent)]
    Connect {
        source: connect::Error,
        backtrace: Backtrace,
    },

    // === H3 Stream Errors ===
    #[snafu(transparent)]
    Stream {
        source: mux::ForwardError<io::Error>,
        backtrace: Backtrace,
    },

    // === Authentication Errors ===
    #[snafu(transparent)]
    Auth {
        source: auth::Error,
        backtrace: Backtrace,
    },

    // === Session Errors ===
    #[snafu(transparent)]
    Session {
        source: session::SessionError,
        backtrace: Backtrace,
    },

    // === Forward Errors ===
    #[snafu(display("Failed to bind to local forward endpoint '{endpoint}': {source}"))]
    LocalForwardBind {
        endpoint: BindAddress,
        source: io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to bind to dynamic forward endpoint '{endpoint}': {source}"))]
    DynamicForwardBind {
        endpoint: SocketAddr,
        source: io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to open forward channel: {source}"))]
    ForwardChannelOpen {
        source: ssh3_proto::mux::ChannelError,
        backtrace: Backtrace,
    },

    // === Protocol Errors ===
    #[snafu(display("Unexpected message from server: {message}"))]
    UnexpectedMessage {
        message: String,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to parse local forward rule '{rule}': {message}"))]
    LocalForwardParse {
        rule: String,
        message: String,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to parse remote forward rule '{rule}': {message}"))]
    RemoteForwardParse {
        rule: String,
        message: String,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to parse dynamic forward endpoint '{endpoint}': {message}"))]
    DynamicForwardParse {
        endpoint: String,
        message: String,
        backtrace: Backtrace,
    },
}
