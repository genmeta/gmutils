use std::{io, net::SocketAddr};

use snafu::prelude::*;
use ssh3_proto::{messages::BindAddress, mux};

use crate::{auth, config, connect, session};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Configuration error"))]
    Config { source: config::Error },

    // === Connect Error ===
    #[snafu(transparent)]
    Connect { source: connect::Error },

    // === H3 Stream Errors ===
    #[snafu(transparent)]
    Stream {
        source: mux::ForwardError<io::Error>,
    },

    // === Authentication Errors ===
    #[snafu(transparent)]
    Auth { source: auth::Error },

    // === Session Errors ===
    #[snafu(transparent)]
    Session { source: session::SessionError },

    // === Forward Errors ===
    #[snafu(display("Failed to bind to local forward endpoint '{endpoint}'"))]
    LocalForwardBind {
        endpoint: BindAddress,
        source: io::Error,
    },

    #[snafu(display("Failed to bind to dynamic forward endpoint '{endpoint}'"))]
    DynamicForwardBind {
        endpoint: SocketAddr,
        source: io::Error,
    },

    #[snafu(display("Failed to open forward channel"))]
    ForwardChannelOpen {
        source: ssh3_proto::mux::ChannelError,
    },

    // === Protocol Errors ===
    #[snafu(display("Unexpected message from server: {message}"))]
    UnexpectedMessage { message: String },
}
