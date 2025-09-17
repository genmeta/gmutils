use std::{io, net::SocketAddr};

use snafu::prelude::*;
use ssh3_proto::{
    messages::{BindAddress, OpenChannel},
    mux,
};

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
    Session { source: session::Error },

    // === Forward Errors ===
    #[snafu(display(
        "Failed to bind to local forward endpoint `{local}` to forward data to remote `{remote}`"
    ))]
    BindLocalForward {
        local: BindAddress,
        remote: BindAddress,
        source: io::Error,
    },

    #[snafu(display(
        "Failed to bind to dynamic forward endpoint `{endpoint}` to forward data to remote"
    ))]
    BindDynamicForward {
        endpoint: SocketAddr,
        source: io::Error,
    },

    #[snafu(display(
        "Failed to open remote forward channel from remote `{remote}` to local `{}`",
        local.as_ref().map_or("<dynamic address>".to_string(), |addr| addr.to_string())
    ))]
    OpenRemoteForwardChannel {
        local: Option<BindAddress>,
        remote: BindAddress,
        source: ssh3_proto::mux::ChannelError,
    },

    // === Protocol Errors ===
    #[snafu(display("Unexpected request `{request}` from server"))]
    UnexpectedMessage { request: OpenChannel },
}
