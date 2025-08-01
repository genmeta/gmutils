use std::{backtrace::Backtrace, sync::Arc};

use futures::{SinkExt, TryStreamExt};
use snafu::prelude::*;
use ssh3_proto::{
    messages::{
        OpenChannel,
        auth::{ClientAuthMessage, ServerAuthMessage},
    },
    mux,
};
use tokio::io;

use crate::{
    // error::{AuthChannelOpenSnafu, AuthMessageReceiveSnafu, AuthStreamClosedSnafu, Error},
    mux::Mux,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to open authentication channel: {source}"))]
    OpenAuthChannel {
        source: mux::ChannelError,
        backtrace: Backtrace,
    },
    #[snafu(display("Auth channel closed with error: {source}"))]
    AuthAborted {
        source: io::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Authentication channel was closed unexpectedly"))]
    AuthChannelClosed { backtrace: Backtrace },
    #[snafu(display("Failed to read password: {source}"))]
    ReadPassword {
        source: io::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Failed to send password: {source}"))]
    SendPassword {
        source: io::Error,
        backtrace: Backtrace,
    },
}

pub async fn login(mux: &Arc<Mux>, user: &str, mut password: Option<&str>) -> Result<(), Error> {
    let (_token, recver, sender) = mux
        .open(OpenChannel::Auth {
            username: user.to_owned(),
        })
        .await
        .context(OpenAuthChannelSnafu)?;
    let mut recver = recver.framed();
    let mut sender = sender.framed();
    loop {
        let auth_message = recver.try_next().await;
        tracing::debug!(target: "auth", ?auth_message, "Received auth message");
        let message = match auth_message.context(AuthAbortedSnafu)? {
            Some(message) => message,
            None => return AuthChannelClosedSnafu.fail(),
        };
        match message {
            ServerAuthMessage::Accept => return Ok(()),
            ServerAuthMessage::Password { prompt } => {
                let password = match password.take() {
                    Some(password) => password.to_owned(),
                    None => tokio::task::spawn_blocking(|| rpassword::prompt_password(prompt))
                        .await
                        .expect("Never panic")
                        .context(ReadPasswordSnafu)?,
                };
                sender
                    .send(ClientAuthMessage::Password(password))
                    .await
                    .context(SendPasswordSnafu)?;
            }
        }
    }
}
