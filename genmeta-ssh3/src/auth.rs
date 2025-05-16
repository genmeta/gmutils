use std::{convert::identity, sync::Arc};

use futures::{SinkExt, TryStreamExt};
use serde::{Deserialize, Serialize};

use crate::{Error, mux::Mux};

#[derive(Debug, Serialize, Deserialize)]
enum ClientAuthMessage {
    Password(String),
}

#[derive(Debug, Serialize, Deserialize)]
enum ServerAuthMessage {
    Accpet,
    Password { prompt: String }, // Reject: ChannelMessage::Close
    Reject { reason: String },
}

pub async fn login(mux: &Arc<Mux>, user: &str, mut password: Option<&str>) -> Result<(), Error> {
    let (_token, mut recver, mut sender) = mux
        .open(crate::mux::OpenChannel::Auth {
            username: user.to_owned(),
        })
        .await?;
    loop {
        let Some(message) = recver.try_next().await.ok().and_then(identity) else {
            return Err("Auth stream closed unexpectedly.".into());
        };
        tracing::debug!("Received auth message: {message:?}");
        match message {
            ServerAuthMessage::Accpet => return Ok(()),
            ServerAuthMessage::Password { prompt } => {
                let password = match password.take() {
                    Some(password) => password.to_owned(),
                    None => {
                        tracing::info!("Password required for user {user}");
                        let Ok(Ok(password)) =
                            tokio::task::spawn_blocking(|| rpassword::prompt_password(prompt))
                                .await
                        else {
                            return Err("Failed to read password".into());
                        };
                        password
                    }
                };
                if let Err(_se) = sender.send(ClientAuthMessage::Password(password)).await {
                    return Err("Failed to send password".into());
                }
            }
            ServerAuthMessage::Reject { reason } => {
                return Err(format!("Authentication failed: {reason}").into());
            }
        }
    }
}
