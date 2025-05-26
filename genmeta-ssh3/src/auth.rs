use std::sync::Arc;

use futures::{SinkExt, TryStreamExt};
use ssh3_proto::messages::{
    OpenChannel,
    auth::{ClientAuthMessage, ServerAuthMessage},
};

use crate::{Error, mux::Mux};

pub async fn login(mux: &Arc<Mux>, user: &str, mut password: Option<&str>) -> Result<(), Error> {
    let (_token, recver, sender) = mux
        .open(OpenChannel::Auth {
            username: user.to_owned(),
        })
        .await?;
    let mut recver = recver.framed();
    let mut sender = sender.framed();
    loop {
        let auth_message = recver.try_next().await;
        tracing::debug!(target: "auth", ?auth_message, "Received auth message");
        let message = match auth_message {
            Ok(Some(message)) => message,
            Ok(None) => return Err("Auth stream closed unexpectedly.".into()),
            Err(e) => return Err(e.into()),
        };
        tracing::debug!(target: "auth", ?message, "Received auth message");
        match message {
            ServerAuthMessage::Accpet => return Ok(()),
            ServerAuthMessage::Password { prompt } => {
                let password = match password.take() {
                    Some(password) => password.to_owned(),
                    None => {
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
        }
    }
}
