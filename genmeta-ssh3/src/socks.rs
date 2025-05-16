use std::{
    fmt::Debug,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
};

use bytes::Bytes;
use dashmap::DashMap;
use futures::{Sink, SinkExt, StreamExt, channel::mpsc, never::Never};
use genmeta_common::map_sink::MapSinkExt;
use serde::{Deserialize, Serialize};
use tokio::{
    io,
    net::{TcpListener, TcpStream},
};
use tokio_util::{
    io::{CopyToBytes, SinkWriter, StreamReader},
    task::AbortOnDropHandle,
};
use tracing::Instrument;

type Token = u64;
type AtomicToken = AtomicU64;

#[derive(Serialize, Debug)]
pub enum ClientSocksMessage {
    Init { token: Token },
    Data { token: Token, data: Bytes },
    Finish { token: Token },
}

#[derive(Deserialize, Debug)]
pub enum ServerSocksMessage {
    Data { token: Token, data: Bytes },
    Error { token: Token, error: String },
}

pub struct SocksConnection {
    data_recver: mpsc::Sender<Bytes>,
    _task_handle: AbortOnDropHandle<()>,
}

pub struct SocksForwardServer<S> {
    token: Arc<AtomicToken>,
    connections: Arc<DashMap<Token, SocksConnection>>,
    message_sender: S,
}

impl<S> SocksForwardServer<S>
where
    S: Sink<ClientSocksMessage, Error: Debug + Send> + Clone + Send + Unpin + 'static,
{
    pub fn new(message_sender: S) -> Self {
        Self {
            token: Arc::new(AtomicToken::new(0)),
            connections: Arc::new(DashMap::new()),
            message_sender,
        }
    }

    pub async fn accpet(&self, mut incoming: TcpStream) {
        let token = self.token.fetch_add(1, Relaxed);
        let message_sender = self.message_sender.clone();

        let (data_recver, rcvd_data_stream) = mpsc::channel(16);
        let mut reader = StreamReader::new(rcvd_data_stream.map(io::Result::Ok));
        let data_sender = message_sender
            .clone()
            .mapped(move |data: Bytes| Ok(ClientSocksMessage::Data { token, data }))
            .sink_map_err(|send_error| {
                io::Error::other(format!("Server internal send error: {send_error:?}"))
            });
        let mut writer = SinkWriter::new(CopyToBytes::new(data_sender));

        let forward_task = async move {
            let mut forwrad_io = io::join(&mut reader, &mut writer);
            io::copy_bidirectional(&mut incoming, &mut forwrad_io).await?;
            io::Result::Ok(())
        };

        let connections = self.connections.clone();
        let mut message_sender = message_sender.clone();
        let forward_task = async move {
            let initial_message = ClientSocksMessage::Init { token };
            if let Err(e) = message_sender.send(initial_message).await {
                tracing::error!(target: "socks", "Error sending initial message: {e:?}");
                return;
            }
            if let Err(e) = forward_task.await {
                tracing::error!(target: "socks", "Error in forward task: {e:?}");
            }

            let close_message = ClientSocksMessage::Finish { token };
            _ = message_sender.send(close_message).await;
            connections.remove(&token);
        };

        let connection = SocksConnection {
            data_recver,
            _task_handle: AbortOnDropHandle::new(tokio::spawn(forward_task.in_current_span())),
        };
        self.connections.insert(token, connection);
    }

    pub async fn receive(&self, token: Token, data: Bytes) {
        if let Some(mut connection) = self.connections.get_mut(&token) {
            if let Err(error) = connection.data_recver.send(data).await {
                tracing::warn!(target: "socks", "Failed to send data to connection {token}: {error:?}");
            }
        } else {
            tracing::warn!(target: "socks", "Connection {token} not found");
        }
    }

    pub async fn listen(&self, listener: TcpListener) -> io::Error {
        let listen = async {
            tracing::info!(target: "socks", "Listening on {}", listener.local_addr()?);
            loop {
                let (incoming, from) = listener.accept().await?;
                tracing::info!(target: "socks", "Accepted connection from {from}");
                self.accpet(incoming).await;
            }
        };
        let io::Result::<Never>::Err(error) = listen.await;
        tracing::error!(target: "socks", "Socks forward server error: {error:?}");
        error
    }

    pub fn close(&self, token: Token) {
        self.connections.remove(&token);
    }
}
