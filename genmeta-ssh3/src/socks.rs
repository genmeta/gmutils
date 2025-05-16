use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use bytes::Bytes;
use dashmap::DashMap;
use futures::never::Never;
use tokio::{
    io,
    net::{TcpListener, TcpStream},
};
use tokio_util::{
    io::{CopyToBytes, SinkWriter, StreamReader},
    task::AbortOnDropHandle,
};
use tracing::Instrument;

use crate::{
    Error,
    mux::{Mux, OpenChannel, Token},
};

pub struct SocksForwardServer {
    connections: Arc<DashMap<Token, AbortOnDropHandle<()>>>,
    mux: Arc<Mux>,
}

impl SocksForwardServer {
    pub fn new(mux: Arc<Mux>) -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            mux,
        }
    }

    pub async fn accpet(&self, mut incoming: TcpStream) -> Result<(), Error> {
        let (token, recver, sender) = self.mux.open::<Bytes, Bytes>(OpenChannel::Socks {}).await?;

        let mut reader = StreamReader::new(recver);
        let mut writer = SinkWriter::new(CopyToBytes::new(sender));

        let forward_task = async move {
            let mut forwrad_io = io::join(&mut reader, &mut writer);
            io::copy_bidirectional(&mut incoming, &mut forwrad_io).await?;
            io::Result::Ok(())
        };

        let connections = self.connections.clone();
        let forward_task = async move {
            if let Err(e) = forward_task.await {
                tracing::error!(target: "socks", "Error in forward task: {e:?}");
            }

            connections.remove(&token);
        };

        self.connections.insert(
            token,
            AbortOnDropHandle::new(tokio::spawn(forward_task.in_current_span())),
        );
        Ok(())
    }

    pub async fn listen(&self, listener: TcpListener) -> Error {
        let listen = async {
            tracing::info!(target: "socks", "Listening on {}", listener.local_addr()?);
            loop {
                let (incoming, from) = listener.accept().await?;
                tracing::info!(target: "socks", "Accepted connection from {from}");
                self.accpet(incoming).await?;
            }
        };
        let Result::<Never, Error>::Err(error) = listen.await;
        error
    }
}

impl super::Options {
    pub fn dynamic_forward_server(&self) -> Option<Result<SocketAddr, Error>> {
        let bind_address = self.dynamic_forward.as_ref()?;
        match bind_address.parse::<SocketAddr>().ok().or_else(|| {
            bind_address
                .parse::<u16>()
                .map(|port| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))
                .ok()
        }) {
            Some(bind_address) => Some(Ok(bind_address)),
            None => Some(Err(format!(
                "Invalid bind address argument `{bind_address}` provide:"
            )
            .into())),
        }
    }
}
