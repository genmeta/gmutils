use std::{net::SocketAddr, sync::Arc};

use derive_more::From;
use futures::{future::BoxFuture, never::Never};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    net::TcpListener,
};
use tracing::Instrument;

use crate::{Error, messages::BindAddress};

#[derive(Debug, From)]
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl Listener {
    pub async fn bind(endpoint: BindAddress) -> io::Result<Self> {
        tracing::debug!(target: "local_forward", "Binding to {endpoint:?}");
        Ok(match endpoint {
            BindAddress::Host { host, port } => Self::Tcp({
                let addr = tokio::net::lookup_host((host.as_str(), port))
                    .await?
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "No address found")
                    })?;
                use socket2::{Domain, Socket, Type};
                let socket = match addr {
                    SocketAddr::V4(..) => Socket::new(Domain::IPV4, Type::STREAM, None)?,
                    SocketAddr::V6(..) => Socket::new(Domain::IPV6, Type::STREAM, None)?,
                };

                if matches!(addr, SocketAddr::V6(..)) {
                    socket.set_only_v6(true)?;
                }

                socket.set_nonblocking(true)?;
                socket.set_reuse_address(true)?;
                socket.bind(&addr.into())?;
                socket.listen(1024)?;

                TcpListener::from_std(socket.into())?
            }),
            #[cfg(unix)]
            BindAddress::Unix { path } => Self::Unix(UnixListener::bind(path)?),
            #[cfg(not(unix))]
            BindAddress::Unix { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "UNIX domain sockets are not supported for this platform.",
                ));
            }
        })
    }

    pub async fn listen_tcp<H>(listener: TcpListener, handler: H) -> Error
    where
        H: for<'io> Fn(
                &'io mut (dyn AsyncRead + Send + Unpin),
                &'io mut (dyn AsyncWrite + Send + Unpin),
            ) -> BoxFuture<'io, Result<(), Error>>
            + Send
            + Sync
            + 'static,
    {
        let listen_task = async move {
            tracing::info!("Listening on {:?}", listener.local_addr()?);
            let handler = Arc::new(handler);
            loop {
                let (incoming, from) = listener.accept().await?;
                tracing::info!("Accepted connection from {from:?}");
                let (mut reader, mut writer) = incoming.into_split();
                let handler = handler.clone();
                tokio::spawn(
                    async move {
                        if let Err(e) = handler(&mut reader, &mut writer).await {
                            tracing::error!("Error in forward task: {e:?}");
                        }
                    }
                    .in_current_span(),
                );
            }
        };
        let Result::<Never, Error>::Err(error) = listen_task.await;
        error
    }

    #[cfg(unix)]
    pub async fn listen_unix<H>(listener: UnixListener, handler: H) -> Error
    where
        H: for<'io> Fn(
                &'io mut (dyn AsyncRead + Send + Unpin),
                &'io mut (dyn AsyncWrite + Send + Unpin),
            ) -> BoxFuture<'io, Result<(), Error>>
            + Send
            + Sync
            + 'static,
    {
        let listen_task = async move {
            tracing::info!("Listening on UNIX {:?}", listener.local_addr()?);
            let handler = Arc::new(handler);
            loop {
                let (incoming, from) = listener.accept().await?;
                tracing::info!("Accepted connection from {from:?}");
                let (mut reader, mut writer) = incoming.into_split();
                let handler = handler.clone();
                tokio::spawn(
                    async move {
                        if let Err(e) = handler(&mut reader, &mut writer).await {
                            tracing::error!("Error in forward task: {e:?}");
                        }
                    }
                    .in_current_span(),
                );
            }
        };
        let Result::<Never, Error>::Err(error) = listen_task.await;
        error
    }

    pub async fn listen<H>(self, handler: H) -> Error
    where
        H: for<'io> Fn(
                &'io mut (dyn AsyncRead + Send + Unpin),
                &'io mut (dyn AsyncWrite + Send + Unpin),
            ) -> BoxFuture<'io, Result<(), Error>>
            + Send
            + Sync
            + 'static,
    {
        match self {
            Listener::Tcp(listener) => Self::listen_tcp(listener, handler).await,
            #[cfg(unix)]
            Listener::Unix(listener) => Self::listen_unix(listener, handler).await,
        }
    }
}
