use std::{path::PathBuf, sync::Arc};

use either::Either;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    Error,
    messages::{BindAddress, OpenChannel},
    mux::{Mux, Recver, Sender, Token},
};

pub struct Forwarder {
    mux: Arc<Mux>,
    open: OpenChannel,
}

impl Forwarder {
    pub fn new(mux: Arc<Mux>, open: OpenChannel) -> Self {
        Self { mux, open }
    }

    pub fn connect(
        &self,
    ) -> impl Future<Output = Result<(Token, Recver, Sender), Error>> + Send + use<> {
        let (mux, open) = (self.mux.clone(), self.open.clone());
        async move {
            (mux.open(open).await)
                .map_err(|e| format!("Failed to open forward channel: {e:?}"))
                .map_err(Into::into)
        }
    }

    pub fn forward<R, W>(
        &self,
        reader: R,
        writer: W,
    ) -> impl Future<Output = Result<(), Error>> + Send + use<R, W>
    where
        R: AsyncRead + Send + Unpin,
        W: AsyncWrite + Send + Unpin,
    {
        let connect = self.connect();

        async move {
            let (_token, recver, sender) = connect.await?;
            let mut stream = io::join(reader, writer);
            let mut forward_stream = io::join(recver.streaming(), sender.streaming());
            // 错误：1. 连接断开（无需处理） 2. 对方Error（无需处理）
            io::copy_bidirectional(&mut stream, &mut forward_stream)
                .await
                .map_err(|e| io::Error::new(e.kind(), format!("Failed to forward data: {e:?}")))?;
            _ = stream.shutdown().await;
            _ = forward_stream.shutdown().await;
            Ok(())
        }
    }
}

pub async fn accpet_tcp_forward(
    mut sender: Sender,
    recver: Recver,
    host: &str,
    port: u16,
) -> io::Result<impl Future<Output = Result<(), Error>> + use<>> {
    let mut tcp_stream = match TcpStream::connect((host, port)).await {
        Ok(tcp_stream) => tcp_stream,
        Err(connect_error) => {
            _ = sender
                .cancel(io::Error::other(format!(
                    "Peer failed to connect to {host}:{port}: {connect_error:?}"
                )))
                .await;

            return Err(io::Error::other(format!(
                "Failed to connect to {host}:{port}: {connect_error:?}"
            )));
        }
    };
    let mut forward_stream = io::join(recver.streaming(), sender.streaming());
    Ok(async move {
        io::copy_bidirectional(&mut forward_stream, &mut tcp_stream)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("Failed to forward data: {e:?}")))?;
        _ = tcp_stream.shutdown().await;
        _ = forward_stream.shutdown().await;

        Ok(())
    })
}

#[cfg(unix)]
pub async fn accpet_unix_forward(
    mut sender: Sender,
    recver: Recver,
    endpoint: PathBuf,
) -> io::Result<impl Future<Output = Result<(), Error>>> {
    let mut unix_stream = match UnixStream::connect(endpoint.clone()).await {
        Ok(unix_stream) => unix_stream,
        Err(connect_error) => {
            _ = sender
                .cancel(io::Error::other(format!(
                    "Peer failed to connect to {endpoint:?}: {connect_error:?}"
                )))
                .await;

            return Err(io::Error::other(format!(
                "Failed to accpet forward to {endpoint:?}: {connect_error:?}"
            )));
        }
    };

    let mut forward_stream = io::join(recver.streaming(), sender.streaming());
    Ok(async move {
        io::copy_bidirectional(&mut forward_stream, &mut unix_stream)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("Failed to forward data: {e:?}")))?;
        _ = unix_stream.shutdown().await;
        _ = forward_stream.shutdown().await;

        Ok(())
    })
}

#[cfg(not(unix))]
async fn reject_unix_forward(
    mut sender: Sender,
    _recver: Recver,
    _endpoint: PathBuf,
) -> io::Result<impl Future<Output = Result<(), Error>>> {
    sender
        .cancel(io::Error::new(
            io::ErrorKind::Unsupported,
            "UNIX domain sockets are not supported for this platform.",
        ))
        .await?;
    Ok(async { Ok(()) })
}

pub async fn accepet_forward(
    sender: Sender,
    recver: Recver,
    local: BindAddress,
) -> io::Result<impl Future<Output = Result<(), Error>>> {
    let future = match local {
        BindAddress::Host { host, port } => {
            Either::Left(accpet_tcp_forward(sender, recver, &host, port).await?)
        }
        #[cfg(unix)]
        BindAddress::Unix { path } => {
            Either::Right(accpet_unix_forward(sender, recver, path).await?)
        }
        #[cfg(not(unix))]
        BindAddress::Unix { path } => {
            Either::Right(reject_unix_forward(sender, recver, path).await?)
        }
    };

    Ok(future)
}
