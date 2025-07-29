use std::sync::Arc;

use futures::FutureExt;
use snafu::{Backtrace, ResultExt, Snafu};
use ssh3_proto::{listener::Listener, mux::Mux, socks};
use tokio::io;

#[derive(Debug, Snafu)]
pub enum SocksError {
    #[snafu(display("Socks server error: {source}"))]
    Server {
        source: socks::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Failed to accept local connections: {source}"))]
    AcceptError {
        source: io::Error,
        backtrace: Backtrace,
    },
}

impl From<io::Error> for SocksError {
    fn from(source: io::Error) -> Self {
        SocksError::AcceptError {
            source,
            backtrace: Backtrace::capture(),
        }
    }
}

pub async fn listen_dynamic_forward(mux: Arc<Mux>, listener: Listener) -> io::Error {
    listener
        .listen(move |reader, writer| {
            let mux = mux.clone();
            async move {
                socks::accept_direct(reader, writer, mux)
                    .await
                    .context(ServerSnafu)
            }
            .boxed()
        })
        .await
}
