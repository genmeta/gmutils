use std::sync::Arc;

use futures::FutureExt;
use ssh3_proto::{listener::Listener, mux::Mux, socks};

use crate::Error;

pub async fn listen_dynamic_forward(mux: Arc<Mux>, listener: Listener) -> Error {
    listener
        .listen(move |reader, writer| {
            let mux = mux.clone();
            async move { Ok(socks::accept_direct(reader, writer, mux).await?) }.boxed()
        })
        .await
}
