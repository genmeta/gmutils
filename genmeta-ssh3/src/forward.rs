mod parser;
mod types;

use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use futures::StreamExt;
use genmeta_common::entry_guard::EntryGuard;
pub use ssh3_proto::forward::*;
use ssh3_proto::{
    messages::{BindAddress, OpenChannel},
    mux::{Mux, Recver, Sender, Token},
};
use tokio::io;
pub use types::{DynamicForwardEndpoint, LocalForwardRule, RemoteForwardRule};

use crate::Error;

pub struct RemoteForwardAcceptor {
    mux: Arc<Mux>,
    forwards: Arc<DashMap<Token, Option<BindAddress>>>,
}

impl RemoteForwardAcceptor {
    pub fn new(mux: Arc<Mux>) -> Self {
        Self {
            mux,
            forwards: Arc::new(DashMap::new()),
        }
    }

    pub async fn accpet(
        &self,
        token: Token,
        local: Option<BindAddress>,
        recver: Recver,
        mut sender: Sender,
    ) -> Result<Option<impl Future<Output = Result<(), Error>> + Send + use<>>, Error> {
        let Some(bind_addr) = self.forwards.get(&token) else {
            _ = sender
                .cancel(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Not allowed to forward to this endpoint",
                ))
                .await;
            return Ok(None);
        };
        let Some(local) = local.or_else(|| bind_addr.value().clone()) else {
            _ = sender
                .cancel(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "No target address provided(Internal error, this is a bug)",
                ))
                .await;
            return Ok(None);
        };
        Ok(Some(accepet_forward(sender, recver, local).await?))
    }

    pub async fn forward(
        &self,
        local: Option<BindAddress>,
        remote: BindAddress,
    ) -> Result<impl Future<Output = io::Result<()>> + Send + use<>, Error> {
        let (token, recver, _sender) = self
            .mux
            .open(OpenChannel::Forward {
                listen: remote,
                socks: local.is_none(),
            })
            .await
            .map_err(|e| format!("Failed to open forward channel: {e:?}"))?;

        self.forwards.insert(token, local);

        let entry_guard = EntryGuard::new(self.forwards.clone(), token);

        Ok(async move {
            let _entry_guard = entry_guard;
            let mut recver = recver.framed::<Bytes>();
            while let Some(next) = recver.next().await {
                next?;
            }
            Ok(())
        })
    }
}
