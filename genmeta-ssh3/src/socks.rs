use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

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

impl super::Options {
    pub async fn dynamic_forward_endpoints(&self) -> Result<Vec<SocketAddr>, Error> {
        self.dynamic_forward
            .iter()
            .try_fold(vec![], |mut acc, bind_address| {
                let (host, port) = bind_address.rsplit_once(':').unwrap_or(("*", bind_address));
                let port = port.parse::<u16>().map_err(|_| {
                    format!("Invalid port `{port}` in dynamic forward bind address `{bind_address}`")
                })?;
                match host {
                    "*" => acc.extend([
                        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port),
                        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port),
                    ]),
                    ipaddr => {
                        let ipaddr = ipaddr.parse::<IpAddr>().map_err(|_| {
                            format!("Invalid host `{host}` in dynamic forward bind address `{bind_address}`")
                        })?;
                        acc.extend([SocketAddr::new(ipaddr, port)]);
                    }
                }
                Result::<_, Error>::Ok(acc)
            })
    }
}
