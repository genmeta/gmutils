#[cfg(feature = "connect")]
pub mod connect;
#[cfg(feature = "error")]
pub mod error;
#[cfg(feature = "h3_stream")]
pub mod h3_stream;
#[cfg(feature = "id")]
pub mod id;

use std::{net::SocketAddr, sync::LazyLock};

pub static AGENTS: LazyLock<Vec<SocketAddr>> = LazyLock::new(|| {
    vec![
        "1.12.74.4:20004".parse().unwrap(),
        "[2402:4e00:c011:1700:8624:7e0:5c9a:2]:20004"
            .parse()
            .unwrap(),
    ]
});

pub static ROOT_CERT: &[u8] = include_bytes!("../../root.crt");
