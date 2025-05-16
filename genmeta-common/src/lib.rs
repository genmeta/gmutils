pub mod cbor_codec;
pub mod h3_stream;
pub mod map_sink;

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::LazyLock,
};

use qbase::net::EndpointAddr;
use qdns::Resolve;

pub static AGENTS: LazyLock<Vec<SocketAddr>> = LazyLock::new(|| {
    vec![
        "1.12.74.4:20004".parse().unwrap(),
        "[2402:4e00:c011:1700:8624:7e0:5c9a:2]:20004"
            .parse()
            .unwrap(),
    ]
});

pub static ROOT_CERT: &[u8] = include_bytes!("../../root.crt");

#[derive(Default)]
pub struct Resolvers {
    resolvers: Vec<Box<dyn Resolve + Send + Sync>>,
}

impl Resolvers {
    pub fn new() -> Self {
        Self::default()
    }

    pub const UDP_DNS_SERVER: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(1, 12, 74, 4)), 5300);

    pub const HTTP_DNS_SERVER: &str = "";

    pub fn with(mut self, resolver: impl Resolve + Send + Sync + 'static) -> Self {
        self.resolvers.push(Box::new(resolver));
        self
    }
}

#[async_trait::async_trait]
impl Resolve for Resolvers {
    async fn publish(&self, _name: &str, _addresses: &[EndpointAddr]) -> io::Result<()> {
        panic!("This resolver does not support publishing")
    }

    async fn lookup(&self, name: &str) -> io::Result<Vec<EndpointAddr>> {
        let mut result = None;
        for resolver in &self.resolvers {
            result = Some(resolver.lookup(name).await);
            if matches!(result, Some(Ok(_))) {
                break;
            }
        }

        result.expect("No resolver provided to lookup")
    }
}
