use std::net::SocketAddr;

use clap::Parser;
use qinterface::factory::ProductQuicInterface;
use qtraversal::{iface::traversal_factory, nat::client::NatType};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Parser, Debug, Clone)]
#[command(name = "nat-detect", version, about)]
pub struct Options {
    #[arg(
        short,
        help = "Bind address to detect NAT type",
        default_value = "0.0.0.0:5379"
    )]
    pub bind: SocketAddr,
    #[arg(short, default_value = "nat.genmeta.net", help = "STUN server address")]
    pub server: String,
}

type Error = Box<dyn core::error::Error + Send + Sync>;

pub async fn run(options: Options) -> Result<(), Error> {
    let servers = nslook_up(options.server.as_str(), options.bind.ip().is_ipv6() as u8).await?;
    let factory = traversal_factory(&servers);
    let iface = factory.bind(options.bind)?;

    let external_addr = iface.endpoint_addr().await?.addr();
    let nat_type: NatType = iface.nat_type().await?.try_into()?;

    println!("NAT type: {nat_type:?}");
    println!("External Address: {external_addr}");
    Ok(())
}

async fn nslook_up(domain: &str, family: u8) -> Result<Vec<SocketAddr>, Error> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let port = 20004;
    let addrs = if family == 1 {
        resolver.ipv6_lookup(domain).await.map(|ips| {
            ips.iter()
                .map(|ip| SocketAddr::new(ip.0.into(), port))
                .collect::<Vec<_>>()
        })
    } else {
        resolver.ipv4_lookup(domain).await.map(|ips| {
            ips.iter()
                .map(|ip| SocketAddr::new(ip.0.into(), port))
                .collect::<Vec<_>>()
        })
    }?;
    Ok(addrs)
}
