use std::{future::poll_fn, net::SocketAddr};

use clap::Parser;
use qinterface::factory::ProductQuicIO;
use qtraversal::iface::traversal_factory;
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
    let iface = factory.bind(options.bind.into())?;

    let external_addr = poll_fn(|cx| iface.poll_endpoint_addr(cx)).await?;
    let nat_type = poll_fn(|cx| iface.poll_nat_type(cx)).await?;

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
