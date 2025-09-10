use std::net::SocketAddr;

use clap::Parser;
use qinterface::{QuicIoExt, factory::ProductQuicIO};
use qtraversal::{iface::traversal_factory, nat::client::NatType};
use snafu::{ResultExt, Whatever};
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
    #[arg(short, help = "Verbose mode")]
    pub verbose: bool,
}

type Error = Whatever;

pub async fn run(options: Options) -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(if options.verbose {
                    tracing_subscriber::filter::LevelFilter::INFO.into()
                } else {
                    tracing_subscriber::filter::LevelFilter::WARN.into()
                })
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();
    let servers = nslook_up(options.server.as_str(), options.bind.ip().is_ipv6() as u8).await?;
    let factory = traversal_factory(&servers);
    let iface = factory
        .bind(options.bind.into())
        .whatever_context("Failed to bind to the specified bind uri")?;

    let external_addr = iface
        .endpoint_addr()
        .await
        .whatever_context("Failed to get external address")?;

    let nat_type: NatType = iface
        .nat_type()
        .await
        .whatever_context("Failed to detect NAT type")?
        .try_into()
        .unwrap();

    println!("NAT type: {nat_type:?}");
    println!("External IP: {}", external_addr.addr().ip());
    Ok(())
}

async fn nslook_up(domain: &str, family: u8) -> Result<Vec<SocketAddr>, Error> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .whatever_context("Failed to create standard DNS resolver")?;
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
    }
    .whatever_context(format!("Failed to lookup domain `{domain}`"))?;
    Ok(addrs)
}
