use std::{net::SocketAddr, sync::Arc};

use clap::Parser;
use qinterface::io::{IO, ProductIO, handy::DEFAULT_IO_FACTORY};
use qtraversal::{
    nat::{client::StunClient, router::StunRouter},
    route::ReceiveAndDeliverPacket,
};
use snafu::{ResultExt, whatever};

#[derive(Parser, Debug, Clone)]
#[command(name = "nat-detect", version, about)]
pub struct Options {
    #[arg(
        short,
        help = "Bind address to detect NAT type",
        default_value = "0.0.0.0:5379"
    )]
    pub bind: SocketAddr,
    #[arg(
        short,
        default_value = "nat.genmeta.net:20004",
        help = "STUN server address"
    )]
    pub server: String,
    #[arg(short, help = "Verbose mode")]
    pub verbose: bool,
}

type Error = genmeta_common::error::Whatever;

pub async fn run(options: Options) -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

    diagnose_nat(&options).await
}

async fn diagnose_nat(options: &Options) -> Result<(), Error> {
    if options.verbose {
        qtraversal::nat::client::VISUALIZE_NAT_DETECTION
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    let stun_server = resolve_stun_server(&options.server, options.bind.is_ipv4()).await?;

    let bind_uri = format!("inet://{}", options.bind).into();
    let iface: Arc<dyn IO> = Arc::from(DEFAULT_IO_FACTORY.bind(bind_uri));

    let stun_router = StunRouter::new();
    let stun_client = StunClient::new(iface.clone(), stun_router.clone(), stun_server, None);

    let _recv_task = ReceiveAndDeliverPacket::task()
        .stun_router(stun_router)
        .iface_ref(iface.clone())
        .spawn();

    let external_addr = stun_client
        .outer_addr()
        .await
        .whatever_context("failed to detect external address")?;

    let nat_type = stun_client
        .nat_type()
        .await
        .whatever_context("failed to detect NAT type")?;

    println!("NAT type: {nat_type:?}");
    println!("External IP: {}", external_addr.ip());
    Ok(())
}

async fn resolve_stun_server(domain: &str, is_ipv4: bool) -> Result<SocketAddr, Error> {
    let mut addrs = tokio::net::lookup_host(domain)
        .await
        .whatever_context(format!("failed to resolve STUN server `{domain}`"))?;
    match addrs.find(|addr| addr.is_ipv4() == is_ipv4) {
        Some(addr) => Ok(addr),
        None => whatever!("no matching address found for STUN server `{domain}`"),
    }
}
