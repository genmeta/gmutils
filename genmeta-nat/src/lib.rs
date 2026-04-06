use std::{io::IsTerminal, net::SocketAddr, str::FromStr, sync::Arc};

use clap::Parser;
use genmeta_common::{
    bind::{self, Bind},
    dns::{self, DnsScheme},
    id,
};
use genmeta_home::identity::Name;
use h3x::dquic::{BuildClientError, qresolve};
use qinterface::io::{IO, ProductIO, handy::DEFAULT_IO_FACTORY};
use qtraversal::{
    nat::{client::StunClient, router::StunRouter},
    route::ReceiveAndDeliverPacket,
};
use snafu::ResultExt;
use tracing_subscriber::prelude::*;

/// Well-known STUN server domain published by pishoo via DNS.
const STUN_DOMAIN: &str = "stun.genmeta.net";

#[derive(Parser, Debug, Clone)]
#[command(name = "nat-detect", version, about)]
pub struct Options {
    /// Client identity
    #[arg(short, long)]
    pub id: Option<Name<'static>>,

    /// Skip identity loading and use anonymous mode
    #[arg(long, conflicts_with = "id")]
    pub anonymous: bool,

    /// Local bind address for NAT detection
    #[arg(short, long, default_value = "0.0.0.0:5379")]
    pub bind: SocketAddr,

    /// Show detailed output
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(transparent)]
    LoadHomeAndIdentity {
        source: id::LoadHomeAndIdentityError,
    },

    #[snafu(display("failed to load identity ssl material"))]
    LoadIdentitySsl {
        source: genmeta_home::identity::ssl::LoadIdentitySslError,
    },

    #[snafu(display("failed to build DNS resolvers"))]
    BuildDnsResolvers { source: BuildClientError },

    #[snafu(display("failed to detect external address"))]
    DetectExternalAddr {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to detect NAT type"))]
    DetectNatType {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to resolve STUN server via DNS"))]
    ResolveStunServer { source: gmdns::resolvers::DnsErrors },

    #[snafu(display("no STUN server address found via DNS"))]
    NoStunServer,
}

pub async fn run(options: Options) -> Result<(), Error> {
    let (stderr, _guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(std::io::stderr().is_terminal())
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive(
                    "netlink_packet_route=error"
                        .parse()
                        .expect("BUG: static tracing directive is valid"),
                ),
        )
        .init();

    diagnose_nat(&options).await
}

async fn diagnose_nat(options: &Options) -> Result<(), Error> {
    if options.verbose {
        qtraversal::nat::client::VISUALIZE_NAT_DETECTION
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    let identity = if options.anonymous {
        None
    } else {
        id::load_home_and_identity(
            options.id.is_some(),
            options
                .id
                .as_ref()
                .map(|id| (&"command line option" as &dyn std::fmt::Display, id.clone())),
        )
        .await?
    };

    let id_material = match &identity {
        Some(id) => Some(id.identity().await.context(error::LoadIdentitySslSnafu)?),
        None => None,
    };

    let binds = bind::Binds::new(vec![
        Bind::from_str("*").expect("BUG: wildcard bind pattern is always valid"),
    ]);
    let bind_setup = bind::setup_bind_interfaces_with(&binds, dns::handy::ensure_default_mdns_prop)
        .await
        .expect("BUG: wildcard bind should not conflict");

    let dns_setup = dns::handy::build_resolvers(
        [DnsScheme::H3],
        &bind_setup.bind_interfaces,
        id_material.as_ref(),
    )
    .context(error::BuildDnsResolversSnafu)?;

    let stun_server = resolve_stun_server(&dns_setup.resolvers, options.bind.is_ipv4()).await?;
    tracing::info!(%stun_server, "resolved STUN server from DNS");

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
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        .context(error::DetectExternalAddrSnafu)?;

    let nat_type = stun_client
        .nat_type()
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        .context(error::DetectNatTypeSnafu)?;

    println!("NAT type: {nat_type:?}");
    println!("External IP: {}", external_addr.ip());
    Ok(())
}

async fn resolve_stun_server(
    resolvers: &gmdns::resolvers::Resolvers,
    is_ipv4: bool,
) -> Result<SocketAddr, Error> {
    use futures::StreamExt;
    use qresolve::EndpointAddr;

    let stream = resolvers
        .lookup(STUN_DOMAIN)
        .await
        .context(error::ResolveStunServerSnafu)?;
    stream
        .filter_map(|(_source, ep)| async move {
            match ep {
                EndpointAddr::Socket(socket_ep) => Some(socket_ep.addr()),
                _ => None,
            }
        })
        .filter(|addr| futures::future::ready(addr.is_ipv4() == is_ipv4))
        .boxed()
        .next()
        .await
        .ok_or(Error::NoStunServer)
}
