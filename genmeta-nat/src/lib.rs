use std::{io::IsTerminal, net::SocketAddr, sync::Arc};

use clap::Parser;
use dhttp::{
    ddns::DnsScheme,
    dquic::{binds::BindPattern, net::IO, qtraversal, resolver::Resolve},
    endpoint::Endpoint,
    home::{self, DhttpHome, identity::IdentityHome},
    name::DhttpName as Name,
};
use qtraversal::{
    nat::{client::StunClient, router::StunRouter},
    route::ReceiveAndDeliverPacket,
};
use snafu::{IntoError, ResultExt};
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

    /// Bind patterns for local network interfaces
    #[arg(long = "interface", value_name = "bind", default_value = "*",
          hide = cfg!(not(debug_assertions)))]
    pub binds: Vec<BindPattern>,

    /// Show detailed output
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(display("failed to locate dhttp home"))]
    LocateDhttpHome { source: home::LocateDhttpHomeError },

    #[snafu(display("failed to load explicit identity `{name}`"))]
    LoadExplicitIdentity {
        name: Name<'static>,
        source: home::identity::ssl::LoadIdentityError,
    },

    #[snafu(display("failed to load identity certificate and key"))]
    LoadIdentitySsl {
        source: home::identity::ssl::LoadIdentitySslError,
    },

    #[snafu(display("failed to detect external address"))]
    DetectExternalAddr {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to detect NAT type"))]
    DetectNatType {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to resolve stun server via dns"))]
    ResolveStunServer { source: std::io::Error },

    #[snafu(display("no STUN server address found via DNS"))]
    NoStunServer,
}

fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (stderr, guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
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
    guard
}

pub async fn run(mut options: Options) -> Result<(), Error> {
    let _guard = init_tracing();
    diagnose_nat(&mut options).await
}

async fn load_identity_home(options: &Options) -> Result<Option<IdentityHome>, Error> {
    if options.anonymous {
        return Ok(None);
    }

    let home = match DhttpHome::load_from_environment() {
        Ok(home) => home,
        Err(source) if options.id.is_none() => {
            tracing::warn!(
                error = %snafu::Report::from_error(&source),
                "failed to locate dhttp home, using anonymous endpoint"
            );
            return Ok(None);
        }
        Err(source) => return Err(error::LocateDhttpHomeSnafu.into_error(source)),
    };

    if let Some(name) = &options.id {
        tracing::debug!(%name, "trying to load command line identity");
        return home
            .load_identity(name.clone())
            .await
            .context(error::LoadExplicitIdentitySnafu { name: name.clone() })
            .map(Some);
    }

    match home.load_default_identity().await {
        Ok(identity) => {
            tracing::debug!(name = %identity.name(), "using default identity");
            Ok(Some(identity))
        }
        Err(source) => {
            tracing::debug!(
                error = %snafu::Report::from_error(&source),
                "failed to load default identity, using anonymous endpoint"
            );
            Ok(None)
        }
    }
}

async fn diagnose_nat(options: &mut Options) -> Result<(), Error> {
    if options.verbose {
        qtraversal::nat::client::VISUALIZE_NAT_DETECTION
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    let identity_home = load_identity_home(options).await?;
    let identity = match &identity_home {
        Some(home) => Some(Arc::new(
            home.identity().await.context(error::LoadIdentitySslSnafu)?,
        )),
        None => None,
    };

    let bind_patterns = Arc::new(options.binds.clone());
    let builder = Endpoint::builder()
        .bind(bind_patterns.clone())
        .maybe_identity(identity)
        .dns(DnsScheme::H3)
        .dns(DnsScheme::System);
    let endpoint = builder.build().await;

    // Use the first bound interface for STUN NAT detection.
    let stun_iface = endpoint
        .network()
        .interfaces()
        .into_iter()
        .next()
        .expect("BUG: at least one interface must be bound");
    let is_ipv4 = stun_iface
        .bind_uri()
        .as_inet_bind_uri()
        .map(|addr| addr.is_ipv4())
        .unwrap_or(true);
    let iface: Arc<dyn IO> = Arc::new(stun_iface.borrow());

    let resolver = endpoint.resolver();
    let stun_server = resolve_stun_server(resolver.as_ref(), is_ipv4).await?;
    tracing::info!(%stun_server, "resolved stun server from dns");

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
    resolvers: &(impl Resolve + ?Sized),
    is_ipv4: bool,
) -> Result<SocketAddr, Error> {
    use futures::StreamExt;
    let stream = resolvers
        .lookup(STUN_DOMAIN)
        .await
        .context(error::ResolveStunServerSnafu)?;
    stream
        .filter_map(|(_source, ep)| async move { Some(ep.addr()) })
        .filter(|addr| futures::future::ready(addr.is_ipv4() == is_ipv4))
        .boxed()
        .next()
        .await
        .ok_or(Error::NoStunServer)
}
