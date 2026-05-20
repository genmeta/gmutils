use std::{io::IsTerminal, net::SocketAddr, sync::Arc};

use clap::Parser;
use dhttp::{
    ddns::DnsScheme,
    dquic::{
        binds::BindPattern,
        net::{BindInterface, BindUri, Family, IO},
        qtraversal,
        resolver::Resolve,
    },
    endpoint::{Endpoint, STUN_SERVER},
    home::{self, DhttpHome, identity::IdentityHome},
    name::DhttpName as Name,
};
use qtraversal::{
    nat::{client::StunClient, router::StunRouter},
    route::ReceiveAndDeliverPacket,
};
use snafu::{IntoError, ResultExt};
use tracing_subscriber::prelude::*;

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

    #[snafu(display("failed to resolve STUN interface `{bind_uri}`"))]
    ResolveStunInterface {
        bind_uri: BindUri,
        source: std::io::Error,
    },

    #[snafu(display("no usable STUN interface found among {candidates} candidates"))]
    NoUsableStunInterface { candidates: usize },
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

    let resolver = endpoint.resolver();
    let (stun_iface, stun_server) =
        select_stun_interface(endpoint.network().interfaces(), resolver.as_ref()).await?;
    let bind_uri = stun_iface.bind_uri();
    let iface: Arc<dyn IO> = Arc::new(stun_iface.borrow());

    tracing::info!(%bind_uri, %stun_server, "resolved stun server from dns");

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

async fn select_stun_interface(
    interfaces: Vec<BindInterface>,
    resolvers: &(impl Resolve + ?Sized),
) -> Result<(BindInterface, SocketAddr), Error> {
    let candidates = interfaces.len();

    for family in [Family::V4, Family::V6] {
        let mut found_usable_family_interface = false;

        for iface in interfaces
            .iter()
            .filter(|iface| iface.bind_uri().family() == family)
        {
            let bind_uri = iface.bind_uri();
            if let Err(error) =
                bind_uri
                    .resolve_binding()
                    .context(error::ResolveStunInterfaceSnafu {
                        bind_uri: bind_uri.clone(),
                    })
            {
                tracing::debug!(
                    %bind_uri,
                    error = %snafu::Report::from_error(&error),
                    "skipping unusable stun interface"
                );
                continue;
            }

            found_usable_family_interface = true;
            match resolve_stun_server(resolvers, family == Family::V4).await {
                Ok(stun_server) => return Ok((iface.clone(), stun_server)),
                Err(Error::NoStunServer) => {
                    tracing::debug!(%family, "no stun server address for interface family");
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        if found_usable_family_interface {
            tracing::debug!(%family, "no usable stun server for interface family");
        }
    }

    Err(Error::NoUsableStunInterface { candidates })
}

async fn resolve_stun_server(
    resolvers: &(impl Resolve + ?Sized),
    is_ipv4: bool,
) -> Result<SocketAddr, Error> {
    use futures::StreamExt;
    let stream = resolvers
        .lookup(STUN_SERVER)
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
