use std::{io::IsTerminal, net::SocketAddr, sync::Arc};

use clap::Parser;
use dhttp::{
    ddns::DnsScheme,
    dquic::{
        binds::BindPattern,
        net::{BindInterface, BindUri},
        qtraversal::{self, nat::client::StunClientsComponent},
    },
    endpoint::Endpoint,
    home::{self, DhttpHome, identity::IdentityHome},
    name::DhttpName as Name,
};
use futures::StreamExt;
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

    #[snafu(display(
        "failed to detect external address on `{bind_uri}` via STUN server {stun_server}"
    ))]
    DetectExternalAddr {
        bind_uri: Box<BindUri>,
        stun_server: SocketAddr,
        source: std::io::Error,
    },

    #[snafu(display("failed to detect NAT type on `{bind_uri}` via STUN server {stun_server}"))]
    DetectNatType {
        bind_uri: Box<BindUri>,
        stun_server: SocketAddr,
        source: std::io::Error,
    },

    #[snafu(display("no STUN client component found on interface `{bind_uri}`"))]
    NoStunClients { bind_uri: Box<BindUri> },

    #[snafu(display("no STUN agent discovered on interface `{bind_uri}`"))]
    NoStunAgent { bind_uri: Box<BindUri> },

    #[snafu(display("no NAT observation found among {candidates} candidate interfaces"))]
    NoNatObservation { candidates: usize },
}

struct NatObservation {
    bind_uri: BindUri,
    stun_server: SocketAddr,
    external_addr: SocketAddr,
    nat_type: qtraversal::nat::client::NatType,
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
    let endpoint = Endpoint::builder()
        .bind(bind_patterns)
        .maybe_identity(identity)
        .dns(DnsScheme::H3)
        .dns(DnsScheme::System)
        .build()
        .await;

    let interfaces = endpoint.network().interfaces();
    let candidates = interfaces.len();
    let observations = observe_interfaces(interfaces).await?;

    if observations.is_empty() {
        return error::NoNatObservationSnafu { candidates }.fail();
    }

    for observation in observations {
        println!("Interface: {}", observation.bind_uri);
        println!("STUN server: {}", observation.stun_server);
        println!("NAT type: {:?}", observation.nat_type);
        println!("External IP: {}", observation.external_addr.ip());
    }

    Ok(())
}

async fn observe_interfaces(interfaces: Vec<BindInterface>) -> Result<Vec<NatObservation>, Error> {
    let mut observations = Vec::new();
    for iface in interfaces {
        let bind_uri = iface.bind_uri();
        match observe_interface(iface).await {
            Ok(mut iface_observations) => observations.append(&mut iface_observations),
            Err(Error::NoStunClients { .. } | Error::NoStunAgent { .. }) => {
                tracing::debug!(%bind_uri, "skipping interface without STUN observation");
            }
            Err(error) => return Err(error),
        }
    }
    Ok(observations)
}

async fn observe_interface(iface: BindInterface) -> Result<Vec<NatObservation>, Error> {
    let bind_uri = iface.bind_uri();
    let clients = iface.with_components(|components, _iface| {
        components.with(|clients: &StunClientsComponent| clients.clone())
    });
    let Some(clients) = clients else {
        return error::NoStunClientsSnafu {
            bind_uri: Box::new(bind_uri),
        }
        .fail();
    };

    let mut tasks = clients.with_clients(|clients| {
        clients
            .values()
            .cloned()
            .map(|client| {
                let bind_uri = bind_uri.clone();
                async move {
                    let stun_server = client.agent_addr();
                    let external_addr =
                        client
                            .outer_addr()
                            .await
                            .context(error::DetectExternalAddrSnafu {
                                bind_uri: Box::new(bind_uri.clone()),
                                stun_server,
                            })?;
                    let nat_type = client.nat_type().await.context(error::DetectNatTypeSnafu {
                        bind_uri: Box::new(bind_uri.clone()),
                        stun_server,
                    })?;
                    Ok(NatObservation {
                        bind_uri,
                        stun_server,
                        external_addr,
                        nat_type,
                    })
                }
            })
            .collect::<futures::stream::FuturesUnordered<_>>()
    });

    if tasks.is_empty() {
        return error::NoStunAgentSnafu {
            bind_uri: Box::new(bind_uri),
        }
        .fail();
    }

    let mut observations = Vec::new();
    while let Some(observation) = tasks.next().await {
        observations.push(observation?);
    }
    Ok(observations)
}
