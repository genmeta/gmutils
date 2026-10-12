use std::{
    collections::{HashMap, HashSet},
    io::IsTerminal,
    string::String as BindPattern,
    time::Duration,
};

use clap::Parser;
use ddns::DnsScheme;
use dhttp_home as home;
use dhttp_identity::name::DhttpName as Name;
use qprotocol::{AddressBook, AddressEvent};
use snafu::{ResultExt, Snafu};
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(name = "nat-detect", version, about)]
pub struct Options {
    /// Client identity
    #[arg(short, long)]
    pub id: Option<Name<'static>>,
    /// Use the global dhttp home
    #[arg(long)]
    pub global: bool,
    /// Skip identity loading
    #[arg(long, conflicts_with = "id")]
    pub anonymous: bool,
    /// Interface names or local IPs to include in the report
    #[arg(long = "interface", default_value = "*")]
    pub binds: Vec<BindPattern>,
    /// Show local bindings and incomplete observations
    #[arg(short, long)]
    pub verbose: bool,
}
impl Options {
    fn home_scope(&self) -> home::HomeScope {
        if self.global {
            home::HomeScope::Global
        } else {
            home::HomeScope::User
        }
    }
}
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(display("failed to initialize DHTTP NAT diagnostics"))]
    Network { source: dhttp::Error },
    #[snafu(display("failed to load dhttp home"))]
    Home { source: home::LoadDhttpHomeError },
    #[snafu(display("failed to load selected identity"))]
    Identity {
        source: home::identity::ssl::ResolveIdentityProfileError,
    },
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

fn selected(patterns: &[BindPattern], device: &str, ip: std::net::IpAddr) -> bool {
    patterns
        .iter()
        .any(|p| p == "*" || p == device || p == &ip.to_string())
}

pub async fn run(options: Options) -> Result<(), Error> {
    let _guard = init_tracing();
    init_network(&[DnsScheme::System, DnsScheme::H3], &["*".into()])
        .await
        .context(error::NetworkSnafu)?;
    if let Some(name) = options.id.as_ref() {
        let home = home::DhttpHome::load(options.home_scope()).context(error::HomeSnafu)?;
        let profile = home
            .resolve_identity_profile((name.borrow()).as_full())
            .await
            .context(error::IdentitySnafu)?;
        dhttp::Endpoint::load_from_with_ocsp(profile.path())
            .await
            .context(error::NetworkSnafu)?;
    }
    let addresses = AddressBook::global();
    let candidates: HashMap<_, _> = addresses
        .inner_bindings()
        .into_iter()
        .filter(|(bound, device)| {
            !bound.ip().is_loopback() && selected(&options.binds, device.name(), bound.ip())
        })
        .collect();
    let mut events = addresses.subscribe_punch(dhttp::Scopes::ALL);
    let mut completed = HashSet::new();
    let mut successes = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while completed.len() < candidates.len() {
        let event = match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(event)) => event,
            _ => break,
        };
        if let AddressEvent::Added {
            bound,
            endpoint,
            nat,
        } = event
        {
            if !candidates.contains_key(&bound)
                || endpoint.scope() != Some(dhttp::Scope::External)
                || !completed.insert(bound)
            {
                continue;
            }
            let device = &candidates[&bound];
            println!(
                "Interface: {} ({bound})\nNAT type: {nat:?}\nExternal IP: {}",
                device.name(),
                endpoint.addr().ip()
            );
            successes += 1;
        }
    }
    println!(
        "Detected NAT on {successes} of {} candidate interfaces.",
        candidates.len()
    );
    if options.verbose {
        for (bound, device) in candidates {
            if !completed.contains(&bound) {
                println!(
                    "Interface: {} ({bound}): no public mapping; NAT classification: {:?}",
                    device.name(),
                    addresses.nat(bound)
                );
            }
        }
    }
    Ok(())
}

async fn init_network(schemes: &[ddns::DnsScheme], binds: &[String]) -> dhttp::Result<()> {
    if binds.iter().any(|bind| bind != "*") {
        return Err(dhttp::Error::InvalidRequest {
            message: "the process-wide DHTTP network currently requires --interface '*'".into(),
        });
    }
    let mdns = ddns::install_resolvers(schemes)?;
    let network = dhttp::DhttpNetwork::init().await?;
    if let Some(mdns) = mdns {
        static MAINTENANCE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
        MAINTENANCE
            .get_or_try_init(|| async {
                mdns.maintain(std::time::Duration::from_secs(1), move || {
                    Ok(network
                        .active_bindings()
                        .map_err(std::io::Error::other)?
                        .into_iter()
                        .filter(|binding| {
                            dhttp::resolve::EndpointAddr::direct(binding.address).scope()
                                == Some(dhttp::Scope::Internal)
                        })
                        .map(|binding| {
                            ddns::mdns::MdnsBinding::new(binding.device, binding.address.ip())
                        })
                        .collect())
                })
                .await?;
                Ok::<(), std::io::Error>(())
            })
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn options_accept_global_flag() {
        let options = Options::try_parse_from(["nat-detect", "--global"]).unwrap();
        assert_eq!(options.home_scope(), home::HomeScope::Global);
    }
    #[test]
    fn interface_filter_selects_names_and_addresses() {
        let ip = "192.0.2.1".parse().unwrap();
        assert!(selected(&["*".into()], "eth0", ip));
        assert!(selected(&["eth0".into()], "eth0", ip));
        assert!(selected(&["192.0.2.1".into()], "eth0", ip));
        assert!(!selected(&["eth1".into()], "eth0", ip));
    }
}
