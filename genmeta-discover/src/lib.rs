use std::{
    collections::{HashMap, HashSet},
    io::IsTerminal,
    pin::Pin,
    sync::{Arc, Mutex},
};

use clap::Parser;
use futures::{Future, StreamExt};
use genmeta_common::{
    bind::{self, Binds},
    dns,
};
use gmdns::{parser::record::RData, resolvers::MdnsResolvers};
use h3x::dquic::{
    prelude::handy::DEFAULT_IO_FACTORY,
    qinterface::{BindInterface, bind_uri::BindUri},
};
use snafu::ResultExt;
use tokio::sync::Notify;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(name = "discover", version, about)]
pub struct Options {
    /// Domain name to discover (e.g. _genmeta.local)
    #[arg(value_name = "DOMAIN", default_value = "")]
    domain: String,

    /// Bind patterns for local network interfaces
    #[arg(long = "interface", value_name = "bind", default_value = "*",
          hide = cfg!(not(debug_assertions)))]
    binds: Vec<bind::Bind>,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(display("failed to setup bind interfaces"))]
    SetupBind {
        source: Box<bind::BindConflictError>,
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

pub async fn run(mut options: Options) -> Result<(), Error> {
    let _guard = init_tracing();

    let binds = Binds::new(std::mem::take(&mut options.binds));
    let bind_setup = bind::setup_bind_interfaces_with(&binds, dns::handy::ensure_default_mdns_prop)
        .await
        .context(error::SetupBindSnafu)?;

    // Build mDNS resolvers using the shared helper.
    // MdnsResolvers holds WeakInterface references — we keep the original
    // BindInterfaces alive via `live_ifaces` for the Mdns components to remain
    // reachable during the discover loop.
    let resolvers = Arc::new(dns::handy::mdns_resolvers(
        bind_setup.bind_interfaces.iter().cloned(),
    ));

    // Shared strong-reference storage: keeps BindInterfaces alive so their
    // WeakInterface refs inside MdnsResolvers remain valid.
    let live_ifaces: Arc<Mutex<HashMap<String, BindInterface>>> = Arc::new(Mutex::new(
        bind_setup
            .bind_interfaces
            .into_iter()
            .map(|iface| (iface.bind_uri().identity_key(), iface))
            .collect(),
    ));

    // Notification channel for network changes.
    let notify = Arc::new(Notify::new());

    // Start background watcher for interface changes.
    let _watcher = {
        let resolvers = resolvers.clone();
        let live_ifaces = live_ifaces.clone();
        let notify = notify.clone();
        let iface_manager = bind_setup.iface_manager.clone();

        bind::watch_bind_interfaces(
            &binds,
            bind_setup.monitor,
            bind_setup.bind_uris,
            // bind_fn: called when a new interface appears
            {
                let resolvers = resolvers.clone();
                let live_ifaces = live_ifaces.clone();
                let notify = notify.clone();
                let iface_manager = iface_manager.clone();
                move |mut uri: BindUri| -> Pin<Box<dyn Future<Output = ()> + Send>> {
                    let resolvers = resolvers.clone();
                    let live_ifaces = live_ifaces.clone();
                    let notify = notify.clone();
                    let iface_manager = iface_manager.clone();
                    Box::pin(async move {
                        // ensure mdns=true on newly discovered interfaces
                        if uri.prop("mdns").is_none() {
                            uri.add_prop("mdns", "true");
                        }
                        let io_factory = Arc::new(DEFAULT_IO_FACTORY);
                        let iface = iface_manager.bind(uri, io_factory).await;
                        init_mdns_on_iface(&resolvers, &iface);
                        let key = iface.bind_uri().identity_key();
                        live_ifaces
                            .lock()
                            .expect("live_ifaces poisoned")
                            .insert(key, iface);
                        tracing::info!("network change: new interface bound, restarting discovery");
                        notify.notify_one();
                    })
                }
            },
            // unbind_fn: called when an interface disappears
            {
                let live_ifaces = live_ifaces.clone();
                let notify = notify.clone();
                move |uri: BindUri| {
                    let key = uri.identity_key();
                    live_ifaces
                        .lock()
                        .expect("live_ifaces poisoned")
                        .remove(&key);
                    tracing::info!("network change: interface removed, restarting discovery");
                    notify.notify_one();
                }
            },
        )
    };

    // Auto-append ._genmeta.local suffix if not already present.
    let with_suffix = if options.domain.is_empty() || options.domain.ends_with("._genmeta.local") {
        options.domain.clone()
    } else {
        format!("{}._genmeta.local", options.domain)
    };

    let matches_domain = |name: &str, domain: &str| {
        if domain.is_empty() {
            true
        } else {
            name == domain || name.ends_with(&format!(".{}", domain))
        }
    };

    let mut domain_set = HashSet::new();
    let mut stream = resolvers.discover();

    loop {
        tokio::select! {
            item = stream.next() => {
                let Some((_source, packet)) = item else { break };
                let records: HashMap<_, HashSet<_>> = packet
                    .answers
                    .iter()
                    .filter(|a| {
                        matches_domain(&a.name(), &options.domain)
                            || matches_domain(&a.name(), with_suffix.as_str())
                    })
                    .fold(HashMap::new(), |mut map, record| {
                        map.entry(record.name().to_string())
                            .or_default()
                            .insert(record.data().clone());
                        map
                    });
                for (name, rdata_set) in records {
                    if !domain_set.insert(name.clone()) {
                        continue;
                    }
                    println!("Name: {name}");
                    for rdata in rdata_set {
                        match rdata {
                            RData::A(ip) => println!("{ip}"),
                            RData::AAAA(ip) => println!("{ip}"),
                            RData::E(ep) => println!("{ep}"),
                            _ => continue,
                        }
                    }
                }
            }
            _ = notify.notified() => {
                // Network topology changed — restart the discover stream to
                // pick up newly added (or drop removed) mDNS resolvers.
                domain_set.clear();
                stream = resolvers.discover();
                tracing::debug!("discovery stream restarted after network change");
            }
        }
    }

    Ok(())
}

/// Initialize an mDNS resolver component on a bound interface and register it
/// with the shared resolvers collection.
fn init_mdns_on_iface(resolvers: &MdnsResolvers, iface: &BindInterface) {
    use gmdns::resolvers::MdnsResolver;

    if iface.bind_uri().prop("mdns").is_some_and(|v| v == "true")
        && iface.with_components_mut(|components, iface| {
            components
                .try_init_with(|| MdnsResolver::from_iface(dns::MDNS_SERVICE, iface))
                .map(|resolver| resolver.service_name() == dns::MDNS_SERVICE)
                .unwrap_or_default()
        })
    {
        tracing::debug!(bind_uri = %iface.bind_uri(), "initialized mDNS resolver for new interface");
        resolvers.insert_iface(iface.clone());
    }
}
