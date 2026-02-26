use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt,
    str::FromStr,
    sync::Arc,
};

use clap::Parser;
use futures::{StreamExt, stream::FuturesUnordered};
use genmeta_common::{
    bind::Bind,
    dns::{self, DnsScheme},
    id,
};
use genmeta_home::{GenmetaHome, identity::Name};
use gmdns::resolvers::{DnsErrors, Resolvers};
use h3x::gm_quic::{
    BuildClientError,
    prelude::handy::DEFAULT_IO_FACTORY,
    qinterface::{device::Devices, manager::InterfaceManager},
};
use snafu::{ResultExt, Snafu, ensure};
use tokio::time;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(name = "nslookup", version, about)]
pub struct Options {
    /// Name to query
    #[arg(index = 1)]
    name: Name<'static>,

    /// Scheme of DNS to query eg. mdns system http
    #[arg(index = 2, default_value = "all")]
    schemes: Vec<DnsScheme>,

    /// Identity to use for connections to H3 DNS server (load from $GENMETA_HOME)
    #[arg(short, long)]
    id: Option<Name<'static>>,

    /// Enable streaming output: print records as they are resolved
    #[arg(short, long, default_value = "true")]
    streaming: bool,

    // TODO: remove this option
    /// Timeout for the whole lookup process, in seconds
    #[arg(short, long, default_value = "10")]
    timeout: u64,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    LocateGenmetaHome {
        source: genmeta_home::LocateGenmetaHomeError,
    },
    #[snafu(display("failed to build h3 DNS client"))]
    BuildH3DnsClient { source: BuildClientError },
    #[snafu(display("failed to lookup DNS records of `{name}`"))]
    LookUp {
        name: Name<'static>,
        source: DnsErrors,
    },

    #[snafu(display("lookup timed out after {timeout} seconds"))]
    Timedout { timeout: u64 },
}

pub async fn run(options: Options) -> Result<(), Error> {
    let (stderr, _guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(stderr))
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        // .with(console_subscriber::spawn())
        .init();

    let genmeta_home = GenmetaHome::load_from_environment();
    let mut id = None;
    if genmeta_home.is_ok() || options.id.is_some() {
        let source = &"command line option" as &dyn fmt::Display;
        id = id::load_id(&genmeta_home?, options.id.map(|id| (source, id))).await;
    }

    let iface_manager = Arc::new(InterfaceManager::new());
    let io_factory = Arc::new(DEFAULT_IO_FACTORY);
    let bind_interfaces = Bind::from_str("*")
        .expect("Genmeta supports `*` as bind to indicate all interfaces")
        .to_bind_uris(Devices::global().interfaces().keys().map(String::as_str))
        .map(|bind_uri| iface_manager.bind(bind_uri.clone(), io_factory.clone()))
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;

    let mut resolvers = Resolvers::new();
    for dns_scheme in options.schemes.into_iter().collect::<BTreeSet<_>>() {
        match dns_scheme {
            DnsScheme::System => {
                resolvers = resolvers.with(Arc::new(dns::handy::system_resolver()))
            }
            DnsScheme::Mdns => {
                let mdns_resolvers = dns::handy::mdns_resolvers(bind_interfaces.iter().cloned());
                resolvers = resolvers.with(Arc::new(mdns_resolvers));
            }
            DnsScheme::Http => {
                resolvers = resolvers.with(Arc::new(dns::handy::http_resolver()));
            }
            DnsScheme::H3 => {
                let resolver = Arc::new(resolvers.clone());
                let resolver = dns::handy::h3_resolver(resolver, id.as_ref());
                resolvers = resolvers.with(Arc::new(resolver.context(BuildH3DnsClientSnafu)?));
            }
            DnsScheme::Dht => {
                unimplemented!("DHT resolver is not implemented yet");
            }
        }
    }

    tracing::debug!(%resolvers);

    let mut lookup = resolvers
        .lookup(options.name.as_full())
        .await
        .context(LookUpSnafu {
            name: options.name.to_owned(),
        })?;

    if options.streaming {
        println!("Name: {}:", options.name);
        let mut last_source = None;
        while let Some((source, endpoint_addr)) = lookup.next().await {
            if !last_source.is_some_and(|last| last == source) {
                println!("{source}:");
            }
            println!("{endpoint_addr}");
            last_source = Some(source);
        }
    } else {
        let mut endpoint_addrs = HashMap::new();

        let collect = lookup.for_each(|(source, endpoint)| {
            endpoint_addrs
                .entry(source)
                .or_insert_with(HashSet::new)
                .insert(endpoint);
            async {}
        });
        let timeout = options.timeout;
        let collect = time::timeout(time::Duration::from_secs(timeout), collect);

        ensure!(
            collect.await.is_ok() || !endpoint_addrs.is_empty(),
            TimedoutSnafu { timeout }
        );

        println!("Name: {}:", options.name);
        for (source, endpoint_addrs) in endpoint_addrs.into_iter() {
            println!("{source}:");
            for endpoint_addr in endpoint_addrs.into_iter().collect::<HashSet<_>>() {
                println!("Address: {endpoint_addr}");
            }
        }
    }

    Ok(())
}
