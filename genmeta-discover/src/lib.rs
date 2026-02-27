use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use clap::Parser;
use futures::{StreamExt, stream::FuturesUnordered};
use genmeta_common::{
    bind::{self, Binds},
    dns,
};
use gmdns::parser::record::RData;
use h3x::gm_quic::{
    prelude::handy::DEFAULT_IO_FACTORY,
    qinterface::{device::Devices, manager::InterfaceManager},
};
use snafu::ResultExt;

#[derive(Parser, Debug, Clone)]
#[command(name = "discover", version, about)]
pub struct Options {
    /// Domain name to discover eg. _genmeta.local, default is empty (all services)
    #[arg(
        value_name = "DOMAIN",
        default_value = "",
        help = "Domain name to discover eg. _genmeta.local, default is empty"
    )]
    domain: String,

    /// Bind patterns to specify which local interfaces to discover on.
    #[arg(long = "interface", value_name = "bind", default_value = "*")]
    binds: Vec<bind::Bind>,
}

type Error = genmeta_common::error::Whatever;

pub async fn run(mut options: Options) -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

    // Expand bind patterns into concrete bind URIs
    let monitor = Devices::global().monitor();
    let binds = Binds::new(std::mem::take(&mut options.binds));
    let mut bind_uris = binds
        .to_bind_uris(monitor.interfaces().keys().map(String::as_str))
        .whatever_context("failed to resolve bind patterns")?;

    // Ensure every bind URI has mdns=true so dns::handy::mdns_resolvers() picks it up
    for uri in &mut bind_uris {
        if uri.prop("mdns").is_none() {
            uri.add_prop("mdns", "true");
        }
    }

    // Bind interfaces
    let iface_manager = Arc::new(InterfaceManager::new());
    let io_factory = Arc::new(DEFAULT_IO_FACTORY);
    let bind_interfaces: Vec<_> = bind_uris
        .iter()
        .map(|uri| iface_manager.bind(uri.clone(), io_factory.clone()))
        .collect::<FuturesUnordered<_>>()
        .collect()
        .await;

    // Build mDNS resolvers using the shared helper
    let resolvers = dns::handy::mdns_resolvers(bind_interfaces);

    let mut stream = resolvers.discover();

    let mut domain_set = HashSet::new();
    while let Some((_source, packet)) = stream.next().await {
        let records: HashMap<_, HashSet<_>> = packet
            .answers
            .iter()
            .filter(|a| a.name().contains(&options.domain))
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
    Ok(())
}
