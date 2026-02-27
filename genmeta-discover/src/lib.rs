use std::collections::{HashMap, HashSet};

use clap::Parser;
use futures::StreamExt;
use genmeta_common::{
    bind::{self, Binds},
    dns,
};
use gmdns::parser::record::RData;
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

    let bind_setup = bind::setup_bind_interfaces_with(
        Binds::new(std::mem::take(&mut options.binds)),
        |bind_uris| {
            for uri in bind_uris.iter_mut() {
                if uri.prop("mdns").is_none() {
                    uri.add_prop("mdns", "true");
                }
            }
        },
    )
    .await
    .whatever_context("failed to resolve bind patterns")?;

    // Build mDNS resolvers using the shared helper
    let resolvers = dns::handy::mdns_resolvers(bind_setup.bind_interfaces);

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
