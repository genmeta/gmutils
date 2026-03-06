use std::collections::{HashMap, HashSet};

use clap::Parser;
use futures::StreamExt;
use genmeta_common::{
    bind::{self, Binds},
    dns,
};
use gmdns::parser::record::RData;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(name = "discover", version, about)]
pub struct Options {
    /// Domain name to discover (e.g. _genmeta.local)
    #[arg(value_name = "DOMAIN", default_value = "")]
    domain: String,

    /// Bind patterns for local network interfaces
    #[arg(long = "interface", value_name = "bind", default_value = "*")]
    binds: Vec<bind::Bind>,
}

#[derive(Debug, snafu::Snafu)]
pub enum Error {
    #[snafu(transparent)]
    BindConflict { source: bind::BindConflictError },
}

pub async fn run(mut options: Options) -> Result<(), Error> {
    let (stderr, _guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive("netlink_packet_route=error".parse().unwrap()),
        )
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
    .await?;

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
