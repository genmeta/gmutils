use std::collections::{HashMap, HashSet};

use clap::Parser;
use futures::StreamExt;
use qdns::MdnsResolver;
use snafu::ResultExt;

#[derive(Parser, Debug, Clone)]
#[command(name = "discover", version, about)]
pub struct Options {
    /// Target domain name or IP address to resolve (default: test.genmeta.net)
    #[arg(
        value_name = "DOMAIN",
        index = 1,
        default_value = "",
        help = "Domain name to discover eg. _genmeta.local, default is empty"
    )]
    domain: String,
}

type Error = genmeta_common::error::Whatever;

pub async fn run(options: Options) -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();
    let mut mdns =
        MdnsResolver::new(qdns::MDNS_SERVICE).whatever_context("Failed to create mDNS resolver")?;
    let mut stream = mdns.discover();
    let mut domain_set = HashSet::new();
    while let Some((_, packet)) = stream.next().await {
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
                    qdns::RData::A(ip) => println!("{ip}"),
                    qdns::RData::AAAA(ip) => println!("{ip}"),
                    qdns::RData::E(ep)
                    | qdns::RData::EE(ep)
                    | qdns::RData::E6(ep)
                    | qdns::RData::EE6(ep) => {
                        println!("{ep}")
                    }
                    _ => continue,
                }
            }
        }
    }
    Ok(())
}
