use std::{
    collections::{HashMap, HashSet},
    io::IsTerminal,
    sync::Arc,
};

use clap::Parser;
use dhttp::{
    ddns::{DHTTP_MDNS_SERVICE, MdnsResolvers, parser::record::RData},
    dquic::{Network, binds::BindPattern},
};
use futures::StreamExt;
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
    binds: Vec<BindPattern>,
}

#[derive(Debug, snafu::Snafu)]
pub enum Error {}

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

pub async fn run(options: Options) -> Result<(), Error> {
    let _guard = init_tracing();

    let network = Network::builder().build();
    let resolvers =
        MdnsResolvers::bind(network, Arc::new(options.binds.clone()), DHTTP_MDNS_SERVICE).await;

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
            name == domain || name.ends_with(&format!(".{domain}"))
        }
    };

    let mut domain_set = HashSet::new();
    let mut stream = resolvers.discover();

    while let Some((_source, packet)) = stream.next().await {
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

    Ok(())
}
