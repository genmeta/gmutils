use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use clap::Parser;
use futures::{StreamExt, stream};
use genmeta_common::error::Whatever;
use qbase::net::addr::BindUri;
use qdns::{MDNS_SERVICE, MdnsResolver};
use qinterface::iface::physical::{Interface, PhysicalInterfaces};
use snafu::{Report, ResultExt};

#[derive(Parser, Debug, Clone)]
#[command(name = "discover", version, about)]
pub struct Options {
    /// Domain name to discover eg. _genmeta.local, default is empty (all services)
    #[arg(
        value_name = "DOMAIn",
        default_value = "",
        help = "Domain name to discover eg. _genmeta.local, default is empty"
    )]
    domain: String,

    #[arg(value_name = "DEVICES", value_delimiter = ',')]
    devices: Vec<String>,
}

type Error = genmeta_common::error::Whatever;

fn bind_mdns_resolver(
    interfaces: &HashMap<String, Interface>,
    device: &str,
) -> Result<MdnsResolver, Whatever> {
    let socket_addr = BindUri::from(format!("iface://v4.{device}:5353"))
        .resolve(interfaces.get(device))
        .whatever_context(format!("Failed to create mDNS resolver for {device}"))?;
    let SocketAddr::V4(socket_addr) = socket_addr else {
        unreachable!()
    };

    let mdns_resolver = MdnsResolver::new(MDNS_SERVICE, *socket_addr.ip(), device)
        .whatever_context(format!("Failed to create mDNS resolver for {device}"))?;
    Result::<_, Whatever>::Ok(mdns_resolver)
}

pub async fn run(options: Options) -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();

    let interfaces = PhysicalInterfaces::global().interfaces();
    let devices: &mut dyn Iterator<Item = &String> = match options.devices.as_slice() {
        [] => &mut interfaces.keys(),
        devices => &mut devices.iter(),
    };

    let mdns_resolvers = devices
        .filter_map(|device| {
            bind_mdns_resolver(&interfaces, device)
                .inspect_err(
                    |error| tracing::debug!("{}", Report::from_error(error)),
                )
                .ok()
        })
        .map(Arc::new)
        .collect::<Vec<_>>();

    let mut stream = stream::iter(&mdns_resolvers).flat_map_unordered(None, |resolver| {
        resolver
            .discover()
            .map(move |discover| (resolver.clone(), discover))
    });

    let mut domain_set = HashSet::new();
    while let Some((_resolver, (_source, packet))) = stream.next().await {
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
