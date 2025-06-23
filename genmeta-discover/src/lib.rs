use std::collections::{HashMap, HashSet};

use clap::Parser;
use gmdns::mdns::Mdns;
use tokio_stream::StreamExt;

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

type Error = Box<dyn core::error::Error + Send + Sync>;

pub async fn run(options: Options) -> Result<(), Error> {
    let mut mdns_resolver = Mdns::new("_genmeta.local", None)?;
    let mut stream = mdns_resolver.discover();

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
            println!("{name}");
            for rdata in rdata_set {
                println!("    {rdata}");
            }
        }
        println!();
    }
    Ok(())
}
