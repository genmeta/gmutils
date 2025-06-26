use std::{collections::HashSet, sync::Arc};

use clap::Parser;
use qdns::{HttpResolver, MdnsResolver, Resolvers, UdpResolver};

#[derive(Parser, Debug, Clone)]
#[command(name = "nslookup", version, about)]
pub struct Options {
    /// Target domain name or IP address to resolve (default: test.genmeta.net)
    #[arg(
        value_name = "DOMAIN",
        index = 1,
        help = "Domain name to query, query "
    )]
    domain: String,

    /// Type of DNS record to query (default: all)
    #[arg(
        value_name = "SCHEMA",
        index = 2,
        default_value = "all",
        help = "Schema of DNS to query eg. mdns system https udp , default is all"
    )]
    schema: String,
}

type Error = Box<dyn core::error::Error + Send + Sync>;

pub async fn run(options: Options) -> Result<(), Error> {
    let mut resolvers = Resolvers::new();
    resolvers = match options.schema.as_str() {
        "mdns" => resolvers.with(Arc::new(MdnsResolver::new(qdns::MDNS_SERVICE)?)),
        "https" => resolvers.with(Arc::new(HttpResolver::new(qdns::HTTP_DNS_SERVER)?)),
        "udp" => resolvers.with(Arc::new(UdpResolver::new(qdns::UDP_DNS_SERVER))),
        "all" => resolvers
            .with(Arc::new(MdnsResolver::new(qdns::MDNS_SERVICE)?))
            .with(Arc::new(HttpResolver::new(qdns::HTTP_DNS_SERVER)?))
            .with(Arc::new(UdpResolver::new(qdns::UDP_DNS_SERVER))),
        _ => return Err("Invalid DNS schema".into()),
    };

    let domain = if options.domain.ends_with("~") {
        options.domain.replacen("~", ".genmeta.net", 1)
    } else {
        options.domain.clone()
    };
    let ret = resolvers.lookup(&domain, true).await.map_err(Box::new)?;

    println!("DNS lookup results for {domain}:");

    for (src, eps) in ret {
        let mut set = HashSet::new();
        let eps: Vec<_> = eps.into_iter().filter(|&x| set.insert(x)).collect();
        println!("Source: {src}");
        for addr in eps.iter() {
            match addr {
                qbase::net::EndpointAddr::Direct { addr } => {
                    println!("Address: {addr}");
                }
                qbase::net::EndpointAddr::Agent { agent, outer } => {
                    println!("Address: {agent}-{outer}")
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use qbase::net::EndpointAddr;
    use qdns::{HttpResolver, Resolve};

    #[tokio::test]
    async fn test_dns_query() {
        let http_dns = HttpResolver::new("https://dns.genmeta.net/").unwrap();
        let addresses = vec![
            EndpointAddr::direct("192.168.1.1:8080".parse().unwrap()),
            EndpointAddr::with_agent(
                "192.168.1.2:8080".parse().unwrap(),
                "114.114.114.114:8080".parse().unwrap(),
            ),
        ];

        http_dns
            .publish("test1.genmeta.net", &addresses)
            .await
            .unwrap();
    }
}
