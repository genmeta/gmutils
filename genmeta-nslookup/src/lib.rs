use std::sync::Arc;

use clap::Parser;
use qbase::net::EndpointAddr;
use qdns::{HttpResolver, MdnsResolver, Resolve, Resolvers, UdpResolver};

/// command-line tool to resolve domain names.
#[derive(Parser, Debug, Clone)]
#[command(name = "nslookup")]
pub struct Options {
    /// Target domain name or IP address to resolve (default: test.genmeta.net)
    #[arg(
        short,
        long,
        value_name = "DOMAIN",
        help = "Domain name or IP address to query"
    )]
    domain: String,

    /// Type of DNS record to query (default: All).
    #[arg(
        short,
        long,
        value_name = "RECORD_TYPE",
        default_value = "All",
        help = "Type of DNS record to query (e.g. E, EE, E6, EE6, All)"
    )]
    record_type: String,

    /// Enable verbose output and detailed tracing information.
    #[arg(short, long, help = "Enable verbose output with detailed tracing")]
    verbose: bool,
}

type Error = Box<dyn core::error::Error + Send + Sync>;

pub async fn run(options: Options) -> Result<(), Error> {
    let resolvers = Resolvers::new()
        .with(Arc::new(MdnsResolver::new(Resolvers::MDNS_SERVICE)?))
        .with(Arc::new(HttpResolver::new(Resolvers::HTTP_DNS_SERVER)?))
        .with(Arc::new(UdpResolver::new(Resolvers::UDP_DNS_SERVER)));
    let ret = resolvers.lookup(&options.domain).await.map_err(Box::new)?;

    for addr in ret {
        let record_type = record_type(addr);
        if options.record_type == "All" || options.record_type == record_type {
            println!("Name: {}", options.domain);
            println!("Endpoint: {addr:?}\n");
        }
    }
    Ok(())
}

fn record_type(ep: EndpointAddr) -> String {
    match ep {
        EndpointAddr::Direct { addr } if addr.is_ipv4() => "E".to_string(),
        EndpointAddr::Direct { addr } if addr.is_ipv6() => "E6".to_string(),
        EndpointAddr::Agent { agent, outer: _ } if agent.is_ipv4() => "EE".to_string(),
        EndpointAddr::Agent { agent, outer: _ } if agent.is_ipv6() => "EE6".to_string(),
        _ => "Unknown".to_string(),
    }
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
