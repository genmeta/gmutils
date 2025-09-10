use std::{collections::HashSet, fmt::Display, io, sync::Arc};

use clap::{Parser, ValueEnum};
use futures::StreamExt;
use qdns::{HttpResolver, MdnsResolver, Resolvers, UdpResolver};
use snafu::{ResultExt, Snafu};

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
    schema: Schema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Schema {
    Udp,
    Http,
    Mdns,
    All,
}

impl Display for Schema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Schema::Udp => write!(f, "udp"),
            Schema::Http => write!(f, "https"),
            Schema::Mdns => write!(f, "mdns"),
            Schema::All => write!(f, "all"),
        }
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to bind `{schema}` resolver"))]
    BindResolverFailed {
        schema: Schema,
        #[snafu(source)]
        source: io::Error,
    },

    #[snafu(display("No DNS records found for domain `{domain}`"))]
    NoResult { domain: String },
}

pub async fn run(Options { domain, schema }: Options) -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::WARN.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();
    let mut resolvers = Resolvers::new();
    resolvers = match schema {
        Schema::Udp => resolvers.with(Arc::new(UdpResolver::new(qdns::UDP_DNS_SERVER))),
        Schema::Http => resolvers.with(Arc::new(
            HttpResolver::new(qdns::HTTP_DNS_SERVER).context(BindResolverFailedSnafu { schema })?,
        )),
        Schema::Mdns => resolvers.with(Arc::new(
            MdnsResolver::new(qdns::MDNS_SERVICE).context(BindResolverFailedSnafu { schema })?,
        )),
        Schema::All => resolvers
            .with(Arc::new(
                MdnsResolver::new(qdns::MDNS_SERVICE)
                    .context(BindResolverFailedSnafu { schema })?,
            ))
            .with(Arc::new(
                HttpResolver::new(qdns::HTTP_DNS_SERVER)
                    .context(BindResolverFailedSnafu { schema })?,
            ))
            .with(Arc::new(UdpResolver::new(qdns::UDP_DNS_SERVER))),
    };

    let domain = if domain.ends_with("~") {
        domain.replacen("~", ".genmeta.net", 1)
    } else {
        domain.clone()
    };

    let mut results = resolvers.lookup(&domain);

    let first_result = results.next().await.ok_or_else(|| Error::NoResult {
        domain: domain.clone(),
    })?;

    let mut results = Box::pin(futures::stream::once(async move { first_result }).chain(results));

    println!("Name: {domain}:");

    while let Some((src, eps)) = results.next().await {
        println!("{src}");
        for endpoint_addr in eps.into_iter().collect::<HashSet<_>>() {
            println!("Address: {endpoint_addr}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use qbase::net::route::SocketEndpointAddr;
    use qdns::{HttpResolver, Resolve};

    #[tokio::test]
    async fn test_dns_query() {
        let http_dns = HttpResolver::new("https://dns.genmeta.net/").unwrap();
        let addresses = vec![
            SocketEndpointAddr::direct("192.168.1.1:8080".parse().unwrap()),
            SocketEndpointAddr::with_agent(
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
