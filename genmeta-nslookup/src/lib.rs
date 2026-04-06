use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io::IsTerminal,
    str::FromStr,
};

use clap::Parser;
use futures::StreamExt;
use genmeta_common::{
    bind::{self, Bind},
    dns::{self, DnsScheme},
    id,
};
use genmeta_home::identity::Name;
use gmdns::resolvers::DnsErrors;
use h3x::dquic::BuildClientError;
use snafu::{ResultExt, Snafu};
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(name = "nslookup", version, about)]
pub struct Options {
    /// Name to query
    #[arg(index = 1)]
    name: Name<'static>,

    /// DNS resolution scheme (e.g. system, mdns, h3)
    #[arg(index = 2, default_value = "mdns,h3", value_delimiter = ',')]
    schemes: Vec<DnsScheme>,

    /// Client identity
    #[arg(short, long)]
    id: Option<Name<'static>>,

    /// Skip identity loading and use anonymous mode
    #[arg(long, conflicts_with = "id")]
    anonymous: bool,

    /// Print records as they are resolved
    #[arg(short, long, default_value = "true")]
    streaming: bool,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    LoadHomeAndIdentity {
        source: id::LoadHomeAndIdentityError,
    },
    #[snafu(display("failed to build DNS resolvers"))]
    BuildDnsResolvers { source: BuildClientError },
    #[snafu(display("failed to load identity ssl material"))]
    LoadIdentitySsl {
        source: genmeta_home::identity::ssl::LoadIdentitySslError,
    },
    #[snafu(display("failed to lookup DNS records of `{name}`"))]
    LookUp {
        name: Name<'static>,
        source: DnsErrors,
    },
}

/// Initialize tracing subscriber with stderr output.
fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (stderr, guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_ansi(std::io::stderr().is_terminal())
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
        // .with(console_subscriber::spawn())
        .init();
    guard
}

pub async fn run(options: Options) -> Result<(), Error> {
    let _guard = init_tracing();
    let id = if options.anonymous {
        None
    } else {
        id::load_home_and_identity(
            options.id.is_some(),
            options
                .id
                .as_ref()
                .map(|id| (&"command line option" as &dyn std::fmt::Display, id.clone())),
        )
        .await?
    };

    let binds = bind::Binds::new(vec![
        Bind::from_str("*").expect("BUG: wildcard bind pattern is always valid"),
    ]);
    let bind_setup = bind::setup_bind_interfaces_with(&binds, dns::handy::ensure_default_mdns_prop)
        .await
        .expect("BUG: wildcard bind should not conflict");

    let id_material = match &id {
        Some(id) => Some(id.identity().await.context(LoadIdentitySslSnafu)?),
        None => None,
    };

    let dns_setup = dns::handy::build_resolvers(
        options.schemes.into_iter().collect::<BTreeSet<_>>(),
        &bind_setup.bind_interfaces,
        id_material.as_ref(),
    )
    .context(BuildDnsResolversSnafu)?;

    tracing::debug!(%dns_setup.resolvers);

    let mut lookup = dns_setup
        .resolvers
        .lookup(options.name.as_full())
        .await
        .context(LookUpSnafu {
            name: options.name.to_owned(),
        })?;

    if options.streaming {
        println!("Name: {}:", options.name);
        let mut last_source = None;
        while let Some((source, endpoint_addr)) = lookup.next().await {
            if !last_source.is_some_and(|last| last == source) {
                println!("{source}:");
            }
            println!("{endpoint_addr}");
            last_source = Some(source);
        }
    } else {
        let mut endpoint_addrs = HashMap::new();

        let collect = lookup.for_each(|(source, endpoint)| {
            endpoint_addrs
                .entry(source)
                .or_insert_with(HashSet::new)
                .insert(endpoint);
            async {}
        });
        collect.await;

        println!("Name: {}:", options.name);
        for (source, endpoint_addrs) in endpoint_addrs.into_iter() {
            println!("{source}:");
            for endpoint_addr in endpoint_addrs.into_iter().collect::<HashSet<_>>() {
                println!("Address: {endpoint_addr}");
            }
        }
    }

    Ok(())
}
