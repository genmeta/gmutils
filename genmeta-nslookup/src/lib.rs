use std::{
    collections::{BTreeSet, HashMap, HashSet},
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
use h3x::gm_quic::BuildClientError;
use snafu::{ResultExt, Snafu, ensure};
use tokio::time;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(name = "nslookup", version, about)]
pub struct Options {
    /// Name to query
    #[arg(index = 1)]
    name: Name<'static>,

    /// Scheme of DNS to query eg. mdns system http
    #[arg(index = 2, default_value = "all")]
    schemes: Vec<DnsScheme>,

    /// Identity to use for connections to DHTTP/3 DNS server (load from $GENMETA_HOME)
    #[arg(short, long)]
    id: Option<Name<'static>>,

    /// Enable streaming output: print records as they are resolved
    #[arg(short, long, default_value = "true")]
    streaming: bool,

    // TODO: remove this option
    /// Timeout for the whole lookup process, in seconds
    #[arg(short, long, default_value = "10")]
    timeout: u64,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    LocateGenmetaHome {
        source: genmeta_home::LocateGenmetaHomeError,
    },
    #[snafu(display("failed to build DNS resolvers"))]
    BuildDnsResolvers { source: BuildClientError },
    #[snafu(display("failed to lookup DNS records of `{name}`"))]
    LookUp {
        name: Name<'static>,
        source: DnsErrors,
    },

    #[snafu(display("lookup timed out after {timeout} seconds"))]
    Timedout { timeout: u64 },
}

pub async fn run(options: Options) -> Result<(), Error> {
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
                .from_env_lossy(),
        )
        // .with(console_subscriber::spawn())
        .init();

    let id = id::load_home_and_identity(
        options.id.is_some(),
        options
            .id
            .as_ref()
            .map(|id| (&"command line option" as &dyn std::fmt::Display, id.clone())),
    )
    .await?;

    let bind_setup = bind::setup_bind_interfaces_with(
        bind::Binds::new(vec![
            Bind::from_str("*").expect("wildcard bind pattern is always valid"),
        ]),
        dns::handy::ensure_default_mdns_prop,
    )
    .await
    .expect("wildcard bind should not conflict");

    let dns_setup = dns::handy::build_resolvers(
        options.schemes.into_iter().collect::<BTreeSet<_>>(),
        &bind_setup.bind_interfaces,
        id.as_ref(),
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
        let timeout = options.timeout;
        let collect = time::timeout(time::Duration::from_secs(timeout), collect);

        ensure!(
            collect.await.is_ok() || !endpoint_addrs.is_empty(),
            TimedoutSnafu { timeout }
        );

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
