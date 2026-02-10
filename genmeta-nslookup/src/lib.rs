use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    io,
    sync::Arc,
};

use clap::{Parser, ValueEnum};
use futures::StreamExt;
use genmeta_home::{GenmetaHome, identity::Name};
use gmdns::{
    H3_DNS_SERVER, HTTP_DNS_SERVER, MDNS_SERVICE,
    resolvers::{DnsErrors, H3Resolver, HttpResolver, Resolvers},
};
use h3x::gm_quic::{H3Client, qdns::SystemResolver};
use snafu::{ResultExt, Snafu, ensure};
use tokio::time;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(name = "nslookup", version, about)]
pub struct Options {
    /// Name to query
    #[arg(index = 1)]
    name: Name<'static>,

    /// Schema of DNS to query eg. mdns system http
    #[arg(index = 2, default_value = "all")]
    schemas: Vec<DnsSchema>,

    /// Identity to use for connections to H3 DNS server (load from $GENMETA_HOME)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DnsSchema {
    Http,
    Mdns,
    All,
    Systme,
    H3,
}

impl DnsSchema {
    pub const fn as_str(&self) -> &'static str {
        match self {
            DnsSchema::Http => "http",
            DnsSchema::Mdns => "mdns",
            DnsSchema::All => "all",
            DnsSchema::Systme => "system",
            DnsSchema::H3 => "h3",
        }
    }
}

impl Display for DnsSchema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to build `{schema}` resolver"))]
    BuildResolver {
        schema: DnsSchema,
        source: io::Error,
    },

    #[snafu(transparent)]
    LocateGenmetaHome {
        source: genmeta_home::LocateGenmetaHomeError,
    },

    #[snafu(display("failed to load identity `{id}`"))]
    LoadIdentity {
        id: Name<'static>,
        source: genmeta_home::identity::fs::LoadIdentityError,
    },

    #[snafu(display(
        "failed to load default identity(since h3 resolver enabled but identity not specified)"
    ))]
    LoadDefaultIdentity {
        source: genmeta_home::identity::default::LoadDefaultIdentityError,
    },

    #[snafu(display("failed to lookup DNS records of `{name}`"))]
    LookUp {
        name: Name<'static>,
        source: DnsErrors,
    },

    #[snafu(display("lookup timed out after {timeout} seconds"))]
    Timedout { timeout: u64 },
}

pub async fn run(
    Options {
        name,
        mut schemas,
        id,
        streaming,
        timeout,
    }: Options,
) -> Result<(), Error> {
    let (stderr, _guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(stderr))
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        // .with(console_subscriber::spawn())
        .init();

    if schemas.contains(&DnsSchema::All) {
        schemas = vec![
            DnsSchema::Systme,
            DnsSchema::Http,
            DnsSchema::H3,
            DnsSchema::Mdns,
        ];
    } else {
        schemas.dedup();
    };

    let mut resolvers = Resolvers::new();

    for schema in schemas {
        tracing::debug!(?schema, "Enabled resolver schema");

        resolvers = match schema {
            DnsSchema::Http => resolvers.with(Arc::new(
                HttpResolver::new(HTTP_DNS_SERVER).context(BuildResolverSnafu { schema })?,
            )),
            DnsSchema::H3 => {
                let genmeta_home = GenmetaHome::load_from_environment()?;
                let identity = match id.clone() {
                    Some(id) => genmeta_home
                        .identities()
                        .load(id.clone())
                        .await
                        .context(LoadIdentitySnafu { id: id.clone() })?,
                    None => genmeta_home
                        .identities()
                        .load_default_identity()
                        .await
                        .context(LoadDefaultIdentitySnafu)?,
                };

                let h3_client = H3Client::builder()
                    .with_identity(identity.name().as_full(), identity.certs(), identity.key())
                    .map_err(io::Error::other)
                    .context(BuildResolverSnafu { schema })?
                    .build();
                let h3_resolver = H3Resolver::new(H3_DNS_SERVER, h3_client)
                    .context(BuildResolverSnafu { schema })?;
                resolvers.with(Arc::new(h3_resolver))
            }
            DnsSchema::Systme => resolvers.with(Arc::new(SystemResolver)),
            DnsSchema::Mdns => resolvers.with_mdns_resolvers(MDNS_SERVICE, |_, _| true),
            DnsSchema::All => unreachable!("Handled above"),
        };
    }

    tracing::debug!(%resolvers);

    let mut lookup = resolvers
        .lookup(name.as_full())
        .await
        .context(LookUpSnafu {
            name: name.to_owned(),
        })?;

    if streaming {
        println!("Name: {name}:");
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
        let collect = time::timeout(time::Duration::from_secs(timeout), collect);

        ensure!(
            collect.await.is_ok() || !endpoint_addrs.is_empty(),
            TimedoutSnafu { timeout }
        );

        println!("Name: {name}:");
        for (source, endpoint_addrs) in endpoint_addrs.into_iter() {
            println!("{source}:");
            for endpoint_addr in endpoint_addrs.into_iter().collect::<HashSet<_>>() {
                println!("Address: {endpoint_addr}");
            }
        }
    }

    Ok(())
}
