use std::{
    collections::{HashMap, HashSet},
    io::IsTerminal,
    sync::Arc,
};

use clap::Parser;
use dhttp::{
    ddns::resolvers::DnsScheme,
    dquic::binds::BindPattern,
    endpoint::Endpoint,
    home::{self, DhttpHome, identity::IdentityProfile},
    name::DhttpName as Name,
};
use futures::StreamExt;
use snafu::{IntoError, ResultExt, Snafu};
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

    /// Use the global dhttp home instead of the default user home
    #[arg(long)]
    global: bool,

    /// Skip identity loading and use anonymous mode
    #[arg(long, conflicts_with = "id")]
    anonymous: bool,

    /// Print records as they are resolved
    #[arg(short, long, default_value = "true")]
    streaming: bool,

    /// Bind patterns for local network interfaces
    #[arg(long = "interface", value_name = "bind", default_value = "*",
          hide = cfg!(not(debug_assertions)))]
    binds: Vec<BindPattern>,
}

impl Options {
    fn home_scope(&self) -> home::HomeScope {
        if self.global {
            home::HomeScope::Global
        } else {
            home::HomeScope::User
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(display("failed to load dhttp home"))]
    LoadDhttpHome { source: home::LoadDhttpHomeError },
    #[snafu(display("failed to load explicit identity `{name}`"))]
    LoadExplicitIdentity {
        name: Name<'static>,
        source: dhttp::home::identity::ssl::ResolveIdentityProfileError,
    },
    #[snafu(display("failed to load identity certificate and key"))]
    LoadIdentitySsl {
        source: dhttp::home::identity::ssl::LoadIdentityError,
    },
    #[snafu(display("failed to build dhttp endpoint"))]
    BuildEndpoint {
        source: dhttp::endpoint::BuildEndpointError,
    },
    #[snafu(display("failed to lookup dns records of `{name}`"))]
    LookUp {
        name: Name<'static>,
        source: std::io::Error,
    },
}

/// Initialize tracing subscriber with stderr output.
fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (stderr, guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
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

async fn load_identity_profile(options: &Options) -> Result<Option<IdentityProfile>, Error> {
    if options.anonymous {
        return Ok(None);
    }

    let home = match DhttpHome::load(options.home_scope()) {
        Ok(home) => home,
        Err(source) if options.id.is_none() => {
            tracing::warn!(
                error = %snafu::Report::from_error(&source),
                "failed to load dhttp home, using anonymous endpoint"
            );
            return Ok(None);
        }
        Err(source) => return Err(error::LoadDhttpHomeSnafu.into_error(source)),
    };

    if let Some(name) = &options.id {
        tracing::debug!(%name, "trying to load command line identity");
        return home
            .resolve_identity_profile(name.clone())
            .await
            .context(error::LoadExplicitIdentitySnafu { name: name.clone() })
            .map(Some);
    }

    match home.resolve_default_identity_profile().await {
        Ok(identity) => {
            tracing::debug!(name = %identity.name(), "using default identity");
            Ok(Some(identity))
        }
        Err(source) => {
            tracing::debug!(
                error = %snafu::Report::from_error(&source),
                "failed to load default identity, using anonymous endpoint"
            );
            Ok(None)
        }
    }
}

pub async fn run(options: Options) -> Result<(), Error> {
    let _guard = init_tracing();
    let identity_profile = load_identity_profile(&options).await?;
    let identity = match &identity_profile {
        Some(profile) => Some(Arc::new(
            profile
                .load_identity()
                .await
                .context(error::LoadIdentitySslSnafu)?,
        )),
        None => None,
    };

    let mut builder = Endpoint::builder()
        .bind(Arc::new(options.binds.clone()))
        .maybe_identity(identity);
    for scheme in options.schemes.iter().copied() {
        builder = builder.dns(scheme);
    }
    let endpoint = builder.build().await.context(error::BuildEndpointSnafu)?;
    let resolver = endpoint.resolver();

    let mut lookup = resolver
        .lookup(options.name.as_full())
        .await
        .context(error::LookUpSnafu {
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn options_accept_global_flag() {
        let options =
            Options::try_parse_from(["nslookup", "--global", "alice.smith", "mdns"]).unwrap();

        assert_eq!(options.home_scope(), dhttp::home::HomeScope::Global);
    }
}
