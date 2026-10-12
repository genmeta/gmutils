use std::{
    collections::{HashMap, HashSet},
    io::IsTerminal,
    string::String as BindPattern,
};

use clap::Parser;
use ddns::DnsScheme;
use dhttp_home as home;
use dhttp_home::{DhttpHome, identity::IdentityProfile};
use dhttp_identity::name::DhttpName as Name;
use futures::StreamExt;
use snafu::{IntoError, ResultExt, Snafu};
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(name = "nslookup", version, about)]
pub struct Options {
    /// Name to query (only a trailing ~ expands to .dhttp.net)
    #[arg(index = 1, value_parser = parse_query_name)]
    name: String,

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

fn parse_query_name(input: &str) -> Result<String, String> {
    dhttp_home::normalize_dns_name(input).ok_or_else(|| format!("invalid DNS name: {input}"))
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
        source: dhttp_home::identity::ssl::ResolveIdentityProfileError,
    },
    #[snafu(display("failed to load identity certificate and key"))]
    LoadIdentitySsl {
        source: dhttp_home::identity::ssl::LoadIdentityError,
    },
    #[snafu(display("failed to build dhttp endpoint"))]
    BuildEndpoint { source: dhttp::Error },
    #[snafu(display("failed to lookup dns records of `{name}`"))]
    LookUp {
        name: String,
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
            .resolve_identity_profile((name.clone()).as_full())
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
    // Validate a selected identity even though DNS lookup itself doesn't require credentials.
    if let Some(profile) = &identity_profile {
        dhttp::Endpoint::load_from_with_ocsp(profile.path())
            .await
            .context(error::BuildEndpointSnafu)?;
    }
    init_network(&options.schemes, &options.binds)
        .await
        .context(error::BuildEndpointSnafu)?;
    let resolver = dhttp::resolve::Resolver::get();

    let mut lookup =
        resolver
            .lookup(&options.name, "443", None)
            .await
            .context(error::LookUpSnafu {
                name: options.name.to_owned(),
            })?;

    if options.streaming {
        println!("Name: {}:", options.name);
        let mut last_source = None;
        while let Some((source, endpoint_addr)) = lookup.next().await {
            if !last_source.as_ref().is_some_and(|last| last == &source) {
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

async fn init_network(schemes: &[ddns::DnsScheme], binds: &[String]) -> dhttp::Result<()> {
    if binds.iter().any(|bind| bind != "*") {
        return Err(dhttp::Error::InvalidRequest {
            message: "the process-wide DHTTP network currently requires --interface '*'".into(),
        });
    }
    let mdns = ddns::install_resolvers(schemes)?;
    let network = dhttp::DhttpNetwork::init().await?;
    if let Some(mdns) = mdns {
        static MAINTENANCE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
        MAINTENANCE
            .get_or_try_init(|| async {
                mdns.maintain(std::time::Duration::from_secs(1), move || {
                    Ok(network
                        .active_bindings()
                        .map_err(std::io::Error::other)?
                        .into_iter()
                        .filter(|binding| {
                            dhttp::resolve::EndpointAddr::direct(binding.address).scope()
                                == Some(dhttp::Scope::Internal)
                        })
                        .map(|binding| {
                            ddns::mdns::MdnsBinding::new(binding.device, binding.address.ip())
                        })
                        .collect())
                })
                .await?;
                Ok::<(), std::io::Error>(())
            })
            .await?;
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

        assert_eq!(options.home_scope(), dhttp_home::HomeScope::Global);
    }

    #[test]
    fn query_names_use_home_normalization_without_implicit_suffix() {
        for (input, expected) in [
            ("nat.example.cn", "nat.example.cn"),
            (" Alice.Smith~ ", "alice.smith.dhttp.net"),
            ("Alice.Smith.DHTTP.NET.", "alice.smith.dhttp.net"),
            ("alice.smith", "alice.smith"),
            ("localhost", "localhost"),
        ] {
            let options = Options::try_parse_from(["nslookup", input, "system"]).unwrap();
            assert_eq!(options.name, expected);
        }
        assert!(Options::try_parse_from(["nslookup", "alice~.example.cn"]).is_err());
    }
}
