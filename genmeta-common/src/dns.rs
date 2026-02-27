use std::fmt;

use clap::ValueEnum;

pub const HTTP_DNS_SERVER: &str = "https://dns.genmeta.net/";
pub const H3_DNS_SERVER: &str = "https://localhost:4433";
pub const MDNS_SERVICE: &str = "_genmeta.local";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum DnsScheme {
    System,
    Mdns,
    Http,
    H3,
    Dht,
}

impl DnsScheme {
    pub const fn as_str(&self) -> &'static str {
        match self {
            DnsScheme::System => "system",
            DnsScheme::Mdns => "mdns",
            DnsScheme::Http => "http",
            DnsScheme::H3 => "h3",
            DnsScheme::Dht => "dht",
        }
    }
}

impl fmt::Display for DnsScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

pub mod handy {
    use std::sync::Arc;

    use genmeta_home::identity::Identity;
    use gmdns::resolvers::{H3Resolver, HttpResolver, MdnsResolver, MdnsResolvers};
    use h3x::gm_quic::{
        BuildClientError, H3Client, prelude::Resolve, qdns::SystemResolver,
        qinterface::BindInterface,
    };

    use super::{H3_DNS_SERVER, HTTP_DNS_SERVER, MDNS_SERVICE};

    pub fn system_resolver() -> SystemResolver {
        tracing::debug!("Initializing system DNS resolver");
        SystemResolver
    }

    pub fn mdns_resolvers(bind_ifaces: impl IntoIterator<Item = BindInterface>) -> MdnsResolvers {
        tracing::debug!("Initializing mDNS resolvers");
        let resolvers = MdnsResolvers::new();
        for mdns_iface in bind_ifaces
            .into_iter()
            .filter(|iface| iface.bind_uri().prop("mdns").is_some_and(|v| v == "true"))
        {
            if mdns_iface.with_components_mut(|components, iface| {
                components
                    .try_init_with(|| MdnsResolver::from_iface(MDNS_SERVICE, iface))
                    .map(|resolver| resolver.service_name() == MDNS_SERVICE)
                    .unwrap_or_default()
            }) {
                tracing::debug!(bind_uri = %mdns_iface.bind_uri(), "Initializing mDNS resolver for nic");
                resolvers.insert_iface(mdns_iface);
            }
        }
        resolvers
    }

    /// Ensure all bind URIs default to `mdns=true` when none explicitly
    /// specifies the `mdns` prop. Designed to be passed directly to
    /// [`setup_bind_interfaces_with`](crate::bind::setup_bind_interfaces_with).
    pub fn ensure_default_mdns_prop(
        bind_uris: &mut Vec<h3x::gm_quic::qinterface::bind_uri::BindUri>,
    ) {
        if !bind_uris.iter().any(|uri| uri.prop("mdns").is_some()) {
            for uri in bind_uris {
                uri.add_prop("mdns", "true");
            }
        }
    }

    pub fn http_resolver() -> HttpResolver {
        tracing::debug!("Initializing HTTP DNS resolver with server {HTTP_DNS_SERVER}");
        HttpResolver::new(HTTP_DNS_SERVER).expect("HTTP_DNS_SERVER is valid URL")
    }

    pub fn h3_resolver(
        resolver: Arc<dyn Resolve>,
        id: Option<&Identity<'static>>,
    ) -> Result<H3Resolver, BuildClientError> {
        tracing::debug!("Initializing H3 DNS resolver with server {H3_DNS_SERVER}");
        let h3_client = match id {
            Some(id) => {
                tracing::debug!("Using client identity {} for H3 DNS resolver", id.name());
                H3Client::builder().with_identity(id.name().as_full(), id.certs(), id.key())?
            }
            None => {
                tracing::warn!("No client identity provided, H3 DNS resolver may not work");
                H3Client::builder().without_identity()?
            }
        }
        .with_resolver(resolver)
        .build();

        Ok(H3Resolver::new(H3_DNS_SERVER, h3_client).expect("H3_DNS_SERVER is valid URL"))
    }

    /// Placeholder for DHT resolver initialization.
    ///
    /// Currently not implemented; call sites expect this function to exist
    /// but the project does not require DHT resolver for tests. Keep as a
    /// noop to allow builds/tests to proceed.
    pub fn dht_resolver() {
        tracing::warn!("DHT resolver not implemented; skipping initialization");
    }

    /// Result of [`build_resolvers`], carrying all DNS resolver state.
    pub struct ResolversSetup {
        /// Combined DNS resolvers.
        pub resolvers: gmdns::resolvers::Resolvers,
        /// mDNS resolvers, present only when the `Mdns` scheme was requested.
        /// Kept as `Arc` so callers can feed in newly-discovered interfaces later.
        pub mdns_resolvers: Option<Arc<MdnsResolvers>>,
    }

    /// Build [`Resolvers`](gmdns::resolvers::Resolvers) from a list of
    /// [`DnsScheme`](super::DnsScheme)s, consolidating the duplicated
    /// match-loop found in consumer crates.
    ///
    /// `bind_interfaces` is used to seed mDNS resolvers when the `Mdns`
    /// scheme is present. `id` is the optional client identity for the H3
    /// DNS resolver.
    pub fn build_resolvers(
        dns_schemes: impl IntoIterator<Item = super::DnsScheme>,
        bind_interfaces: &[h3x::gm_quic::qinterface::BindInterface],
        id: Option<&genmeta_home::identity::Identity<'static>>,
    ) -> Result<ResolversSetup, BuildClientError> {
        use super::DnsScheme;

        let mut resolvers = gmdns::resolvers::Resolvers::new();
        let mut mdns = None;

        for dns_scheme in dns_schemes {
            match dns_scheme {
                DnsScheme::System => {
                    resolvers = resolvers.with(Arc::new(system_resolver()));
                }
                DnsScheme::Mdns => {
                    let arc = mdns.get_or_insert_with(|| Arc::new(MdnsResolvers::new()));
                    arc.merge(&self::mdns_resolvers(bind_interfaces.iter().cloned()));
                    resolvers = resolvers.with(arc.clone());
                }
                DnsScheme::Http => {
                    resolvers = resolvers.with(Arc::new(http_resolver()));
                }
                DnsScheme::H3 => {
                    let snapshot = Arc::new(resolvers.clone());
                    let resolver = h3_resolver(snapshot, id)?;
                    resolvers = resolvers.with(Arc::new(resolver));
                }
                DnsScheme::Dht => {
                    dht_resolver();
                }
            }
        }

        Ok(ResolversSetup {
            resolvers,
            mdns_resolvers: mdns,
        })
    }
}
