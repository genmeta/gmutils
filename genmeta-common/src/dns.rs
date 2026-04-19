use std::fmt;

use clap::ValueEnum;

pub const HTTP_DNS_SERVER: &str = "https://dns.genmeta.net/";
pub const H3_DNS_SERVER: &str = "https://dns.genmeta.net:4433";
pub const MDNS_SERVICE: &str = "_genmeta.local";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum DnsScheme {
    Mdns,
    Http,
    H3,
    Dht,
}

impl DnsScheme {
    pub const fn as_str(&self) -> &'static str {
        match self {
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
    #[cfg(feature = "h3-client")]
    use std::sync::Arc;

    #[cfg(feature = "h3-client")]
    use dhttp_home::identity::ssl::Identity;
    #[cfg(feature = "h3-client")]
    use gmdns::resolvers::H3Resolver;
    use gmdns::resolvers::{HttpResolver, MdnsResolver, MdnsResolvers};
    use h3x::dquic::qinterface::BindInterface;
    #[cfg(feature = "h3-client")]
    use h3x::{
        client::Client,
        dquic::prelude::Resolve,
        endpoint::{Identity as EndpointIdentity, Network, QuicEndpoint, ServerQuicConfig},
    };

    #[cfg(feature = "h3-client")]
    use super::H3_DNS_SERVER;
    use super::{HTTP_DNS_SERVER, MDNS_SERVICE};
    #[cfg(feature = "h3-client")]
    use crate::h3_client::{default_client_quic_config, endpoint_identity};

    pub fn mdns_resolvers(bind_ifaces: impl IntoIterator<Item = BindInterface>) -> MdnsResolvers {
        tracing::debug!("initializing mDNS resolvers");
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
                tracing::debug!(bind_uri = %mdns_iface.bind_uri(), "initializing mDNS resolver for nic");
                resolvers.insert_iface(mdns_iface);
            }
        }
        resolvers
    }

    /// Ensure all bind URIs default to `mdns=true` when none explicitly
    /// specifies the `mdns` prop. Designed to be passed directly to
    /// [`setup_bind_interfaces_with`](h3x::endpoint::binds::setup_bind_interfaces_with).
    pub fn ensure_default_mdns_prop(
        bind_uris: &mut Vec<h3x::dquic::qinterface::bind_uri::BindUri>,
    ) {
        if !bind_uris.iter().any(|uri| uri.prop("mdns").is_some()) {
            for uri in bind_uris {
                uri.add_prop("mdns", "true");
            }
        }
    }

    pub fn http_resolver() -> HttpResolver {
        tracing::debug!("initializing HTTP DNS resolver with server {HTTP_DNS_SERVER}");
        HttpResolver::new(HTTP_DNS_SERVER).expect("BUG: HTTP_DNS_SERVER is a valid URL")
    }

    #[cfg(feature = "h3-client")]
    pub fn h3_resolver(
        resolver: Arc<dyn Resolve>,
        id_material: Option<&Identity>,
    ) -> H3Resolver<QuicEndpoint> {
        tracing::debug!("initializing DHTTP/3 DNS resolver with server {H3_DNS_SERVER}");
        let identity = match id_material {
            Some(id) => {
                tracing::debug!(
                    "using preloaded client identity {} for DHTTP/3 DNS resolver",
                    id.name()
                );
                endpoint_identity(id)
            }
            None => {
                tracing::warn!("no client identity provided, DHTTP/3 DNS resolver may not work");
                EndpointIdentity::Anonymous
            }
        };
        // The DNS resolver lives on its own `Network` with all-default
        // infrastructure (global InterfaceManager, no STUN). Outbound
        // connections create ephemeral interfaces on demand.
        let network = Network::builder().build();
        let endpoint = QuicEndpoint::new(
            network,
            identity,
            resolver,
            default_client_quic_config(),
            ServerQuicConfig::default(),
        );
        let client = Client::from_quic_client().client(endpoint).build();
        H3Resolver::new(H3_DNS_SERVER, client).expect("BUG: H3_DNS_SERVER is a valid URL")
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
    #[cfg(feature = "h3-client")]
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
    /// scheme is present. `id` is the optional client identity for the DHTTP/3
    /// DNS resolver.
    #[cfg(feature = "h3-client")]
    pub fn build_resolvers(
        dns_schemes: impl IntoIterator<Item = super::DnsScheme>,
        bind_interfaces: &[h3x::dquic::qinterface::BindInterface],
        id_material: Option<&Identity>,
    ) -> ResolversSetup {
        use super::DnsScheme;

        let mut resolvers = gmdns::resolvers::Resolvers::new();
        let mut mdns = None;

        for dns_scheme in dns_schemes {
            match dns_scheme {
                DnsScheme::Mdns => {
                    let arc = mdns.get_or_insert_with(|| Arc::new(MdnsResolvers::new()));
                    arc.merge(&self::mdns_resolvers(bind_interfaces.iter().cloned()));
                    resolvers = resolvers.with(arc.clone());
                }
                DnsScheme::Http => {
                    resolvers = resolvers.with(Arc::new(http_resolver()));
                }
                DnsScheme::H3 => {
                    let snapshot = Arc::new(
                        resolvers
                            .clone()
                            .with(Arc::new(h3x::dquic::prelude::handy::SystemResolver)),
                    );
                    let resolver = h3_resolver(snapshot, id_material);
                    resolvers = resolvers.with(Arc::new(resolver));
                }
                DnsScheme::Dht => {
                    dht_resolver();
                }
            }
        }

        // Always append SystemResolver as the final fallback so that IP literal
        // addresses (e.g. STUN server "10.10.0.2:20002") can be resolved
        // without going through DNS.
        resolvers = resolvers.with(Arc::new(h3x::dquic::prelude::handy::SystemResolver));

        ResolversSetup {
            resolvers,
            mdns_resolvers: mdns,
        }
    }

    /// Resolve a domain name to socket addresses using the standard H3 + System
    /// DNS resolver chain. Suitable for lightweight tools that don't need mDNS
    /// or client identity.
    #[cfg(feature = "h3-client")]
    pub async fn resolve_domain(name: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use futures::StreamExt;
        use h3x::dquic::qresolve::{EndpointAddr, Resolve};

        let setup = build_resolvers([super::DnsScheme::H3], &[], None);
        let stream = Resolve::lookup(&setup.resolvers, name).await?;
        Ok(stream
            .filter_map(|(_source, ep)| async move {
                match ep {
                    EndpointAddr::Socket(socket_ep) => Some(socket_ep.addr()),
                    _ => None,
                }
            })
            .collect()
            .await)
    }
}
