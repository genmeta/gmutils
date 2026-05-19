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
    use gmdns::resolvers::{HttpResolver, MdnsResolvers};
    use h3x::dquic::{Network, QuicEndpoint, qinterface::BindInterface, resolver::Resolve};
    #[cfg(feature = "h3-client")]
    use h3x::{dquic::server::ServerQuicConfig, endpoint::H3Endpoint};

    #[cfg(feature = "h3-client")]
    use super::H3_DNS_SERVER;
    use super::HTTP_DNS_SERVER;
    #[cfg(feature = "h3-client")]
    use crate::h3_client::default_client_quic_config;

    pub fn mdns_resolvers(_bind_ifaces: impl IntoIterator<Item = BindInterface>) -> MdnsResolvers {
        panic!("genmeta-common mDNS helpers are deprecated; use dhttp::ddns::MdnsResolvers::bind")
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
    pub async fn h3_resolver(
        resolver: Arc<dyn Resolve + Send + Sync>,
        id_material: Option<&Identity>,
        network: Option<Arc<Network>>,
    ) -> H3Resolver<QuicEndpoint> {
        tracing::debug!("initializing DHTTP/3 DNS resolver with server {H3_DNS_SERVER}");
        if let Some(id) = id_material {
            tracing::debug!(
                "using preloaded client identity {} for DHTTP/3 DNS resolver",
                id.name()
            );
        } else {
            tracing::warn!("no client identity provided, DHTTP/3 DNS resolver may not work");
        }
        // Prefer reusing the caller-supplied `Network` so the DNS endpoint
        // and the main client share the same `QuicRouter` (and therefore
        // the same connectionless-packet dispatcher). Otherwise every
        // additional `Network` on the global router loses the dispatcher
        // race, making its server endpoints unreachable for NAT-punch
        // Initial packets. When no network is provided (e.g. standalone
        // tools like `genmeta-nslookup` / `genmeta-nat` that don't spin
        // up a curl client), fall back to a default network.
        let network = network.unwrap_or_else(|| Network::builder().build());
        let endpoint = QuicEndpoint::builder()
            .network(network)
            .maybe_identity(id_material.cloned().map(Arc::new))
            .resolver(resolver)
            .client(default_client_quic_config())
            .server(ServerQuicConfig::default())
            .build()
            .await;
        let h3 = H3Endpoint::new(endpoint);
        H3Resolver::new(H3_DNS_SERVER, h3).expect("BUG: H3_DNS_SERVER is a valid URL")
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
    pub async fn build_resolvers(
        dns_schemes: impl IntoIterator<Item = super::DnsScheme>,
        bind_interfaces: &[h3x::dquic::qinterface::BindInterface],
        id_material: Option<&Identity>,
        network: Option<Arc<Network>>,
    ) -> ResolversSetup {
        use super::DnsScheme;

        let mut resolvers = gmdns::resolvers::Resolvers::new();
        let mdns = None;

        for dns_scheme in dns_schemes {
            match dns_scheme {
                DnsScheme::Mdns => {
                    let _ = bind_interfaces;
                    tracing::warn!(
                        "genmeta-common mDNS resolver builder is deprecated; use dhttp::ddns"
                    );
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
                    let resolver = h3_resolver(snapshot, id_material, network.clone()).await;
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
        use h3x::dquic::qresolve::Resolve;

        let setup = build_resolvers([super::DnsScheme::H3], &[], None, None).await;
        let stream = Resolve::lookup(&setup.resolvers, name).await?;
        Ok(stream
            .filter_map(|(_source, ep)| async move { Some(ep.addr()) })
            .collect()
            .await)
    }
}
