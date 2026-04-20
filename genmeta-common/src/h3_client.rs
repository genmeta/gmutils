//! One-call H3 client setup consolidating the duplicated initialization flow
//! across consumer crates.

use std::sync::{Arc, LazyLock};

use h3x::{
    client::Client,
    connection::ConnectionBuilder,
    dquic::{
        prelude::{Connection, handy::ToCertificate},
        qinterface::BindInterface,
    },
    endpoint::{
        BindsGuard, ClientOnlyConfig, ClientQuicConfig, Identity, NamedIdentity, Network,
        QuicEndpoint, ServerCertVerifierChoice, ServerQuicConfig,
        binds::{BindConflictError, Binds},
    },
};
use rustls::{RootCertStore, client::WebPkiServerVerifier};
use snafu::{ResultExt, Snafu};

use crate::dns;

/// Lazily-initialized Genmeta root CA certificate store, embedded at compile
/// time from the project-level `root.crt`.
pub fn genmeta_root_cert_store() -> &'static Arc<RootCertStore> {
    static STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
        let mut store = RootCertStore::empty();
        store.add_parsable_certificates(
            include_bytes!(concat!(env!("OUT_DIR"), "/root.crt")).to_certificate(),
        );
        Arc::new(store)
    });
    &STORE
}

/// Client-QUIC configuration used by both the main client and the DNS
/// resolver client: TLS 1.3 + WebPKI verifier against the Genmeta root
/// CA + `h3` ALPN.
pub fn default_client_quic_config() -> ClientQuicConfig {
    static VERIFIER: LazyLock<Arc<WebPkiServerVerifier>> = LazyLock::new(|| {
        WebPkiServerVerifier::builder(genmeta_root_cert_store().clone())
            .build()
            .expect("BUG: webpki verifier built from fixed genmeta roots")
    });
    let own = ClientOnlyConfig {
        verifier: ServerCertVerifierChoice::WebPki(VERIFIER.clone()),
        alpns: vec![b"h3".to_vec()],
        ..Default::default()
    };
    ClientQuicConfig {
        own: Arc::new(own),
        ..Default::default()
    }
}

/// Convert a loaded identity into the endpoint form used by [`QuicEndpoint`].
pub fn endpoint_identity(id: &dhttp_home::identity::ssl::Identity) -> Identity {
    Identity::Named(Arc::new(NamedIdentity {
        name: Arc::<str>::from(id.name().as_full()),
        certs: id.certs().to_vec(),
        key: Arc::new(id.key().clone_key()),
    }))
}

/// Result of [`setup_h3_client`].
pub struct H3ClientSetup {
    /// The constructed H3 client, ready to connect.
    pub client: Client<QuicEndpoint>,
    /// RAII guard owning the bind set installed on the network. Drop to
    /// cancel the reconcile watcher and unbind every URI registered
    /// through [`Network::add_binds`].
    pub binds_guard: BindsGuard,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SetupH3ClientError {
    #[snafu(transparent)]
    BindConflict { source: Box<BindConflictError> },

    #[snafu(display("failed to load identity ssl material"))]
    LoadIdentitySsl {
        source: dhttp_home::identity::ssl::LoadIdentitySslError,
    },
}

/// Default STUN server address.
const DEFAULT_STUN_SERVER: &str = "nat.genmeta.net:20004";

/// Ensure each [`Bind`](h3x::endpoint::Bind) pattern carries an
/// `mdns=true` query parameter so the bound interfaces participate in mDNS
/// service discovery. Preserves any explicit caller configuration: if *any*
/// existing pattern already mentions `mdns=` in its path-and-query, leave
/// every pattern untouched (matches legacy `ensure_default_mdns_prop`
/// semantics).
fn ensure_default_mdns_on_binds(binds: &mut Binds) {
    use http::uri::PathAndQuery;

    let has_mdns = binds.iter().any(|b| {
        b.path_and_query_str()
            .is_some_and(|pq| pq.contains("mdns="))
    });
    if has_mdns {
        return;
    }
    for bind in binds.iter_mut() {
        let new_pq_str = match bind.path_and_query.as_ref() {
            None => "/?mdns=true".to_string(),
            Some(existing) => {
                let s = existing.as_str();
                if s.contains('?') {
                    format!("{s}&mdns=true")
                } else {
                    format!("{s}?mdns=true")
                }
            }
        };
        bind.path_and_query = Some(
            new_pq_str
                .parse::<PathAndQuery>()
                .expect("BUG: derived a valid path-and-query"),
        );
    }
}

/// Consolidated H3 client initialization: bind → ssl → dns → stun → endpoint → watch.
#[bon::builder]
pub async fn setup_h3_client(
    binds: &Binds,
    dns_schemes: &[dns::DnsScheme],
    identity: Option<&dhttp_home::identity::IdentityHome>,
    /// Optional custom connection builder for registering additional protocol
    /// factories (e.g. `Ssh3ProtocolFactory`).
    connection_builder: Option<Arc<ConnectionBuilder<Connection>>>,
    /// Optional STUN server override. When `Some`, uses the given server;
    /// when `None`, falls back to [`DEFAULT_STUN_SERVER`].
    /// Set to `Some("")` to explicitly disable STUN.
    stun_server: Option<String>,
) -> Result<H3ClientSetup, SetupH3ClientError> {
    let id_material = match identity {
        Some(id) => Some(
            id.identity()
                .await
                .context(setup_h3_client_error::LoadIdentitySslSnafu)?,
        ),
        None => None,
    };

    // Build the main [`Network`] first. Two reasons order matters:
    //
    // 1. `NetworkBuilder::build()` installs the connectionless-packet
    //    dispatcher on the globally-shared [`QuicRouter`]. This must
    //    happen before any other `Network` is constructed on the same
    //    router — otherwise NAT-punch Initial packets destined for the
    //    main endpoint's SNI registry would be routed nowhere (see
    //    `h3x::endpoint::network::install_dispatcher` for the warning).
    //
    // 2. The DHTTP/3 DNS resolver reuses the same [`Network`] (passed
    //    as `Some(network.clone())` below) so client and resolver share
    //    one router, one interface manager, and one STUN agent set.
    let effective_stun = stun_server.unwrap_or_else(|| DEFAULT_STUN_SERVER.into());
    let network = {
        let builder = Network::builder();
        if effective_stun.is_empty() {
            builder.build()
        } else {
            builder
                .stun_server(Arc::<str>::from(effective_stun))
                .build()
        }
    };

    // Bind every interface through the network — this goes through
    // `Network::bind` which installs the QUIC router, STUN, forwarder,
    // and receive-and-deliver components on each interface (unlike a raw
    // `InterfaceManager::bind` call). `Network::add_binds` also starts a
    // reconcile watcher that keeps the bind set in sync with network
    // interface changes, and returns a [`BindsGuard`] that unbinds
    // everything on drop.
    let mut binds_owned = binds.clone();
    ensure_default_mdns_on_binds(&mut binds_owned);
    let binds_guard = network.add_binds(&binds_owned).await?;

    // Gather the currently-bound interfaces for DNS mDNS resolver
    // construction. `build_resolvers` picks the mdns-enabled subset
    // internally via each interface's `mdns` property.
    let bind_interfaces: Vec<BindInterface> = network
        .current_bind_uris()
        .into_iter()
        .filter_map(|uri| network.get_iface(&uri))
        .collect();

    let dns_setup = dns::handy::build_resolvers(
        dns_schemes.iter().copied(),
        &bind_interfaces,
        id_material.as_ref(),
        Some(network.clone()),
    );

    let endpoint = QuicEndpoint::new(
        network,
        id_material
            .as_ref()
            .map(endpoint_identity)
            .unwrap_or(Identity::Anonymous),
        Arc::new(dns_setup.resolvers),
        default_client_quic_config(),
        ServerQuicConfig::default(),
    );

    let client = {
        let partial = Client::from_quic_client().client(endpoint);
        match connection_builder {
            Some(cb) => partial.builder(cb).build(),
            None => partial.build(),
        }
    };

    Ok(H3ClientSetup {
        client,
        binds_guard,
    })
}
