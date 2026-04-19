//! One-call H3 client setup consolidating the duplicated initialization flow
//! across consumer crates.

use std::sync::{Arc, LazyLock};

use h3x::{
    client::Client,
    connection::ConnectionBuilder,
    dquic::{
        prelude::{Connection, handy::ToCertificate},
        qinterface::bind_uri::BindUri,
    },
    endpoint::{
        ClientOnlyConfig, ClientQuicConfig, Identity, NamedIdentity, Network, QuicEndpoint,
        ServerCertVerifierChoice, ServerQuicConfig,
        binds::{self, BindConflictError, Binds},
    },
};
use rustls::{RootCertStore, client::WebPkiServerVerifier};
use snafu::{ResultExt, Snafu};
use tokio_util::task::AbortOnDropHandle;

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
    /// Background task watching for network interface changes. Drop to stop.
    pub watcher: AbortOnDropHandle<()>,
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

/// Consolidated H3 client initialization: bind → ssl → dns → stun → endpoint → watch.
#[bon::builder]
pub async fn setup_h3_client(
    binds: &Binds,
    dns_schemes: &[dns::DnsScheme],
    identity: Option<&dhttp_home::identity::IdentityHome>,
    /// Optional filter applied to expanded bind URIs before initial binding.
    /// Useful for restricting the client-initiated set to IPv4-only or
    /// IPv6-only addresses.
    bind_uri_filter: Option<fn(&BindUri) -> bool>,
    /// Optional custom connection builder for registering additional protocol
    /// factories (e.g. `Ssh3ProtocolFactory`).
    connection_builder: Option<Arc<ConnectionBuilder<Connection>>>,
    /// Optional STUN server override. When `Some`, uses the given server;
    /// when `None`, falls back to [`DEFAULT_STUN_SERVER`].
    /// Set to `Some("")` to explicitly disable STUN.
    stun_server: Option<String>,
) -> Result<H3ClientSetup, SetupH3ClientError> {
    let bind_setup =
        binds::setup_bind_interfaces_with(binds, dns::handy::ensure_default_mdns_prop).await?;
    let monitor = bind_setup.monitor;

    let id_material = match identity {
        Some(id) => Some(
            id.identity()
                .await
                .context(setup_h3_client_error::LoadIdentitySslSnafu)?,
        ),
        None => None,
    };

    let dns_setup = dns::handy::build_resolvers(
        dns_schemes.iter().copied(),
        &bind_setup.bind_interfaces,
        id_material.as_ref(),
    );

    // `bind_uris` controls the initial client-initiated set (honouring
    // `bind_uri_filter`); the shared iface_manager still contains every
    // interface expanded by `bind_setup`, so mdns/dns keep seeing the full
    // set.
    let bind_uris: Vec<BindUri> = match bind_uri_filter {
        Some(f) => bind_setup
            .bind_uris
            .iter()
            .filter(|uri| f(uri))
            .cloned()
            .collect(),
        None => bind_setup.bind_uris.clone(),
    };

    // Share `bind_setup.iface_manager` with the `Network` so the endpoint
    // connects out through the same bound interfaces.
    let effective_stun = stun_server.unwrap_or_else(|| DEFAULT_STUN_SERVER.into());
    let network = {
        let builder = Network::builder().iface_manager(bind_setup.iface_manager.clone());
        if effective_stun.is_empty() {
            builder.build()
        } else {
            builder
                .stun_server(Arc::<str>::from(effective_stun))
                .build()
        }
    };

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

    let iface_manager = bind_setup.iface_manager.clone();
    let io_factory = client.quic_client().network.io_factory().clone();
    let watcher = binds::watch_bind_interfaces(
        binds,
        monitor,
        bind_uris,
        {
            let iface_manager = iface_manager.clone();
            let io_factory = io_factory.clone();
            move |uri| {
                let iface_manager = iface_manager.clone();
                let io_factory = io_factory.clone();
                Box::pin(async move {
                    let _ = iface_manager.bind(uri, io_factory).await;
                })
            }
        },
        {
            let iface_manager = iface_manager.clone();
            move |uri| {
                let iface_manager = iface_manager.clone();
                tokio::spawn(async move {
                    iface_manager.unbind(uri).await;
                });
            }
        },
    );

    Ok(H3ClientSetup { client, watcher })
}
