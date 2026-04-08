//! One-call H3 client setup consolidating the duplicated initialization flow
//! across consumer crates.

use std::sync::{Arc, LazyLock};

use h3x::{
    connection::ConnectionBuilder,
    dquic::{
        BuildClientError, H3Client,
        prelude::{
            Connection,
            handy::{NoopLogger, ToCertificate},
        },
        qinterface::bind_uri::BindUri,
    },
};
use rustls::RootCertStore;
use snafu::{ResultExt, Snafu};
use tokio_util::task::AbortOnDropHandle;

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

use crate::{bind, dns};

/// Result of [`setup_h3_client`].
pub struct H3ClientSetup {
    /// The constructed H3 client, ready to connect.
    pub client: H3Client,
    /// Background task watching for network interface changes. Drop to stop.
    pub watcher: AbortOnDropHandle<()>,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SetupH3ClientError {
    #[snafu(transparent)]
    BindConflict {
        source: Box<bind::BindConflictError>,
    },

    #[snafu(display("failed to load identity SSL material"))]
    LoadIdentitySsl {
        source: dhttp_home::identity::ssl::LoadIdentitySslError,
    },

    #[snafu(display("failed to build DNS resolvers"))]
    BuildDnsResolvers { source: BuildClientError },

    #[snafu(display("failed to build HTTP/3 client"))]
    BuildClient { source: BuildClientError },
}

/// Default STUN server address.
const DEFAULT_STUN_SERVER: &str = "stun.genmeta.net:20002";

/// Consolidated H3 client initialization: bind → ssl → dns → stun → client → watch.
#[bon::builder]
pub async fn setup_h3_client(
    binds: &bind::Binds,
    dns_schemes: &[dns::DnsScheme],
    identity: Option<&dhttp_home::identity::IdentityHome>,
    /// Optional filter applied to expanded bind URIs before binding the QUIC
    /// client. Useful for restricting to IPv4-only or IPv6-only addresses.
    bind_uri_filter: Option<fn(&BindUri) -> bool>,
    /// Optional custom connection builder for registering additional protocol
    /// factories (e.g. `Ssh3ProtocolFactory`). When provided, replaces the
    /// default connection builder used by the QUIC client.
    connection_builder: Option<Arc<ConnectionBuilder<Connection>>>,
    /// Optional STUN server override. When `Some`, uses the given server;
    /// when `None`, falls back to [`DEFAULT_STUN_SERVER`].
    /// Set to `Some("")` to explicitly disable STUN.
    stun_server: Option<String>,
) -> Result<H3ClientSetup, SetupH3ClientError> {
    let bind_setup =
        bind::setup_bind_interfaces_with(binds, dns::handy::ensure_default_mdns_prop).await?;
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
    )
    .context(setup_h3_client_error::BuildDnsResolversSnafu)?;

    let bind_uris: Vec<BindUri> = match bind_uri_filter {
        Some(f) => bind_setup
            .bind_uris
            .iter()
            .filter(|uri| f(uri))
            .cloned()
            .collect(),
        None => bind_setup.bind_uris.clone(),
    };

    let client = match &id_material {
        Some(id_material) => H3Client::builder()
            .with_root_certificates(genmeta_root_cert_store().clone())
            .with_identity(
                id_material.name().as_full(),
                id_material.certs(),
                id_material.key(),
            ),
        None => H3Client::builder()
            .with_root_certificates(genmeta_root_cert_store().clone())
            .without_identity(),
    }
    .context(setup_h3_client_error::BuildClientSnafu)?
    .with_iface_manager(bind_setup.iface_manager)
    .with_resolver(Arc::new(dns_setup.resolvers));

    // Enable STUN for NAT traversal. Resolution order:
    // 1. Explicit `stun_server` parameter
    // 2. Default: stun.genmeta.net:20002
    // An empty string explicitly disables STUN.
    let effective_stun = stun_server.unwrap_or_else(|| DEFAULT_STUN_SERVER.into());
    let client = if effective_stun.is_empty() {
        client
    } else {
        client.with_stun(effective_stun)
    };

    let client = client.bind(&bind_uris).await;

    let client = match connection_builder {
        Some(builder) => client.with_builder(builder),
        None => client,
    }
    .with_qlog(Arc::new(NoopLogger))
    .build();

    let quic = client.quic_client().clone();
    let watcher = bind::watch_bind_interfaces(
        binds,
        monitor,
        bind_uris,
        {
            let quic = quic.clone();
            move |uri| {
                let quic = quic.clone();
                Box::pin(async move {
                    quic.bind(uri).await;
                })
            }
        },
        {
            let quic = quic.clone();
            move |uri| {
                quic.unbind(&uri);
            }
        },
    );

    Ok(H3ClientSetup { client, watcher })
}
