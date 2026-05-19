//! One-call H3 endpoint setup consolidating duplicated initialization flow.

use std::sync::{Arc, LazyLock};

use h3x::{
    connection::ConnectionBuilder,
    dquic::{
        QuicEndpoint,
        binds::BindPattern,
        cert::handy::ToCertificate,
        client::{ClientQuicConfig, ServerCertVerifierChoice},
        connection::Connection,
        server::ServerQuicConfig,
    },
    endpoint::H3Endpoint,
};
use rustls::{RootCertStore, client::WebPkiServerVerifier};
use snafu::{ResultExt, Snafu};

use crate::dns;

pub type H3Client = Arc<H3Endpoint<QuicEndpoint, Connection>>;

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
    ClientQuicConfig {
        verifier: ServerCertVerifierChoice::WebPki(VERIFIER.clone()),
        alpns: vec![b"h3".to_vec()],
        ..Default::default()
    }
}

/// Result of [`setup_h3_client`].
pub struct H3ClientSetup {
    /// The constructed H3 endpoint, ready to connect.
    pub client: H3Client,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SetupH3ClientError {
    #[snafu(display("failed to load identity ssl material"))]
    LoadIdentitySsl {
        source: dhttp_home::identity::ssl::LoadIdentitySslError,
    },
}

/// Default STUN server address.
const DEFAULT_STUN_SERVER: &str = "stun.genmeta.net:20004";

fn ensure_default_mdns_on_binds(binds: &mut [BindPattern]) {
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

/// Consolidated H3 client initialization: ssl → DNS → endpoint.
#[bon::builder]
pub async fn setup_h3_client(
    binds: &[BindPattern],
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

    let effective_stun = stun_server.unwrap_or_else(|| DEFAULT_STUN_SERVER.into());
    let network = {
        let builder = h3x::dquic::Network::builder();
        if effective_stun.is_empty() {
            builder.build()
        } else {
            builder
                .stun_server(Arc::<str>::from(effective_stun))
                .build()
        }
    };

    let mut bind_patterns = binds.to_vec();
    ensure_default_mdns_on_binds(&mut bind_patterns);
    let bind_patterns = Arc::new(bind_patterns);

    let dns_setup = dns::handy::build_resolvers(
        dns_schemes.iter().copied(),
        &[],
        id_material.as_ref(),
        Some(network.clone()),
    )
    .await;

    let quic = QuicEndpoint::builder()
        .network(network)
        .maybe_identity(id_material.map(Arc::new))
        .resolver(Arc::new(dns_setup.resolvers))
        .client(default_client_quic_config())
        .server(ServerQuicConfig::default())
        .bind(bind_patterns)
        .build()
        .await;

    let endpoint = match connection_builder {
        Some(builder) => H3Endpoint::builder().quic(quic).builder(builder).build(),
        None => H3Endpoint::new(quic),
    };
    Ok(H3ClientSetup {
        client: Arc::new(endpoint),
    })
}
