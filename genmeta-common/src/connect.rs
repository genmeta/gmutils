use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::Duration,
};

pub use ::{
    gm_quic::{self, *},
    h3, h3_shim, qdns,
};
use bytes::Bytes;
use dashmap::DashMap;
use futures::StreamExt;
use gm_quic::{
    builder::{ClientParameters, Log},
    prelude::{BindUri, Connection, ParameterId, QuicClient, handy::ToCertificate},
    qinterface::iface::{
        QuicInterfaces,
        physical::{InterfaceEvent, PhysicalInterfaces},
    },
    qtraversal::iface::TraversalFactory,
};
use h3::client::SendRequest;
use qdns::Resolvers;
use snafu::ResultExt;
use tokio::{sync::Mutex, time};
use tokio_util::task::AbortOnDropHandle;

use crate::{error::Whatever, identity::config::Profile};
pub static AGENTS: LazyLock<Vec<SocketAddr>> = LazyLock::new(|| {
    vec![
        "1.12.74.4:20004".parse().unwrap(),
        "[2402:4e00:c011:1700:8624:7e0:5c9a:2]:20004"
            .parse()
            .unwrap(),
    ]
});

fn traversal_factory() -> &'static Arc<TraversalFactory> {
    TraversalFactory::initialize_global(AGENTS.as_slice()).unwrap()
}

pub static ROOT_CERT: &[u8] = include_bytes!("../../root.crt");

#[derive(Clone)]
pub struct ReusableConnection {
    #[allow(unused)]
    pub quic: Arc<Connection>,
    pub h3: SendRequest<h3_shim::OpenStreams, Bytes>,
}

/// H3 Connection reuse pool
pub struct H3ConnectionPool {
    quic_client: Arc<QuicClient>,
    h3_clients: Arc<DashMap<String, Arc<Mutex<Option<ReusableConnection>>>>>,
    _maintain_binding: AbortOnDropHandle<()>,
    verbose: bool,
}

impl H3ConnectionPool {
    /// Creates a new reuse pool, using the given client to create the underlying quic connection.
    ///
    /// If this client is used by multiple [`H3ConnectionPool`] and the client enables [`reuse_connection`], it may cause some problems.
    ///
    /// [`reuse_connection`]: gm_quic::QuicClientBuilder::reuse_connection
    pub fn new(
        profile: Option<&Profile>,
        mut parameters: ClientParameters,
        qlogger: Arc<dyn Log + Send + Sync>,
    ) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ROOT_CERT.to_certificate());
        let mut monitor = PhysicalInterfaces::global().monitor();

        fn resolve_bind_uris(
            devices: impl IntoIterator<Item = impl AsRef<str>>,
        ) -> impl Iterator<Item = BindUri> {
            devices.into_iter().flat_map(|device| {
                [
                    BindUri::from(format!("iface://v4.{}:0", device.as_ref())).alloc_port(),
                    BindUri::from(format!("iface://v6.{}:0", device.as_ref())).alloc_port(),
                ]
            })
        }

        let client = Arc::new(
            match profile {
                Some(Profile { id, key, cert }) => {
                    parameters
                        .set(ParameterId::ClientName, id.to_owned())
                        .unwrap();
                    QuicClient::builder()
                        .with_root_certificates(roots)
                        .with_cert(cert.as_slice(), key.as_slice())
                }
                None => QuicClient::builder()
                    .with_root_certificates(roots)
                    .without_cert(),
            }
            .with_parameters(parameters)
            .with_iface_factory(traversal_factory().as_ref().clone())
            .with_qlog(qlogger)
            .bind(resolve_bind_uris(monitor.interfaces().keys()))
            .enable_sslkeylog()
            .build(),
        );

        let quic_client = client.clone();
        let maintain_binding = AbortOnDropHandle::new(tokio::spawn(async move {
            while let Some((_currnet_interfaces, event)) = monitor.update().await {
                tracing::debug!(target: "listen", ?event, "Interface event received");
                match event.as_ref() {
                    InterfaceEvent::Added { device, .. } => {
                        for bind_uri in resolve_bind_uris([&device]) {
                            tracing::debug!(target: "listen", ?bind_uri, "Add interface to client binding");
                            let bind_interface = QuicInterfaces::global()
                                .bind(bind_uri, traversal_factory().clone());
                            quic_client.add_interface(bind_interface);
                        }
                    }
                    InterfaceEvent::Removed { device, .. } => {
                        for bind_uri in resolve_bind_uris([&device]) {
                            tracing::debug!(target: "listen", ?bind_uri, "Remove interface from client binding");
                            quic_client.remove_interface(&bind_uri);
                        }
                    }
                    InterfaceEvent::Changed { .. } => { /* Ignore changes */ }
                }
            }
        }));
        Self {
            quic_client: client,
            h3_clients: Arc::new(DashMap::new()),
            _maintain_binding: maintain_binding,
            verbose: false,
        }
    }

    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// Get a connection to the specified server.
    ///
    /// If there is no current connection to the server, the given endpoint addr will be used to create a connection.
    ///
    /// If there is already a connection to the given server, just return the existing connection.
    pub async fn connect(
        &self,
        server_name: &str,
        resolvers: &Resolvers,
        timeout: Duration,
    ) -> Result<ReusableConnection, Whatever> {
        let mut entry = None;

        // Get a shared access so that multiple asynchronous tasks can asynchronously wait for other tasks
        // to create connections
        let entry = loop {
            match entry {
                Some(entry) => break entry,
                None => {
                    self.h3_clients.entry(server_name.to_string()).or_default();
                    entry = self.h3_clients.get(server_name).map(|e| e.clone());
                }
            }
        };

        let mut entry = entry.lock().await;

        if let Some(conn) = entry.as_ref() {
            // todo: fresh quic conenc
            tracing::debug!(target: "pool", "Reusing connection to {server_name}");
            return Ok(conn.clone());
        }

        let connect_or_reuse = async {
            let mut lookup = resolvers
                .lookup(server_name)
                .await
                .whatever_context("dns lookup failed")?;

            let (resolver, server_eps) = lookup.next().await.unwrap();
            if self.verbose {
                eprintln!(
                    "* resolved {server_name} to endpoint addresses: [{}] (resolver {resolver})",
                    server_eps
                        .iter()
                        .map(|ep| ep.to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
                )
            }

            let quic_connection = self.quic_client.connect(server_name, server_eps).unwrap();

            tokio::spawn({
                let conn = quic_connection.clone();
                async move {
                    while let Some((_, endpoints)) = lookup.next().await {
                        for endpoint in endpoints {
                            _ = conn.add_peer_endpoint(endpoint.into());
                        }
                    }
                }
            });
            let (mut h3_connection, send_request) = time::timeout(
                timeout,
                h3::client::new(h3_shim::QuicConnection::new(quic_connection.clone())),
            )
            .await
            .whatever_context("connect timed out")?
            .whatever_context("failed to establish h3 connection")?;

            if self.verbose {
                eprintln!("* establish http3 connection to {server_name}");
            }

            let conn = ReusableConnection {
                quic: quic_connection.clone(),
                h3: send_request.clone(),
            };

            *entry = Some(conn.clone());

            tokio::spawn({
                let h3_clients = self.h3_clients.clone();
                let server_name = server_name.to_owned();
                async move {
                    _ = h3_connection.wait_idle().await;
                    h3_clients.remove(&server_name);
                }
            });

            tracing::debug!(target: "pool", "Created connection to {server_name}");

            Ok(conn)
        };

        match connect_or_reuse.await {
            Ok(send_request) => Ok(send_request),
            Err(error) => {
                // clean up failed connections
                let server_name = server_name.to_owned();
                tokio::task::spawn_blocking({
                    let h3_clients = self.h3_clients.clone();
                    move || h3_clients.remove_if(&server_name, |_, v| v.blocking_lock().is_none())
                });
                Err(error)
            }
        }
    }

    pub fn clear_connections(&self) {
        self.h3_clients.clear();
    }
}
