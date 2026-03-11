//! Shared bind setup logic for QUIC interface binding.
//!
//! Consolidates the duplicated bind-interfaces initialization flow found across
//! consumer crates (`genmeta-curl`, `genmeta-ssh3`, `genmeta-nslookup`).

use std::{collections::HashSet, future::Future, pin::Pin, sync::Arc};

use futures::{StreamExt, stream::FuturesUnordered};
use h3x::gm_quic::{
    prelude::handy::DEFAULT_IO_FACTORY,
    qinterface::{
        BindInterface,
        bind_uri::BindUri,
        device::{Devices, InterfacesMonitor},
        manager::InterfaceManager,
    },
};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use super::{BindConflictError, Binds};

/// Result of [`setup_bind_interfaces`], carrying all state needed by downstream
/// code (DNS resolver construction, H3Client building, etc.).
pub struct BindSetup {
    /// Concrete bind URIs expanded from the user-supplied [`Binds`] patterns.
    pub bind_uris: Vec<BindUri>,
    /// Interface manager that owns the bindings.
    pub iface_manager: Arc<InterfaceManager>,
    /// Bound interfaces — one per bind URI.
    pub bind_interfaces: Vec<BindInterface>,
    /// Interfaces monitor for detecting runtime changes to network interfaces.
    pub monitor: InterfacesMonitor,
}

/// Like [`setup_bind_interfaces`], but calls `f` on the expanded bind URIs
/// before binding, allowing callers to mutate them (e.g. inject properties).
pub async fn setup_bind_interfaces_with(
    binds: &Binds,
    f: impl FnOnce(&mut Vec<BindUri>),
) -> Result<BindSetup, Box<BindConflictError>> {
    let monitor = Devices::global().monitor();

    let mut bind_uris = binds.to_bind_uris(monitor.interfaces().keys().map(String::as_str))?;
    f(&mut bind_uris);

    let iface_manager = Arc::new(InterfaceManager::new());
    let io_factory = Arc::new(DEFAULT_IO_FACTORY);

    let bind_interfaces = bind_uris
        .iter()
        .map(|bind_uri| iface_manager.bind(bind_uri.clone(), io_factory.clone()))
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;

    Ok(BindSetup {
        bind_uris,
        iface_manager,
        bind_interfaces,
        monitor,
    })
}

/// Expand [`Binds`] patterns into concrete network bindings.
///
/// This performs the full bind-setup pipeline that was previously duplicated in
/// every consumer crate:
///
/// 1. Obtain the current set of network interfaces via [`Devices::global`].
/// 2. Expand [`Binds`] patterns into concrete [`BindUri`]s.
/// 3. Create an [`InterfaceManager`] and bind each URI.
///
/// The returned [`BindSetup`] owns all state; callers decide which parts to
/// keep (e.g. `nslookup` ignores the monitor).
pub async fn setup_bind_interfaces(binds: &Binds) -> Result<BindSetup, Box<BindConflictError>> {
    setup_bind_interfaces_with(binds, |_| {}).await
}

/// Watch for network interface changes and dynamically bind/unbind URIs.
pub fn watch_bind_interfaces<B, U>(
    binds: &Binds,
    mut monitor: InterfacesMonitor,
    initial_bind_uris: Vec<BindUri>,
    bind_fn: B,
    unbind_fn: U,
) -> AbortOnDropHandle<()>
where
    B: Fn(BindUri) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
    U: Fn(BindUri) + Send + 'static,
{
    let binds = binds.clone();
    let span = tracing::Span::current();

    AbortOnDropHandle::new(tokio::spawn(
        async move {
            // Initial reconcile: handle events that arrived between setup and watcher start
            let mut current_set: HashSet<BindUri> = match binds
                .to_bind_uris(monitor.interfaces().keys().map(String::as_str))
            {
                Ok(new_uris) => {
                    let new_set: HashSet<BindUri> = new_uris.into_iter().collect();
                    let initial_set: HashSet<BindUri> = initial_bind_uris.into_iter().collect();

                    for uri in &new_set - &initial_set {
                        tracing::info!("Binding new URI `{uri}` during initial reconcile");
                        bind_fn(uri).await;
                    }
                    for uri in &initial_set - &new_set {
                        tracing::info!("Unbinding URI `{uri}` during initial reconcile");
                        unbind_fn(uri);
                    }

                    new_set
                }
                Err(err) => {
                    tracing::warn!("Failed to compute bind URIs during initial reconcile: {err}");
                    initial_bind_uris.into_iter().collect()
                }
            };

            // Monitor loop: react to interface changes
            while let Some((interfaces, _event)) = monitor.update().await {
                let new_uris = match binds.to_bind_uris(interfaces.keys().map(String::as_str)) {
                    Ok(uris) => uris,
                    Err(err) => {
                        tracing::warn!("Failed to compute bind URIs after interface change: {err}");
                        continue;
                    }
                };

                let new_set: HashSet<BindUri> = new_uris.into_iter().collect();

                for uri in &current_set - &new_set {
                    tracing::info!("Unbinding URI `{uri}`");
                    unbind_fn(uri);
                }
                for uri in &new_set - &current_set {
                    tracing::info!("Binding new URI `{uri}`");
                    bind_fn(uri).await;
                }

                current_set = new_set;
            }
        }
        .instrument(span),
    ))
}
