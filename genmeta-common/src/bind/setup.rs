//! Shared bind setup logic for QUIC interface binding.
//!
//! Consolidates the duplicated bind-interfaces initialization flow found across
//! consumer crates (`genmeta-curl`, `genmeta-ssh3`, `genmeta-nslookup`).

use std::sync::Arc;

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
pub async fn setup_bind_interfaces(binds: Binds) -> Result<BindSetup, BindConflictError> {
    let monitor = Devices::global().monitor();

    let bind_uris = binds.to_bind_uris(monitor.interfaces().keys().map(String::as_str))?;

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
