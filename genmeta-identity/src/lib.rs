// TODO: migrate cert_server.rs from reqwest to h3x client

mod bootstrap;

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub use cli::{Cli, Error, Options, run, run_listen};

#[cfg(feature = "cli")]
pub mod auth;
pub mod cert_server;
#[cfg(feature = "cli")]
pub mod checkout;
pub mod code_signing;
pub mod local_identity;

pub const DEFAULT_DEVICE_NAME: &str = "local device";

pub const DEFAULT_DHTTP_CA_SERVICE: &str = "https://api.genmeta.net";
pub const DHTTP_CA_SERVICE: &str = bootstrap::DHTTP_CA_SERVICE;

#[cfg(test)]
#[path = "../tests/unit/lib.rs"]
mod tests;
