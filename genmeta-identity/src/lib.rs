// use h3

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub use cli::{Error, Options, run};

pub mod cert_server;

pub const REGISTERABLE_DOMAINS: &[&str] = &["pilot", "lab"];

#[cfg(debug_assertions)]
pub const DEFAULT_CERT_SERVER_BASE_URL: &str = "http://127.0.0.1:3001";
#[cfg(not(debug_assertions))]
pub const DEFAULT_CERT_SERVER_BASE_URL: &str = "https://license.genmeta.net";
