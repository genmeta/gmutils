// TODO: migrate cert_server.rs from reqwest to h3x client

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub use cli::{Error, Options, run};

pub mod cert_server;

pub const REGISTERABLE_SUFFIXES: &[&str] = &["pilot", "lab"];

pub const DEFAULT_CERT_SERVER_BASE_URL: &str = "https://license.genmeta.net";
