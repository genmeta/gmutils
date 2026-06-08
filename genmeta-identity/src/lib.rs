// TODO: migrate cert_server.rs from reqwest to h3x client

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub use cli::{Error, Options, run};

pub mod cert_server;

pub const REGISTERABLE_SUFFIXES: &[&str] = &["pilot", "lab"];

pub const DEFAULT_CERT_SERVER_BASE_URL: &str = "https://license.genmeta.net";
pub const CERT_SERVER_URL_ENV: &str = "CERT_SERVER_URL";

#[cfg(test)]
mod tests {
    #[test]
    fn build_script_uses_dhttp_root_ca_env_only() {
        let build_script = include_str!("../build.rs");

        assert!(build_script.contains("DHTTP_ROOT_CA"));
        assert!(!build_script.contains("std::env::var(\"ROOT_CA\")"));
        assert!(!build_script.contains("rerun-if-env-changed=ROOT_CA"));
    }
}
