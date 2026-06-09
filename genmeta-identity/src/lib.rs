// TODO: migrate cert_server.rs from reqwest to h3x client

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub use cli::{Error, Options, run};

#[cfg(feature = "cli")]
pub mod auth;
pub mod cert_server;
pub mod checkout;
pub mod local_identity;

pub const REGISTERABLE_SUFFIXES: &[&str] = &["pilot", "lab"];
pub const DEFAULT_DEVICE_NAME: &str = "local device";

pub const DEFAULT_CERT_SERVER_BASE_URL: &str = "https://license.genmeta.net";
pub const CERT_SERVER_URL_ENV: &str = "CERT_SERVER_URL";

#[cfg(test)]
mod tests {
    use super::cert_server::CertServer;

    #[test]
    fn cert_server_client_builds_with_dhttp_root_ca() {
        reqwest::Certificate::from_pem(dhttp::trust::DHTTP_ROOT_CA)
            .expect("DHTTP root CA should be valid PEM");

        _ = rustls::crypto::ring::default_provider().install_default();
        CertServer::new("https://license.genmeta.net")
            .expect("cert server client should build with DHTTP root CA");
    }
}
