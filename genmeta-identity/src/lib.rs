// TODO: migrate cert_server.rs from reqwest to h3x client

mod bootstrap;

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub use cli::{Cli, Error, Options, run};

#[cfg(feature = "cli")]
pub mod auth;
pub mod cert_server;
pub mod checkout;
pub mod local_identity;

pub const DEFAULT_DEVICE_NAME: &str = "local device";

pub const DEFAULT_CERT_SERVER_BASE_URL: &str = "https://license.genmeta.net";
pub const CERT_SERVER_URL_ENV: &str = "DHTTP_CERT_SERVER_URL";
pub const CERT_SERVER_BASE_URL: &str = bootstrap::DHTTP_CERT_SERVER_URL;

#[cfg(test)]
mod tests {
    use super::{
        CERT_SERVER_BASE_URL, CERT_SERVER_URL_ENV, DEFAULT_CERT_SERVER_BASE_URL,
        cert_server::CertServer,
    };

    #[test]
    fn cert_server_client_builds_with_dhttp_root_ca() {
        reqwest::Certificate::from_pem(dhttp::trust::DHTTP_ROOT_CA)
            .expect("DHTTP root CA should be valid PEM");

        _ = rustls::crypto::ring::default_provider().install_default();
        CertServer::new("https://license.genmeta.net")
            .expect("cert server client should build with DHTTP root CA");
    }

    #[test]
    fn cert_server_url_env_uses_dhttp_bootstrap_namespace() {
        assert_eq!(CERT_SERVER_URL_ENV, "DHTTP_CERT_SERVER_URL");
    }

    #[test]
    fn cert_server_base_url_defaults_to_license_server() {
        if option_env!("DHTTP_CERT_SERVER_URL").is_none() {
            assert_eq!(CERT_SERVER_BASE_URL, DEFAULT_CERT_SERVER_BASE_URL);
        }
    }

    #[test]
    fn cert_server_base_url_uses_compile_time_environment() {
        if let Some(expected) = option_env!("DHTTP_CERT_SERVER_URL") {
            assert_eq!(CERT_SERVER_BASE_URL, expected);
        }
    }
}
