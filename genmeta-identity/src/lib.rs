// TODO: migrate cert_server.rs from reqwest to h3x client

mod bootstrap;

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cli")]
pub use cli::{Cli, Error, Options, run};

#[cfg(feature = "cli")]
pub mod auth;
pub mod cert_server;
#[cfg(feature = "cli")]
pub mod checkout;
pub mod local_identity;

pub const DEFAULT_DEVICE_NAME: &str = "local device";

pub const DEFAULT_DHTTP_CA_SERVICE: &str = "https://api.genmeta.net";
pub const DHTTP_CA_SERVICE: &str = bootstrap::DHTTP_CA_SERVICE;

#[cfg(test)]
mod tests {
    use super::{DEFAULT_DHTTP_CA_SERVICE, DHTTP_CA_SERVICE, cert_server::CertServer};

    #[test]
    fn cert_server_client_builds_with_dhttp_root_ca() {
        reqwest::Certificate::from_pem(dhttp::trust::DHTTP_ROOT_CA_PEM)
            .expect("DHTTP root CA should be valid PEM");

        _ = rustls::crypto::ring::default_provider().install_default();
        CertServer::new(DEFAULT_DHTTP_CA_SERVICE)
            .expect("cert server client should build with DHTTP root CA");
    }

    #[test]
    fn cert_server_base_url_defaults_to_genmeta_production_server() {
        if option_env!("DHTTP_CA_SERVICE").is_none() {
            assert_eq!(DHTTP_CA_SERVICE, DEFAULT_DHTTP_CA_SERVICE);
        }
    }

    #[test]
    fn cert_server_base_url_uses_compile_time_environment() {
        if let Some(expected) = option_env!("DHTTP_CA_SERVICE") {
            assert_eq!(DHTTP_CA_SERVICE, expected);
        }
    }
}
