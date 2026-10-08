//! Shared CLI identity storage and process-wide DHTTP transport setup.
pub use cli_home as home;
pub use dhttp_home as runtime_home;
pub mod ocsp;
pub use ddns;
pub use dhttp::{access, log};
pub use dhttp_identity::{certificate, identity, name};
pub use qprotocol;
pub mod message;
pub mod trust;
include!(concat!(env!("OUT_DIR"), "/bootstrap.rs"));

use std::{io, path::Path, sync::Arc};

pub type BindPattern = String;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DnsScheme {
    System,
    Mdns,
    H3,
    Http,
}
impl std::str::FromStr for DnsScheme {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "system" => Ok(Self::System),
            "mdns" => Ok(Self::Mdns),
            "h3" => Ok(Self::H3),
            "http" => Ok(Self::Http),
            _ => Err(format!("unsupported DNS scheme: {s}")),
        }
    }
}
impl std::fmt::Display for DnsScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::System => "system",
            Self::Mdns => "mdns",
            Self::H3 => "h3",
            Self::Http => "http",
        })
    }
}

/// New transport requests can be authenticated or explicitly anonymous.
#[derive(Clone)]
pub struct Client {
    endpoint: Option<dhttp::Endpoint>,
}
impl Client {
    pub fn anonymous() -> Self {
        Self { endpoint: None }
    }
    pub fn from_endpoint(endpoint: dhttp::Endpoint) -> Self {
        Self {
            endpoint: Some(endpoint),
        }
    }
    pub fn name(&self) -> Option<name::DhttpName<'static>> {
        self.endpoint
            .as_ref()
            .map(|e| name::DhttpName::try_from(e.name().to_owned()).expect("loaded identity name"))
    }
    pub fn from_request<B>(&self, request: http::Request<B>) -> dhttp::Request<B> {
        match &self.endpoint {
            Some(endpoint) => endpoint.from_request(request),
            None => dhttp::Anonymous.from_request(request),
        }
    }
    pub async fn load_profile(path: &Path) -> dhttp::Result<Self> {
        let profile =
            dhttp_home::identity::IdentityProfile::try_from(path).map_err(io::Error::other)?;
        let (certs, key) = futures::try_join!(
            async {
                profile
                    .load_certs()
                    .await
                    .map_err(|source| dhttp::Error::Home {
                        path: profile.cert_path(),
                        source: Arc::new(source),
                    })
            },
            async {
                profile
                    .load_key()
                    .await
                    .map_err(|source| dhttp::Error::Home {
                        path: profile.key_path(),
                        source: Arc::new(source),
                    })
            },
        )?;
        qtls::RootCerts::set([DHTTP_ROOT_CA_DER.to_vec().into()]).map_err(|source| {
            dhttp::Error::TlsConfig {
                source: Arc::new(source),
            }
        })?;
        let ocsp = ocsp::load_or_refresh(&profile, &certs).await?;
        let identity = qbase::endpoint::Endpoint::new(
            &qtls::default_provider(),
            profile.name(),
            certs,
            key,
            ocsp,
        )
        .map_err(|source| dhttp::Error::Credentials {
            source: Arc::new(source),
        })?;
        Ok(Self::from_endpoint(dhttp::Endpoint::new(identity)))
    }
}

/// Resolver installation must precede network initialization, as in pishoo.
pub async fn init(schemes: &[DnsScheme], binds: &[BindPattern]) -> dhttp::Result<()> {
    if binds.iter().any(|bind| bind != "*") {
        return Err(dhttp::Error::InvalidRequest {
            message: "the process-wide DHTTP network currently requires --interface '*'".into(),
        });
    }
    let mdns = install_resolvers(schemes)?;
    dhttp::DhttpNetwork::init().await?;
    if let Some(mdns) = mdns {
        maintain_mdns_bindings(&mdns).await;
        static MAINTENANCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        MAINTENANCE.get_or_init(|| {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    maintain_mdns_bindings(&mdns).await;
                }
            });
        });
    }
    Ok(())
}

async fn maintain_mdns_bindings(mdns: &ddns::mdns::MdnsResolverSet) {
    let desired: std::collections::HashSet<_> = dhttp::AddressBook::global()
        .inner_bindings()
        .into_iter()
        .filter(|(bound, _)| qprotocol::Dock::global().find_socket(*bound).is_some())
        .map(|(bound, device)| ddns::mdns::MdnsBinding::new(device.name(), bound.ip()))
        .collect();
    for instance in mdns.snapshot() {
        let binding = ddns::mdns::MdnsBinding::new(instance.bound_device(), instance.bound_ip());
        if !desired.contains(&binding)
            && let Err(error) = mdns.remove(&binding).await
        {
            tracing::warn!(%error, "failed to remove mDNS binding");
        }
    }
    for binding in desired {
        if let Err(error) = mdns.upsert(binding).await {
            tracing::warn!(%error, "failed to prepare mDNS binding");
        }
    }
}

pub fn install_resolvers(schemes: &[DnsScheme]) -> io::Result<Option<ddns::mdns::MdnsResolverSet>> {
    #[derive(Default)]
    struct Installed {
        schemes: std::collections::HashSet<DnsScheme>,
        mdns: Option<ddns::mdns::MdnsResolverSet>,
    }
    static INSTALLED: std::sync::OnceLock<std::sync::Mutex<Installed>> = std::sync::OnceLock::new();
    let mut installed = INSTALLED
        .get_or_init(Default::default)
        .lock()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut requested = schemes.to_vec();
    // H3/HTTP DNS needs ordinary DNS for its bootstrap server; SystemResolver excludes DHTTP names.
    if schemes
        .iter()
        .any(|s| matches!(s, DnsScheme::H3 | DnsScheme::Http))
    {
        requested.push(DnsScheme::System);
    }
    for scheme in requested {
        if installed.schemes.contains(&scheme) {
            continue;
        }
        match scheme {
            DnsScheme::System => {
                dhttp::resolve::Resolver::add(Arc::new(dhttp::resolve::SystemResolver))
            }
            DnsScheme::H3 => dhttp::resolve::Resolver::add(Arc::new(
                ddns::H3Resolver::anonymous(
                    ddns::resolvers::DHTTP_NAME_SERVICE
                        .parse()
                        .map_err(io::Error::other)?,
                )
                .map_err(io::Error::other)?,
            )),
            DnsScheme::Http => dhttp::resolve::Resolver::add(Arc::new(
                ddns::http::HttpResolver::new(
                    ddns::resolvers::DHTTP_NAME_SERVICE
                        .parse()
                        .map_err(io::Error::other)?,
                )
                .map_err(io::Error::other)?,
            )),
            DnsScheme::Mdns => {
                let set =
                    ddns::mdns::MdnsResolverSet::new(ddns::resolvers::DHTTP_MDNS_SERVICE_DOMAIN);
                dhttp::resolve::Resolver::add(Arc::new(set.clone()));
                installed.mdns = Some(set);
            }
        }
        installed.schemes.insert(scheme);
    }
    Ok(schemes
        .contains(&DnsScheme::Mdns)
        .then(|| installed.mdns.clone())
        .flatten())
}

/// Convert the CLI storage handle into the new runtime's identity-local layout.
pub fn runtime_profile(
    profile: &home::identity::IdentityProfile,
) -> dhttp_home::identity::IdentityProfile {
    dhttp_home::identity::IdentityProfile::try_from(profile.path())
        .expect("CLI resolved a valid identity profile")
}

/// Poll upload and response consumption together; a completed response ends uploading.
/// Receiving has priority so an early HTTP rejection remains visible to the caller.
pub async fn transfer<U, R, T, E>(upload: U, receive: R) -> Result<T, E>
where
    U: std::future::Future<Output = Result<(), E>>,
    R: std::future::Future<Output = Result<T, E>>,
{
    tokio::pin!(upload, receive);
    tokio::select! {
        biased;
        response = &mut receive => response,
        uploaded = &mut upload => { uploaded?; receive.await },
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn transfer_drains_duplex_response_during_large_upload() {
        let (mut upload_client, mut upload_server) = tokio::io::duplex(64);
        let (mut response_server, mut response_client) = tokio::io::duplex(64);
        let server = tokio::spawn(async move {
            tokio::io::copy(&mut upload_server, &mut response_server)
                .await
                .unwrap();
        });
        let payload = vec![42u8; 256 * 1024];
        let upload = async {
            upload_client.write_all(&payload).await?;
            upload_client.shutdown().await
        };
        let receive = async {
            let mut body = Vec::new();
            response_client.read_to_end(&mut body).await?;
            Ok::<_, io::Error>(body)
        };
        let body =
            tokio::time::timeout(std::time::Duration::from_secs(5), transfer(upload, receive))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(body, payload);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn early_rejection_does_not_wait_for_a_blocked_upload() {
        let uploading = std::future::pending::<Result<(), io::Error>>();
        let response = async { Ok::<_, io::Error>(http::StatusCode::PAYLOAD_TOO_LARGE) };
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            transfer(uploading, response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(status, http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn repeated_bootstrap_does_not_duplicate_resolvers() {
        let schemes = [DnsScheme::System, DnsScheme::H3];
        install_resolvers(&schemes).unwrap();
        let before = dhttp::resolve::Resolver::get().to_string();
        install_resolvers(&schemes).unwrap();
        assert_eq!(dhttp::resolve::Resolver::get().to_string(), before);
    }

    #[test]
    fn runtime_profile_preserves_identity_local_paths() {
        let home = home::DhttpHome::new("/tmp/dhttp".into());
        let cli = home.identity_profile("alice.pilot".parse().unwrap());
        let native = runtime_profile(&cli);
        assert_eq!(native.path(), cli.path());
        assert_eq!(native.access_db_path(), cli.access_db_path());
        assert_eq!(native.name(), cli.name().as_full());
    }
}
