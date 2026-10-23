use std::{io::IsTerminal, time::Duration};

use dhttp_home::{DhttpHome, LoadDhttpHomeError, identity::settings::LoadDhttpSettingsError};
use dhttp_identity::name::DhttpName as Name;
use http_body_util::BodyExt;
use snafu::{IntoError, OptionExt, ResultExt, Snafu};
use tokio::io::AsyncWriteExt;
use tracing_subscriber::prelude::*;

mod api;
mod cli;
pub use cli::{Options, ParseCommandError, ReportFromStr};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(transparent)]
    ParseCommand { source: ParseCommandError },
    #[snafu(display("failed to load dhttp home"))]
    LoadHome { source: LoadDhttpHomeError },
    #[snafu(display("failed to load default identity config"))]
    LoadDefaultIdentityConfig { source: LoadDhttpSettingsError },
    #[snafu(display(
        "no default identity configured, use `genmeta identity default <name>` to set one"
    ))]
    MissingDefaultIdentity,
    #[snafu(display("failed to resolve local credentials for identity `{name}`"))]
    LoadProfile {
        name: Name<'static>,
        source: dhttp_home::identity::ssl::ResolveIdentityProfileError,
    },
    #[snafu(display("failed to initialize authenticated DHTTP client"))]
    Endpoint { source: dhttp::Error },
    #[snafu(display("failed to build daccess management URI"))]
    RequestUri { source: http::Error },
    #[snafu(display("failed to send daccess management request"))]
    Request { source: dhttp::Error },
    #[snafu(display("failed to read daccess response"))]
    Read { source: dhttp::BoxError },
    #[snafu(display("daccess response exceeds 8 MiB"))]
    ResponseTooLarge,
    #[snafu(display("daccess management request timed out after {seconds} seconds"))]
    Timeout { seconds: u64 },
    #[snafu(display("failed to encode or decode daccess JSON"))]
    Json { source: serde_json::Error },
    #[snafu(display("daccess API {path} returned HTTP {status}: {message}"))]
    Api {
        status: http::StatusCode,
        path: String,
        message: String,
    },
}

fn init_tracing(verb: bool) -> tracing_appender::non_blocking::WorkerGuard {
    let (stderr, guard) = tracing_appender::non_blocking(std::io::stderr());
    let filter = if verb {
        tracing_subscriber::filter::LevelFilter::DEBUG
    } else {
        tracing_subscriber::filter::LevelFilter::OFF
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(filter)
        .init();
    guard
}

pub async fn run(options: Options) -> Result<(), Error> {
    let _guard = init_tracing(options.verb);
    let home = DhttpHome::load(options.home_scope()).context(error::LoadHomeSnafu)?;
    let output = run_for_home(&home, options).await?;
    if !output.is_empty() {
        println!("{}", output.trim_end());
    }
    Ok(())
}

pub async fn run_for_home(home: &DhttpHome, options: Options) -> Result<String, Error> {
    let timeout = options.timeout;
    let (identity, command) = options.into_parts()?;
    if let cli::Command::Print { output } = command {
        return Ok(output);
    }
    let identity = resolve_identity(home, identity).await?;
    let profile = home
        .resolve_identity_profile((identity.clone()).as_full())
        .await
        .context(error::LoadProfileSnafu {
            name: identity.clone(),
        })?;
    init_local_network().await.context(error::EndpointSnafu)?;
    let endpoint = dhttp::Endpoint::load_from_with_ocsp(profile.path())
        .await
        .context(error::EndpointSnafu)?;
    let server = identity
        .as_full()
        .parse()
        .expect("a normalized identity is a valid DHTTP authority");
    api::execute(&DhttpTransport { endpoint, timeout }, &server, command).await
}

async fn init_local_network() -> dhttp::Result<()> {
    init_network(&[ddns::DnsScheme::Mdns], &["*".into()]).await
}

async fn resolve_identity(
    home: &DhttpHome,
    identity: Option<Name<'static>>,
) -> Result<Name<'static>, Error> {
    if let Some(identity) = identity {
        return Ok(identity);
    }
    let config = match home.load_settings().await {
        Ok(config) => config,
        Err(LoadDhttpSettingsError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return error::MissingDefaultIdentitySnafu.fail();
        }
        Err(source) => return Err(error::LoadDefaultIdentityConfigSnafu.into_error(source)),
    };
    config
        .settings()
        .default_identity_name()
        .cloned()
        .context(error::MissingDefaultIdentitySnafu)
}

struct DhttpTransport {
    endpoint: dhttp::Endpoint,
    timeout: u64,
}
impl api::Transport for DhttpTransport {
    async fn send(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> Result<http::Response<Vec<u8>>, Error> {
        tokio::time::timeout(Duration::from_secs(self.timeout), async {
            let (parts, body) = request.into_parts();
            let response = if body.is_empty() {
                self.endpoint
                    .from_request(http::Request::from_parts(parts, dhttp::Empty::new()))
                    .await
                    .context(error::RequestSnafu)?
            } else {
                let (mut writer, receive) = self
                    .endpoint
                    .from_request(http::Request::from_parts(
                        parts,
                        dhttp::WndBuf::new(64 * 1024),
                    ))
                    .await
                    .context(error::RequestSnafu)?;
                let upload = async {
                    writer.write_all(&body).await.map_err(dhttp::Error::from)?;
                    writer.shutdown().await.map_err(dhttp::Error::from)
                };
                // These JSON requests are small. Finish uploading before dropping
                // the writer; response headers alone do not mean upload has ended.
                let ((), response) =
                    tokio::try_join!(upload, receive).context(error::RequestSnafu)?;
                response
            };
            let (parts, mut body) = response.into_parts();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.context(error::ReadSnafu)?;
                if let Ok(data) = frame.into_data() {
                    if bytes.len().saturating_add(data.len()) > 8 * 1024 * 1024 {
                        return error::ResponseTooLargeSnafu.fail();
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            Ok(http::Response::from_parts(parts, bytes))
        })
        .await
        .map_err(|_| Error::Timeout {
            seconds: self.timeout,
        })?
    }
}

async fn init_network(schemes: &[ddns::DnsScheme], binds: &[String]) -> dhttp::Result<()> {
    if binds.iter().any(|bind| bind != "*") {
        return Err(dhttp::Error::InvalidRequest {
            message: "the process-wide DHTTP network currently requires --interface '*'".into(),
        });
    }
    let mdns = ddns::install_resolvers(schemes)?;
    let network = dhttp::DhttpNetwork::init().await?;
    if let Some(mdns) = mdns {
        static MAINTENANCE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
        MAINTENANCE
            .get_or_try_init(|| async {
                mdns.maintain(std::time::Duration::from_secs(1), move || {
                    Ok(network
                        .active_bindings()
                        .map_err(std::io::Error::other)?
                        .into_iter()
                        .filter(|binding| {
                            dhttp::resolve::EndpointAddr::direct(binding.address).scope()
                                == Some(dhttp::Scope::Internal)
                        })
                        .map(|binding| {
                            ddns::mdns::MdnsBinding::new(binding.device, binding.address.ip())
                        })
                        .collect())
                })
                .await?;
                Ok::<(), std::io::Error>(())
            })
            .await?;
    }
    Ok(())
}
