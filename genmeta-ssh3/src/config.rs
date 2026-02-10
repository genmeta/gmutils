use std::{str::FromStr, time::Duration};

use genmeta_home::{
    GenmetaHome, LocateGenmetaHomeError,
    identity::{Identity, InvalidName, Name, fs::LoadIdentityError},
};
use http::{Uri, uri::Authority};
use snafu::{Report, ResultExt, Snafu};
use ssh_config::error::ReadConfigError;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to parse URI `{uri}`"))]
    InvalidUri {
        uri: String,
        source: http::uri::InvalidUri,
    },
    #[snafu(display("failed to parse identity `{id}` as peer authority"))]
    InvalidPeerName { id: String, source: InvalidName },
    #[snafu(display("failed to parse `{authority}` as URI authority"))]
    InvalidAuthority {
        authority: String,
        source: http::uri::InvalidUri,
    },
    #[snafu(display("unsupported URI scheme `{scheme}`, only `ssh3` is supported"))]
    UnsupportedScheme { scheme: String },
    #[snafu(display("missing authority in URI"))]
    MissingAuthority {},
    #[snafu(display("failed to read ssh configuration"))]
    ReadConfig { source: ReadConfigError },
    #[snafu(transparent)]
    LocateGenmetaHome { source: LocateGenmetaHomeError },
    #[snafu(display("identity `{id}` in ssh config is invalid"))]
    InvalidId { id: String, source: InvalidName },
    #[snafu(display("failed to read identity for `{id}`"))]
    LoadIdentity {
        id: Name<'static>,
        source: LoadIdentityError,
    },
}

#[derive(Debug)]
pub struct Config {
    pub username: String,
    pub password: Option<String>,
    pub uri: Uri,
    pub id: Option<Identity<'static>>,
    pub connect_timeout: Duration,
    // TODO
    // pub dns_schemes: Vec<DnsSchema>,
}

// CLI args > config file priority
// e.g., -i id -l login_name priority higher than corresponding Host
// HostName can provide the host part of URI
impl super::Options {
    pub async fn config(&self) -> Result<Config, Error> {
        let (ssh_config, read_config_errors) =
            ssh_config::openssh::read_config(&self.options, &self.host)
                .await
                .context(ReadConfigSnafu {})?;

        for (message, error) in read_config_errors {
            tracing::error!("{message}: {}", snafu::Report::from_error(error));
        }

        // user: command line -> config file -> uri -> whoami
        let mut username = self.login_name.clone().or_else(|| ssh_config.user.clone());
        let mut password = None;

        // uri: ssh_config(if present) -> command line
        let uri = match &ssh_config.hostname {
            Some(uri) => uri.clone(),
            None => self.host.parse().context(InvalidUriSnafu {
                uri: self.host.clone(),
            })?,
        };

        if username.is_none() {
            tracing::debug!("User not found in ssh_config, Try parse it from hostname");
            (username, password) = parse_username_password_from_uri(&uri);
        }

        let (username, password) = match username {
            Some(username) => (username, password),
            None => {
                tracing::debug!("User not found in URI, use current user");
                (whoami::username(), None)
            }
        };

        let uri = complete_uri(uri, &username)?;

        let try_load_default_identity = || async {
            let genmeta_home = match GenmetaHome::load_from_environment() {
                Ok(genmeta_home) => genmeta_home,
                Err(error) => {
                    tracing::warn!(
                        "No identity specified in CLI or ssh config, and default identity cannot be load as {}",
                        Report::from_error(error)
                    );
                    return None;
                }
            };
            let id = match genmeta_home.identities().load_default_identity().await {
                Ok(id) => id,
                Err(error) => {
                    tracing::warn!(
                        "No identity specified in CLI or ssh config, and default identity cannot be load as {}",
                        Report::from_error(error)
                    );
                    return None;
                }
            };
            Some(id)
        };

        let id = match self.id.as_ref() {
            Some(id) => Some(id.borrow()),
            None => match &ssh_config.id {
                Some(id) => Some(Name::from_str(id).context(InvalidIdSnafu { id })?),
                None => None,
            },
        };

        let id = match id {
            Some(id) => {
                let genmeta_home = GenmetaHome::load_from_environment()?;
                Some(
                    genmeta_home
                        .identities()
                        .load(id.to_owned())
                        .await
                        .context(LoadIdentitySnafu { id: id.to_owned() })?,
                )
            }
            None => try_load_default_identity().await,
        };

        let connect_timeout = ssh_config.connect_timeout.unwrap_or(Duration::MAX);

        Ok(Config {
            username,
            password,
            uri,
            id,
            connect_timeout,
        })
    }
}

fn parse_username_password_from_uri(uri: &Uri) -> (Option<String>, Option<String>) {
    uri.authority()
        .and_then(|authority| authority.as_str().rsplit_once('@'))
        .map(|(username_password, _host)| {
            username_password
                .split_once(':')
                .map(|(username, password)| {
                    (Some(username.to_string()), Some(password.to_string()))
                })
                .unwrap_or((Some(username_password.to_string()), None))
        })
        .unwrap_or((None, None))
}

fn complete_uri(uri: Uri, username: &str) -> Result<Uri, Error> {
    let mut uri_parts = uri.into_parts();
    uri_parts.scheme = match uri_parts.scheme {
        Some(ref scheme) if scheme.as_str() == "ssh3" => uri_parts.scheme,
        None => Some("ssh3".parse().unwrap()),
        Some(scheme) => {
            return Err(UnsupportedSchemeSnafu {
                scheme: scheme.to_string(),
            }
            .build());
        }
    };
    uri_parts.path_and_query = match uri_parts.path_and_query {
        root if root.as_ref().is_none_or(|path| path == "/") => {
            tracing::debug!(target: "connect", "Path is empty, using `/ssh` as default");
            Some("/ssh".parse().unwrap())
        }
        path_and_query => path_and_query,
    };

    uri_parts.path_and_query = match uri_parts.path_and_query {
        Some(ref path_and_query) => Some(
            format!(
                "{}/{}?{}",
                path_and_query.path(),
                username,
                path_and_query.query().unwrap_or_default()
            )
            .parse()
            .unwrap(),
        ),
        None => unreachable!(),
    };

    uri_parts.authority = match uri_parts.authority {
        Some(authority) => {
            let peer_name = Name::from_str(authority.host()).context(InvalidPeerNameSnafu {
                id: authority.host().to_string(),
            })?;
            let authority =
                Authority::from_str(peer_name.as_full()).context(InvalidAuthoritySnafu {
                    authority: peer_name.as_full().to_string(),
                })?;
            Some(authority)
        }
        None => return Err(MissingAuthoritySnafu {}.build()),
    };

    Ok(Uri::from_parts(uri_parts).expect("Failed to construct URI from parts"))
}
