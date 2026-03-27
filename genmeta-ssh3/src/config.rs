use core::fmt;
use std::{collections::BTreeSet, str::FromStr, time::Duration};

use genmeta_common::{
    bind::{self, Binds},
    dns, id,
};
use genmeta_home::identity::{IdentityHome, InvalidName, Name};
use http::{Uri, uri::Authority};
use snafu::{ResultExt, Snafu};

use crate::{
    forward::{DynamicForward, LocalForward, RemoteForward},
    ssh_config,
};

#[derive(Debug, Snafu)]
#[snafu(module(config_error))]
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
    ReadConfig { source: ssh_config::ReadConfigError },
    #[snafu(transparent)]
    LoadHomeAndIdentity {
        source: id::LoadHomeAndIdentityError,
    },
    #[snafu(display("identity `{id}` in ssh config is invalid"))]
    InvalidIdInSshConfig { id: String, source: InvalidName },
    #[snafu(display("failed to parse path and query `{path_and_query}`"))]
    InvalidPathAndQuery {
        path_and_query: String,
        source: http::uri::InvalidUri,
    },
    #[snafu(display("failed to construct URI from parts"))]
    ConstructUri { source: http::uri::InvalidUriParts },
}

#[derive(Debug)]
pub struct Config {
    pub binds: bind::Binds,
    pub dns: BTreeSet<dns::DnsScheme>,
    pub username: String,
    pub password: Option<String>,
    pub uri: Uri,
    pub id: Option<IdentityHome>,
    pub connect_timeout: Duration,
    pub local_forwards: Vec<LocalForward>,
    pub remote_forwards: Vec<RemoteForward>,
    pub dynamic_forwards: Vec<DynamicForward>,
}

// CLI args > config file priority
// e.g., -i id -l login_name priority higher than corresponding Host
// HostName can provide the host part of URI
impl super::Options {
    pub async fn config(&self) -> Result<Config, Error> {
        let (ssh_config, read_config_errors) = ssh_config::read_config(&self.options, &self.host)
            .await
            .context(config_error::ReadConfigSnafu {})?;

        for warning in &read_config_errors {
            tracing::warn!(
                "ssh config {}:{}: {}",
                warning.location.path.display(),
                warning.location.line,
                warning.message,
            );
        }

        // user: command line -> config file -> uri -> whoami
        let mut username = self.login_name.clone().or_else(|| ssh_config.user.clone());
        let mut password = None;

        // uri: ssh_config hostname (if present) -> command line host
        let uri: Uri = match &ssh_config.hostname {
            Some(hostname) => hostname
                .parse()
                .context(config_error::InvalidUriSnafu { uri: hostname })?,
            None => self.host.parse().context(config_error::InvalidUriSnafu {
                uri: self.host.clone(),
            })?,
        };

        if username.is_none() {
            tracing::debug!("User not found in ssh_config, trying to parse from hostname");
            (username, password) = parse_username_password_from_uri(&uri);
        }

        let (username, password) = match username {
            Some(username) => (username, password),
            None => {
                tracing::debug!("User not found in URI, using current user");
                (
                    whoami::username().unwrap_or_else(|_| "unknown".to_string()),
                    None,
                )
            }
        };

        let uri = complete_uri(uri, &username)?;

        let cli_id = (self.id.as_ref())
            .map(|id| (&"command line options" as &dyn fmt::Display, id.borrow()));
        let ssh_config_id = (ssh_config.id.as_ref())
            .map(|id| {
                Name::from_str(id)
                    .context(config_error::InvalidIdInSshConfigSnafu { id })
                    .map(|name| (&"ssh config" as &dyn fmt::Display, name))
            })
            .transpose()?;

        let id = if self.anonymous {
            None
        } else {
            id::load_home_and_identity(
                cli_id.is_some() || ssh_config_id.is_some(),
                Option::into_iter(cli_id).chain(ssh_config_id),
            )
            .await?
        };

        let connect_timeout = ssh_config.connect_timeout.unwrap_or(Duration::MAX);

        // Merge forwarding rules: CLI args take precedence, then ssh config.
        let mut local_forwards = self.local_forwards.clone();
        local_forwards.extend(ssh_config.local_forwards);
        let mut remote_forwards = self.remote_forwards.clone();
        remote_forwards.extend(ssh_config.remote_forwards);
        let mut dynamic_forwards = self.dynamic_forward.clone();
        dynamic_forwards.extend(ssh_config.dynamic_forwards);

        Ok(Config {
            binds: Binds::new(self.binds.clone()),
            dns: self.dns.iter().cloned().collect(),
            username,
            password,
            uri,
            id,
            connect_timeout,
            local_forwards,
            remote_forwards,
            dynamic_forwards,
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
        None => Some("ssh3".parse().expect("BUG: `ssh3` is a valid URI scheme")),
        Some(scheme) => {
            return Err(config_error::UnsupportedSchemeSnafu {
                scheme: scheme.to_string(),
            }
            .build());
        }
    };
    uri_parts.path_and_query = match uri_parts.path_and_query {
        root if root.as_ref().is_none_or(|path| path == "/") => {
            tracing::debug!("Path is empty, using `/ssh` as default");
            Some("/ssh".parse().expect("BUG: `/ssh` is a valid path"))
        }
        path_and_query => path_and_query,
    };

    uri_parts.path_and_query = match uri_parts.path_and_query {
        Some(ref path_and_query) => {
            let path_and_query = format!(
                "{}/{}?{}",
                path_and_query.path(),
                username,
                path_and_query.query().unwrap_or_default()
            );
            Some(
                path_and_query
                    .parse()
                    .context(config_error::InvalidPathAndQuerySnafu { path_and_query })?,
            )
        }
        None => unreachable!(),
    };

    uri_parts.authority = match uri_parts.authority {
        Some(authority) => {
            let peer_name =
                Name::from_str(authority.host()).context(config_error::InvalidPeerNameSnafu {
                    id: authority.host().to_string(),
                })?;
            let authority = Authority::from_str(peer_name.as_full()).context(
                config_error::InvalidAuthoritySnafu {
                    authority: peer_name.as_full().to_string(),
                },
            )?;
            Some(authority)
        }
        None => return Err(config_error::MissingAuthoritySnafu {}.build()),
    };

    Uri::from_parts(uri_parts).context(config_error::ConstructUriSnafu)
}
