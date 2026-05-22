use std::{collections::BTreeSet, str::FromStr, time::Duration};

use dhttp::{
    config::{self, DhttpConfig, identity::IdentityConfig},
    ddns,
    dquic::binds::BindPattern,
    name::{DhttpName, DhttpName as Name, InvalidDhttpName as InvalidName},
};
use http::{Uri, uri::Authority};
use snafu::{IntoError, ResultExt, Snafu, ensure};

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
    #[snafu(display("unsupported uri scheme `{scheme}`, only `https` is supported"))]
    UnsupportedScheme { scheme: String },
    #[snafu(display("missing authority in uri"))]
    MissingAuthority {},
    #[snafu(display("failed to read ssh configuration"))]
    ReadConfig { source: ssh_config::ReadConfigError },
    #[snafu(display("bare `~` requires an identity"))]
    BareTildeWithoutIdentity,
    #[snafu(display("failed to locate dhttp config"))]
    LocateDhttpConfig {
        source: config::LocateDhttpConfigError,
    },
    #[snafu(display("failed to load explicit identity `{name}`"))]
    LoadExplicitIdentity {
        name: Name<'static>,
        source: config::identity::ssl::LoadIdentityError,
    },
    #[snafu(display("identity `{id}` in ssh config is invalid"))]
    InvalidIdInSshConfig { id: String, source: InvalidName },
    #[snafu(display("failed to expand identity name in uri"))]
    ExpandNameInUri { source: dhttp::name::ExpandUriError },
    #[snafu(display("failed to parse identity name in uri"))]
    ExpandUriName {
        source: dhttp::name::InvalidDhttpName,
    },
    #[snafu(display("failed to parse expanded authority `{authority}`"))]
    ParseExpandedAuthority {
        authority: String,
        source: http::uri::InvalidUri,
    },
    #[snafu(display("failed to parse path and query `{path_and_query}`"))]
    InvalidPathAndQuery {
        path_and_query: String,
        source: http::uri::InvalidUri,
    },
    #[snafu(display("failed to construct uri from parts"))]
    ConstructUri { source: http::uri::InvalidUriParts },
}

#[derive(Debug)]
pub struct Config {
    pub binds: Vec<BindPattern>,
    pub dns: BTreeSet<ddns::DnsScheme>,
    pub username: String,
    pub uri: Uri,
    pub id: Option<IdentityConfig>,
    pub connect_timeout: Duration,
    pub local_forwards: Vec<LocalForward>,
    pub remote_forwards: Vec<RemoteForward>,
    pub dynamic_forwards: Vec<DynamicForward>,
}

fn expand_uri_without_identity(uri: Uri) -> Result<Uri, Error> {
    let Some(authority) = uri.authority() else {
        return Uri::from_parts(uri.into_parts()).context(config_error::ConstructUriSnafu);
    };
    ensure!(
        authority.host() != "~",
        config_error::BareTildeWithoutIdentitySnafu
    );

    DhttpName::expand_uri_with_base(None, uri).context(config_error::ExpandNameInUriSnafu)
}

fn expand_uri(uri: Uri, self_name: Option<&Name<'_>>) -> Result<Uri, Error> {
    match self_name {
        Some(name) => name
            .expand_uri(uri)
            .context(config_error::ExpandNameInUriSnafu),
        None => expand_uri_without_identity(uri),
    }
}

async fn load_identity_config(
    options: &super::Options,
    ssh_config_id_name: Option<Name<'static>>,
) -> Result<Option<IdentityConfig>, Error> {
    if options.anonymous {
        return Ok(None);
    }

    let explicit = options
        .id
        .clone()
        .map(|name| ("command line options", name))
        .or_else(|| ssh_config_id_name.map(|name| ("ssh config", name)));

    let home = match DhttpConfig::load_from_environment() {
        Ok(home) => home,
        Err(source) if explicit.is_none() => {
            tracing::warn!(
                error = %snafu::Report::from_error(&source),
                "failed to locate dhttp config, using anonymous endpoint"
            );
            return Ok(None);
        }
        Err(source) => return Err(config_error::LocateDhttpConfigSnafu.into_error(source)),
    };

    if let Some((source_name, name)) = explicit {
        tracing::debug!(%name, source = source_name, "trying to load explicit identity");
        return home
            .load_identity(name.clone())
            .await
            .context(config_error::LoadExplicitIdentitySnafu { name })
            .map(Some);
    }

    match home.load_default_identity().await {
        Ok(identity) => {
            tracing::debug!(name = %identity.name(), "using default identity");
            Ok(Some(identity))
        }
        Err(source) => {
            tracing::debug!(
                error = %snafu::Report::from_error(&source),
                "failed to load default identity, using anonymous endpoint"
            );
            Ok(None)
        }
    }
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
            tracing::debug!("user not found in ssh_config, trying to parse from hostname");
            username = parse_username_from_uri(&uri);
        }

        let username = match username {
            Some(username) => username,
            None => {
                tracing::debug!("user not found in URI, using current user");
                whoami::username().unwrap_or_else(|_| "unknown".to_string())
            }
        };

        // Parse ssh_config identity for identity loading below.
        let ssh_config_id_name: Option<Name<'static>> = ssh_config
            .id
            .as_ref()
            .map(|id| Name::from_str(id).context(config_error::InvalidIdInSshConfigSnafu { id }))
            .transpose()?;

        let id = load_identity_config(self, ssh_config_id_name).await?;

        // Expand ~ in URI using loaded identity (--id > ssh_config > default identity)
        let uri = expand_uri(uri, id.as_ref().map(|id| id.name()))?;

        let uri = complete_uri(uri, &username)?;

        let connect_timeout = ssh_config.connect_timeout.unwrap_or(Duration::MAX);

        // Merge forwarding rules: CLI args take precedence, then ssh config.
        let mut local_forwards = self.local_forwards.clone();
        local_forwards.extend(ssh_config.local_forwards);
        let mut remote_forwards = self.remote_forwards.clone();
        remote_forwards.extend(ssh_config.remote_forwards);
        let mut dynamic_forwards = self.dynamic_forward.clone();
        dynamic_forwards.extend(ssh_config.dynamic_forwards);

        Ok(Config {
            binds: self.binds.clone(),
            dns: self.dns.iter().cloned().collect(),
            username,
            uri,
            id,
            connect_timeout,
            local_forwards,
            remote_forwards,
            dynamic_forwards,
        })
    }
}

fn parse_username_from_uri(uri: &Uri) -> Option<String> {
    uri.authority()
        .and_then(|authority| authority.as_str().rsplit_once('@'))
        .map(|(userinfo, _host)| {
            // Strip password portion if present (user:pass@host)
            userinfo
                .split_once(':')
                .map_or(userinfo, |(user, _)| user)
                .to_string()
        })
}

fn complete_uri(uri: Uri, username: &str) -> Result<Uri, Error> {
    let mut uri_parts = uri.into_parts();
    uri_parts.scheme = match uri_parts.scheme {
        Some(ref scheme) if scheme.as_str() == "https" => uri_parts.scheme,
        None => Some(http::uri::Scheme::HTTPS),
        Some(scheme) => {
            return Err(config_error::UnsupportedSchemeSnafu {
                scheme: scheme.to_string(),
            }
            .build());
        }
    };
    uri_parts.path_and_query = match uri_parts.path_and_query {
        root if root.as_ref().is_none_or(|path| path == "/") => {
            tracing::debug!("path is empty, using `/ssh` as default");
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
