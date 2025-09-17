use genmeta_common::id::expand_id;
use http::Uri;
use snafu::{IntoError, ResultExt, Snafu};
use ssh_config::{error::ReadConfigError, genmeta::Profile};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to parse authority '{authority}' as URI authority"))]
    AuthorityParse {
        authority: String,
        source: http::uri::InvalidUri,
    },

    #[snafu(display("Unsupported URI scheme '{scheme}', only 'ssh3' is supported"))]
    UnsupportedScheme { scheme: String },

    #[snafu(display("Missing authority in URI"))]
    MissingAuthority {},

    #[snafu(display("Failed to read profile for `{id}`"))]
    ReadProfile { id: String, source: ReadConfigError },
}

// 为主 Error 提供 From 转换
impl From<Error> for crate::error::Error {
    fn from(err: Error) -> Self {
        crate::error::ConfigSnafu {}.into_error(err)
    }
}

#[derive(Debug)]
pub struct Config {
    pub username: String,
    pub password: Option<String>,
    pub uri: Uri,
    pub profile: Option<Profile>,
}

// Host Xxx > Host.XXX > Host.HostName xxx
// HostName可以提供Uri的host部分
impl super::Options {
    pub async fn config(&self) -> Result<Config, Error> {
        let (host, read_config_errors) =
            ssh_config::openssh::read_config(&self.uri.to_string()).await;

        for (message, error) in read_config_errors {
            tracing::error!(target: "config", "{message}: {error}", );
        }

        // user: command line -> config file -> uri -> whoami
        let mut username = self.login_name.clone().or_else(|| host.user.clone());
        let mut password = None;

        // uri: ssh_config(if present) -> command line
        let uri = match host.hostname {
            Some(uri) => uri,
            None => self.uri.clone(),
        };

        if username.is_none() {
            tracing::debug!(target: "config", "User not found in ssh_config, Try parse it from hostname");
            (username, password) = parse_username_password_from_uri(&uri);
        }

        let (username, password) = match username {
            Some(username) => (username, password),
            None => (whoami::username(), None),
        };

        let uri = complete_uri(uri, &username)?;

        let profile = match &self.id {
            Some(id) => Some(
                ssh_config::genmeta::read_config(id, None)
                    .await
                    .context(ReadProfileSnafu { id })?,
            ),
            None => None,
        };

        Ok(Config {
            username,
            password,
            uri,
            profile,
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
            let host = expand_id(authority.host());
            Some(
                host.parse()
                    .context(AuthorityParseSnafu { authority: host })?,
            )
        }
        None => return Err(MissingAuthoritySnafu {}.build()),
    };

    Ok(Uri::from_parts(uri_parts).expect("Failed to construct URI from parts"))
}
