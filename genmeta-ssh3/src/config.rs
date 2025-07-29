mod parser;

use std::env;

use http::Uri;
use parser::SshConfig;
use snafu::{Backtrace, ResultExt, Snafu};
use tokio::fs;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to parse URI '{uri}' from hostname"))]
    UriParse {
        uri: String,
        source: http::uri::InvalidUri,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to parse authority '{authority}' as URI authority"))]
    AuthorityParse {
        authority: String,
        source: http::uri::InvalidUri,
        backtrace: Backtrace,
    },

    #[snafu(display("Unsupported URI scheme '{scheme}', only 'ssh3' is supported"))]
    UnsupportedScheme {
        scheme: String,
        backtrace: Backtrace,
    },

    #[snafu(display("Missing authority in URI"))]
    MissingAuthority { backtrace: Backtrace },

    #[snafu(display("Failed to get HOME environment variable to locate SSH config"))]
    MissingHomeEnv { backtrace: Backtrace },

    #[snafu(display("Failed to read SSH config file '{path}'"))]
    ConfigFileRead {
        path: String,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to parse SSH config file '{path}'"))]
    ConfigFileParse {
        path: String,
        source: peg::error::ParseError<peg::str::LineCol>,
        backtrace: Backtrace,
    },
}

// 为主 Error 提供 From 转换
impl From<Error> for crate::error::Error {
    fn from(err: Error) -> Self {
        crate::error::Error::Config {
            source: err,
            backtrace: Backtrace::capture(),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub username: String,
    pub password: Option<String>,
    pub uri: Uri,
}

// Host Xxx > Host.XXX > Host.HostName xxx
// HostName可以提供Uri的host部分
impl super::Options {
    pub async fn config(&self) -> Result<Config, Error> {
        let ssh_config = ssh_config().await?;
        let host_params = ssh_config.query(&self.uri.to_string());

        // user: command line -> config file -> uri -> whoami
        let mut username = self
            .login_name
            .clone()
            .or_else(|| host_params.get("user").cloned());
        let mut password = None;

        // uri: ssh_config(if present) -> command line
        let uri = match host_params.get("hostname") {
            Some(host_name) => host_name.parse::<Uri>().context(UriParseSnafu {
                uri: host_name.clone(),
            })?,
            None => self.uri.clone(),
        };

        if username.is_none() {
            tracing::debug!(target: "config", "User not found in ssh_config, Try parse it from hostname");
            (username, password) = parse_username_password_from_uri(&uri);
        }

        let uri = complete_uri(uri)?;

        let (username, password) = match username {
            Some(username) => (username, password),
            None => (whoami::username(), None),
        };

        Ok(Config {
            username,
            password,
            uri,
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

fn complete_uri(uri: Uri) -> Result<Uri, Error> {
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
            tracing::warn!(target: "connect", "Path is empty, using `/ssh` as default");
            Some("/ssh".parse().unwrap())
        }
        path_and_query => path_and_query,
    };

    uri_parts.authority = match uri_parts.authority {
        Some(authority) => {
            let host = authority.host().replacen("~", ".genmeta.net", 1);
            Some(host.parse().context(AuthorityParseSnafu {
                authority: host.clone(),
            })?)
        }
        None => return Err(MissingAuthoritySnafu {}.build()),
    };

    Ok(Uri::from_parts(uri_parts).expect("Failed to construct URI from parts"))
}

pub async fn ssh_config() -> Result<SshConfig, Error> {
    let mut ssh_config = SshConfig::default();

    // Read the user-wide SSH configuration file.
    // This is typically located at /etc/ssh/ssh_config.
    let read_user_config = async {
        let home = env::var_os("HOME").ok_or_else(|| MissingHomeEnvSnafu {}.build())?;
        let path = format!("{}/.ssh/config", home.to_string_lossy());
        fs::read_to_string(&path)
            .await
            .context(ConfigFileReadSnafu { path })
    };

    match read_user_config.await {
        Ok(content) => {
            let path = "user SSH config".to_string();
            ssh_config += content
                .parse::<SshConfig>()
                .context(ConfigFileParseSnafu { path })?;
        }
        Err(e) => {
            tracing::error!(target: "config", "Failed to read user-wide SSH config: {e:?}");
        }
    }

    // Read the system-wide SSH configuration file.
    // This is typically located at /etc/ssh/ssh_config.
    let read_system_config = async {
        let path = "/etc/ssh/ssh_config".to_string();
        fs::read_to_string(&path)
            .await
            .context(ConfigFileReadSnafu { path })
    };

    match read_system_config.await {
        Ok(content) => {
            let path = "system SSH config".to_string();
            ssh_config += content
                .parse::<SshConfig>()
                .context(ConfigFileParseSnafu { path })?;
        }
        Err(e) => {
            tracing::error!(target: "config", "Failed to read system-wide SSH config: {e:?}");
        }
    }

    Ok(ssh_config)
}
