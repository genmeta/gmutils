mod parser;

use std::env;

use http::Uri;
use parser::SshConfig;
use tokio::fs;

use crate::Error;

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
            Some(host_name) => host_name
                .parse::<Uri>()
                .map_err(|e| format!("Failed to parse host name '{host_name}' as URI: {e}"))?,
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
            let message = format!(
                "Unsupported scheme `{scheme}` for ssh. Scheme in uri is must not be present or be `ssh3`"
            );
            return Err(message.into());
        }
    };
    uri_parts.path_and_query = match uri_parts.path_and_query {
        root if root.as_ref().is_none_or(|path| path == "/") => {
            tracing::warn!(target: "connect", "Path is empty, using `/ssh` as default");
            Some("/ssh".parse().unwrap())
        }
        path_and_query => path_and_query,
    };

    uri_parts.authority =
        match uri_parts.authority {
            Some(authority) => {
                let host = authority.host().replacen("~", ".genmeta.net", 1);
                Some(host.parse().map_err(|e| {
                    format!("Failed to parse authority '{host}' as URI authority: {e}")
                })?)
            }
            None => return Err("Missing authority in URI".into()),
        };

    Ok(Uri::from_parts(uri_parts).expect("Failed to construct URI from parts"))
}

pub async fn ssh_config() -> Result<SshConfig, Error> {
    let mut ssh_config = SshConfig::default();

    // Read the user-wide SSH configuration file.
    // This is typically located at /etc/ssh/ssh_config.
    let read_user_config = async {
        let home = env::var_os("HOME")
            .ok_or("Failed to get HOME environment variable to locate user-wide SSH config file")?;
        fs::read_to_string(format!("{}/.ssh/config", home.to_string_lossy()))
            .await
            .map_err(|e| format!("{e:?}"))
    };

    match read_user_config.await {
        Ok(content) => {
            ssh_config += content
                .parse::<SshConfig>()
                .map_err(|e| format!("Failed to parse user-wide SSH config: {e}"))?;
        }
        Err(e) => {
            tracing::error!(target: "config", "Failed to read user-wide SSH config: {e:?}");
        }
    }

    // Read the system-wide SSH configuration file.
    // This is typically located at /etc/ssh/ssh_config.
    let read_system_config = async {
        fs::read_to_string("/etc/ssh/ssh_config")
            .await
            .map_err(|e| format!("{e:?}"))
    };

    match read_system_config.await {
        Ok(content) => {
            ssh_config += content
                .parse::<SshConfig>()
                .map_err(|e| format!("Failed to parse system-wide SSH config: {e}"))?;
        }
        Err(e) => {
            tracing::error!(target: "config", "Failed to read system-wide SSH config: {e:?}");
        }
    }

    Ok(ssh_config)
}
