use std::{env, io::Cursor};

use http::Uri;
use ssh2_config::{ParseRule, SshConfig};
use tokio::fs;

use crate::Error;

pub struct Profile {
    pub user: String,
    pub password: Option<String>,
    pub uri: Uri,
}

fn username_password_from_uri(uri: &Uri) -> (Option<String>, Option<String>) {
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

// Host Xxx > Host.XXX > Host.HostName xxx
// HostName可以提供Uri的host部分
impl super::Options {
    pub async fn profile(&self) -> Result<Profile, Error> {
        let ssh_config = read_ssh_config().await?;
        let host_params = ssh_config.query(self.server.to_string());

        let mut user = host_params.user;
        let mut password = None;

        let uri = match host_params.host_name {
            Some(host_name) => host_name
                .parse::<Uri>()
                .map_err(|e| format!("Failed to parse host name '{host_name}' as URI: {e}"))?,
            None => self.server.clone(),
        };

        let mut uri_parts = uri.into_parts();

        if user.is_none() {
            (user, password) = username_password_from_uri(&self.server);
        }

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

        uri_parts.authority = uri_parts
            .authority
            .map(|authority| authority.host().parse().unwrap());

        let uri = Uri::from_parts(uri_parts).expect("Failed to construct URI from parts");

        if uri.host().is_none() {}

        let (user, password) = match user {
            Some(user) => (user, password),
            None => (whoami::username(), None),
        };

        Ok(Profile {
            user,
            password,
            uri,
        })
    }
}

pub async fn read_ssh_config() -> Result<SshConfig, Error> {
    let mut ssh_config = SshConfig::default();

    // Read the user-wide SSH configuration file.
    // This is typically located at /etc/ssh/ssh_config.
    if let Some(home) = env::var_os("HOME")
        && let Ok(content) =
            fs::read_to_string(format!("{}/.ssh/config", home.to_string_lossy())).await
    {
        ssh_config = ssh_config
            .parse(
                &mut Cursor::new(content),
                ParseRule::ALLOW_UNSUPPORTED_FIELDS | ParseRule::ALLOW_UNKNOWN_FIELDS,
            )
            .map_err(|e| format!("Failed to parse user-wide SSH config: {e}"))?;
    }

    // Read the system-wide SSH configuration file.
    // This is typically located at /etc/ssh/ssh_config.
    if let Ok(system_wide_content) = fs::read_to_string("/etc/ssh/ssh_config").await {
        ssh_config = ssh_config
            .parse(
                &mut Cursor::new(system_wide_content),
                ParseRule::ALLOW_UNSUPPORTED_FIELDS | ParseRule::ALLOW_UNKNOWN_FIELDS,
            )
            .map_err(|e| format!("Failed to parse system-wide SSH config: {e}"))?;
    }

    Ok(ssh_config)
}
