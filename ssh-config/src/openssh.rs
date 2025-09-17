use std::path::{Path, PathBuf};

use genmeta_common::id::ClientName;
use http::Uri;
use snafu::{OptionExt, ResultExt};
use tokio::fs;

use crate::{
    ast::{self, IStr},
    error::*,
    pattern::SinglePattern,
};

pub fn user_config_file_path() -> Option<PathBuf> {
    dirs::home_dir().map(|mut path| {
        path.push(".ssh");
        path.push("config");
        path
    })
}

pub fn system_config_file_path() -> Option<PathBuf> {
    #[cfg(unix)]
    return Some(PathBuf::from("/etc/ssh/ssh_config"));
    #[cfg(not(unix))]
    return None;
}

#[derive(Debug, Clone)]
pub struct Host {
    pub user: Option<String>,
    pub hostname: Option<Uri>,
    pub id: Option<ClientName>,
}

pub async fn read_config(host: &str) -> (Host, Vec<(&'static str, ReadConfigError)>) {
    let mut result = Host {
        user: None,
        hostname: None,
        id: None,
    };

    let mut errors = Vec::new();

    let mut parse_config = async |path: &Path| {
        let data = fs::read_to_string(path)
            .await
            .context(ReadConfigFileSnafu { path })?;

        let config_file = ast::ConfigFile::new(&data).context(LexConfigSnafu { path })?;

        let map = config_file.query(&[IStr::new("Host"), IStr::new("Match")], host, |pat| {
            SinglePattern::new(pat.to_string())
        });

        if result.hostname.is_none() {
            result.hostname = match map
                .get(&IStr::new("hostname"))
                .map(|(l, v)| (l, v.as_slice()))
            {
                Some((&loc, [value])) => value
                    .parse()
                    .context(ParseUriSnafu { location: loc })
                    .map(Some),
                Some((&loc, ..)) => TooManyArgumentsSnafu { location: loc }.fail(),
                None => Ok(None),
            }
            .context(ParseConfigSnafu { path })?;
        }

        if result.user.is_none() {
            result.user = match map.get(&IStr::new("user")).map(|(l, v)| (l, v.as_slice())) {
                Some((&_loc, [value])) => Ok(Some(value.to_string())),
                Some((&loc, ..)) => TooManyArgumentsSnafu { location: loc }.fail(),
                None => Ok(None),
            }
            .context(ParseConfigSnafu { path })?;
        }

        if result.id.is_none() {
            result.id = match map.get(&IStr::new("id")).map(|(l, v)| (l, v.as_slice())) {
                Some((&_loc, [value])) => Ok(Some(value.parse().unwrap())),
                Some((&loc, ..)) => TooManyArgumentsSnafu { location: loc }.fail(),
                None => Ok(None),
            }
            .context(ParseConfigSnafu { path })?;
        }

        Ok(())
    };

    let read_user_config = async {
        let message = "Cannot locate home directory to locate user's openssh configuration file (usually ~/.ssh/config)";
        let path = user_config_file_path().context(LocateConfigFileSnafu { message })?;

        parse_config(&path).await
    };

    if let Err(error) = read_user_config.await {
        errors.push(("Cannot read user ssh configuration", error));
    }

    let read_system_config = async {
        let message =
            "Cannot locate system-wide openssh configuration file (usually /etc/ssh/ssh_config)";
        let path = system_config_file_path().context(LocateConfigFileSnafu { message })?;

        parse_config(&path).await
    };

    if let Err(error) = read_system_config.await {
        errors.push(("Cannot read system ssh configuration", error));
        // errors.push(error);
    }

    (result, errors)
}
