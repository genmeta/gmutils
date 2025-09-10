use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

use snafu::{OptionExt, ResultExt};
use tokio::fs;

use crate::{
    ast::{ConfigFile, IStr},
    error::*,
};

#[derive(Debug, Clone)]
pub struct Profile {
    pub id: String,
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
}

pub fn user_config_file_path() -> Option<PathBuf> {
    dirs::config_dir().map(|mut path| {
        path.push("genmeta");
        path.push("profile");
        path
    })
}

pub async fn read_config(id: &str, path: Option<&Path>) -> Result<Profile, ReadConfigError> {
    let user_config_file_path = user_config_file_path();
    let path = path
        .or(user_config_file_path.as_deref())
        .context(LocateConfigSnafu {
            message: "Cannot locate user's config directory",
        })?;

    let data = fs::read_to_string(path)
        .await
        .context(ReadConfigSnafu { path })?;
    let config = ConfigFile::new(&data).context(LexConfigSnafu { path })?;

    let map = config.query(&[IStr::new("Id")], id);

    let key = match map.get(&IStr::new("key")).map(|(l, v)| (l, v.as_slice())) {
        Some((&_loc, [value])) => fs::read(value.deref()).await.context(ReadAssetSnafu {
            path: value.deref(),
        }),
        Some((&loc, ..)) => TooManyArgumentsSnafu { location: loc }.fail(),
        None => MissingParameterSnafu {
            pattern: id,
            keyword: "key",
        }
        .fail(),
    }
    .context(ParseConfigSnafu { path })?;

    let cert = match map.get(&IStr::new("cert")).map(|(l, v)| (l, v.as_slice())) {
        Some((&_loc, [value])) => fs::read(value.deref()).await.context(ReadAssetSnafu {
            path: value.deref(),
        }),
        Some((&loc, ..)) => TooManyArgumentsSnafu { location: loc }.fail(),
        None => MissingParameterSnafu {
            pattern: id,
            keyword: "cert",
        }
        .fail(),
    }
    .context(ParseConfigSnafu { path })?;

    Ok(Profile {
        id: id.to_string(),
        key,
        cert,
    })
}
