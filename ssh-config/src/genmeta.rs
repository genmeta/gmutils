use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

use peg::str::LineCol;
use snafu::{OptionExt, ResultExt};
use tokio::fs;

use crate::{
    ast::{ConfigFile, IStr, Pair, PositionedToken},
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

pub mod keywords {
    use super::*;

    pub const ID: IStr<&str> = IStr::new("id");
    pub const MATCHERS: &[IStr<&str>] = &[ID];
    pub const KEY: IStr<&str> = IStr::new("key");
    pub const CERT: IStr<&str> = IStr::new("cert");
}

pub fn path_argument_parser<'c, A: AsRef<[PositionedToken<&'c str>]>>(
    keyword: IStr<&'static str>,
) -> impl AsyncFn(&str, Option<&(LineCol, A)>) -> Result<Vec<u8>, ParseConfigError> {
    async move |pattern, arguments: Option<&(LineCol, A)>| match arguments
        .map(|(loc, args)| (loc, args.as_ref()))
    {
        Some((&location, [argument])) => {
            fs::read(argument.deref())
                .await
                .context(ReadAssetFileSnafu {
                    location,
                    path: argument.deref(),
                })
        }
        Some((&loc, ..)) => TooManyArgumentsSnafu { location: loc }.fail(),
        None => MissingParameterSnafu { pattern, keyword }.fail(),
    }
}

async fn parse_key(
    id: &str,
    arguments: Option<&(LineCol, impl AsRef<[PositionedToken<&str>]>)>,
) -> Result<Vec<u8>, ParseConfigError> {
    path_argument_parser(keywords::KEY)(id, arguments).await
}

async fn parse_cert(
    id: &str,
    arguments: Option<&(LineCol, impl AsRef<[PositionedToken<&str>]>)>,
) -> Result<Vec<u8>, ParseConfigError> {
    path_argument_parser(keywords::CERT)(id, arguments).await
}

async fn parse_config(id: &str, path: &Path, data: String) -> Result<Profile, ReadConfigError> {
    let config = ConfigFile::new(&data).context(LexConfigSnafu { path })?;

    let map = config.query(keywords::MATCHERS, id);

    let key = parse_key(id, map.get(&keywords::KEY))
        .await
        .context(ParseConfigSnafu { path })?;

    let cert = parse_cert(id, map.get(&keywords::CERT))
        .await
        .context(ParseConfigSnafu { path })?;

    Ok(Profile {
        id: id.to_string(),
        key,
        cert,
    })
}

pub async fn read_config(id: &str, path: Option<&Path>) -> Result<Profile, ReadConfigError> {
    let user_config_file_path = user_config_file_path();
    let path = path
        .or(user_config_file_path.as_deref())
        .context(LocateConfigFileSnafu {
            message: "Cannot locate user's config directory",
        })?;

    let data = fs::read_to_string(path)
        .await
        .context(ReadConfigFileSnafu { path })?;
    parse_config(id, path, data).await
}

pub async fn check_config(path: Option<&Path>) -> Result<(), CheckConfigError> {
    let user_config_file_path = user_config_file_path();
    let path = path
        .or(user_config_file_path.as_deref())
        .context(LocateConfigFileSnafu {
            message: "Cannot locate user's config directory",
        })?;

    let data = fs::read_to_string(path)
        .await
        .context(ReadConfigFileSnafu { path })?;
    let config = ConfigFile::new(&data).context(LexConfigSnafu { path })?;

    for Pair { keyword, arguments } in config.pairs() {
        let location = config.locate(keyword);
        let arguments = Some((location, arguments));
        match keyword.deref() {
            keyword if keyword == &keywords::KEY => {
                parse_key("", arguments.as_ref()).await.map(|_| ())
            }
            keyword if keyword == &keywords::CERT => {
                parse_cert("", arguments.as_ref()).await.map(|_| ())
            }
            keyword if keywords::MATCHERS.contains(keyword) => Ok(()),
            _ => {
                return UnknownKeywordSnafu {
                    keyword: keyword.to_string(),
                    path,
                    location,
                }
                .fail();
            }
        }
        .context(ParseConfigSnafu { path })?;
    }

    Ok(())
}
