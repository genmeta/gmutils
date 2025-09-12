use std::{borrow::Cow, io, path::PathBuf};

use peg::{error::ParseError, str::LineCol};

#[derive(snafu::Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum ParseConfigError {
    #[snafu(display("Too many values at {location}"))]
    TooManyArguments { location: LineCol },
    #[snafu(display("Cannot read file `{}` which specified at {location}", path.display()))]
    ReadAssetFile {
        location: LineCol,
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(feature = "openssh")]
    #[snafu(display("Cannot parse URI at {location}"))]
    ParseUri {
        location: LineCol,
        source: <http::Uri as std::str::FromStr>::Err,
    },
    #[snafu(display("Missing parameter `{keyword}` for `{pattern}`"))]
    MissingParameter {
        pattern: String,
        keyword: Cow<'static, str>,
    },
}

#[derive(snafu::Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum ReadConfigError {
    #[snafu(display("Cannot locate config file: {message}"))]
    LocateConfigFile { message: String },
    #[snafu(display("Cannot read config file at `{}`", path.display()))]
    ReadConfigFile { path: PathBuf, source: io::Error },
    #[snafu(display("Cannot parse config file `{}`", path.display()))]
    LexConfig {
        path: PathBuf,
        source: ParseError<LineCol>,
    },
    #[snafu(display("Cannot parse config file `{}`", path.display()))]
    ParseConfig {
        path: PathBuf,
        source: ParseConfigError,
    },
}

#[derive(snafu::Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum CheckConfigError {
    #[snafu(display("Find unknown keyword `{keyword}` at {}:{location}", path.display()))]
    UnknownKeyword {
        keyword: String,
        path: PathBuf,
        location: LineCol,
    },
    #[snafu(transparent)]
    ReadConfig { source: ReadConfigError },
}
