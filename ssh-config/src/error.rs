use std::{borrow::Cow, io, path::PathBuf};

use peg::{error::ParseError, str::LineCol};

#[derive(snafu::Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum ParseConfigError {
    #[snafu(display("Too many values at {location}"))]
    TooManyArguments { location: LineCol },
    #[snafu(display("Cannot read file at `{}`: {source}", path.display()))]
    ReadAsset {
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(feature = "openssh")]
    #[snafu(display("Cannot parse URI at {location}: {source}"))]
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
    LocateConfig {
        message: String,
    },
    #[snafu(display("Cannot read config file at `{}`: {source}", path.display()))]
    ReadConfig {
        path: PathBuf,
        source: io::Error,
    },
    #[snafu(display("Cannot parse config file `{}`: {source}", path.display()))]
    LexConfig {
        path: PathBuf,
        source: ParseError<LineCol>,
    },
    #[snafu(display("Cannot parse config file `{}`: {source}", path.display()))]
    ParseConfig {
        path: PathBuf,
        source: ParseConfigError,
    },

    T,
}
