use std::path::PathBuf;

use clap::Parser;
use dhttp::{
    ddns::resolvers::DnsScheme, dquic::binds::BindPattern, home, name::DhttpName as Name,
};
use http::{Method, Uri};
use snafu::OptionExt;

use crate::error::{ParseHeaderError, parse_header_error};

/// Maximum number of redirects to follow (same default as curl since 8.3.0)
pub(crate) const MAX_REDIRS_DEFAULT: u32 = 30;
pub(crate) const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Supported content encodings for --compressed
pub(crate) const ACCEPT_ENCODING: &str = "deflate, gzip, zstd";

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    /// URL to request
    pub(crate) uri: Uri,

    /// Specify request method to use
    #[arg(short = 'X', long)]
    pub(crate) request: Option<Method>,

    /// Send data in a POST request
    #[arg(short, long, conflicts_with("upload_file"))]
    pub(crate) data: Option<String>,

    /// Transfer local file to destination
    #[arg(short = 'T', long, conflicts_with("data"))]
    pub(crate) upload_file: Option<PathBuf>,

    /// Pass custom header(s) to server
    #[arg(short = 'H', long, value_parser = parse_header)]
    pub(crate) header: Vec<(String, String)>,

    /// Follow redirects
    #[arg(short = 'L', long)]
    pub(crate) location: bool,

    /// Maximum number of redirects to follow
    #[arg(long, default_value_t = MAX_REDIRS_DEFAULT)]
    pub(crate) max_redirs: u32,

    /// Write output to file instead of stdout
    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,

    /// Define output format for response metadata
    ///
    /// Supported: %{response_code}, %{http_code}, %{url}, %{method},
    /// %{scheme}, %{http_version}, %{time_total}, %{time_connect},
    /// %{time_starttransfer}, %{size_download}, %{header{name}}
    #[arg(short = 'w', long = "write-out")]
    pub(crate) write_out: Option<String>,

    /// Request compressed response and decompress it
    #[arg(long)]
    pub(crate) compressed: bool,

    /// Disable content decoding; pass raw bytes through
    #[arg(long, conflicts_with("compressed"))]
    pub(crate) raw: bool,

    /// Maximum time allowed for connection in seconds
    ///
    /// Use 0 to disable the timeout.
    #[arg(long, default_value_t = DEFAULT_CONNECT_TIMEOUT_SECS)]
    pub(crate) connect_timeout: u64,

    /// Client identity for DHTTP/3 connections
    #[arg(short, long, value_name = "client_identity")]
    pub(crate) id: Option<Name<'static>>,

    /// Use the global dhttp home instead of the default user home
    #[arg(long)]
    pub(crate) global: bool,

    /// Skip identity loading and use anonymous mode
    #[arg(long, conflicts_with = "id")]
    pub(crate) anonymous: bool,

    /// Resolve names to IPv4 addresses only
    #[arg(short = '4', long = "ipv4")]
    pub(crate) ipv4: bool,

    /// Resolve names to IPv6 addresses only
    #[arg(short = '6', long = "ipv6")]
    pub(crate) ipv6: bool,

    /// DNS resolution schemes
    #[arg(long, value_name = "scheme", default_value = "mdns,h3", value_delimiter = ',', hide = cfg!(not(debug_assertions)))]
    pub(crate) dns: Vec<DnsScheme>,

    /// Bind patterns for DHTTP/3 connections
    #[arg(long = "interface", value_name = "bind", default_value = "*", hide = cfg!(not(debug_assertions)))]
    pub(crate) binds: Vec<BindPattern>,

    /// Make the operation more talkative
    #[arg(short, long)]
    pub(crate) verbose: bool,

    /// Suppress progress and error messages
    #[arg(short = 's', long)]
    pub(crate) silent: bool,

    /// Show error messages even when --silent is active
    #[arg(short = 'S', long = "show-error")]
    pub(crate) show_error: bool,
}

impl Options {
    pub(crate) fn home_scope(&self) -> home::HomeScope {
        if self.global {
            home::HomeScope::Global
        } else {
            home::HomeScope::User
        }
    }
}

fn parse_header(s: &str) -> Result<(String, String), ParseHeaderError> {
    let mut parts = s.splitn(2, ':');
    let key = parts
        .next()
        .context(parse_header_error::MissingKeySnafu { input: s })?
        .trim()
        .to_string();
    let value = parts
        .next()
        .context(parse_header_error::MissingValueSnafu { input: s })?
        .trim()
        .to_string();
    Ok((key, value))
}
