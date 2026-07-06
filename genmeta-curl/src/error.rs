use std::{convert::Infallible, path::PathBuf};

use dhttp::{
    h3x::{
        dhttp::message::{InitialMessageStreamError, MessageStreamError},
        hyper::SendMessageError,
        quic,
    },
    home,
    name::DhttpName as Name,
};
use snafu::Snafu;
use tokio::io;

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("missing authority in uri"))]
    MissingAuthority {},

    #[snafu(display("failed to normalize dhttp uri"))]
    NormalizeUri {
        source: dhttp::message::IntoUriError,
    },

    #[snafu(display("failed to construct normalized request uri"))]
    ConstructRequestUri { source: http::uri::InvalidUriParts },

    #[snafu(display("failed to load dhttp home"))]
    LoadDhttpHome { source: home::LoadDhttpHomeError },

    #[snafu(display("failed to load explicit identity `{name}`"))]
    LoadExplicitIdentity {
        name: Name<'static>,
        source: dhttp::home::identity::ssl::ResolveIdentityProfileError,
    },

    #[snafu(display("failed to load identity certificate and key"))]
    LoadIdentitySsl {
        source: dhttp::home::identity::ssl::LoadIdentityError,
    },

    #[snafu(display("failed to build dhttp endpoint"))]
    BuildEndpoint {
        source: dhttp::endpoint::BuildEndpointError,
    },

    #[snafu(display("failed to connect to server"))]
    Connect {
        source: dhttp::endpoint::ConnectError,
    },

    #[snafu(display("connection timed out"))]
    Timedout {},

    #[snafu(display("failed to open request stream"))]
    InitialMessageStream { source: InitialMessageStreamError },

    #[snafu(display("failed to build HTTP request"))]
    BuildRequest { source: http::Error },

    #[snafu(display("failed to get HTTP/3 stream id"))]
    GetStreamId { source: quic::StreamError },

    #[snafu(display("failed to write verbose output"))]
    WriteVerbose { source: io::Error },

    #[snafu(display("failed to send HTTP request"))]
    SendRequest {
        source: SendMessageError<Infallible>,
    },

    #[snafu(display("failed to open file `{}` to upload", path.display()))]
    OpenUploadFile { path: PathBuf, source: io::Error },

    #[snafu(display("failed to upload file `{}` to server", path.display()))]
    UploadFile { path: PathBuf, source: io::Error },

    #[snafu(display("failed to close request stream"))]
    CloseRequestStream { source: MessageStreamError },

    #[snafu(display("failed to receive response"))]
    ReceiveResponse { source: MessageStreamError },

    #[snafu(display("failed to create output file"))]
    CreateOutputFile { source: io::Error },

    #[snafu(display("failed to read response body or write to output"))]
    ReadResponse { source: io::Error },

    #[snafu(display("failed to flush output"))]
    FlushOutput { source: io::Error },

    #[snafu(display("too many redirects"))]
    TooManyRedirects {},

    #[snafu(display("redirect location is missing or invalid"))]
    InvalidRedirectLocation { source: http::uri::InvalidUri },

    #[snafu(display("failed to parse redirect URL `{url}`"))]
    ParseRedirectUrl {
        url: String,
        source: url::ParseError,
    },
}

pub(crate) use error::*;

#[derive(Debug, Snafu)]
#[snafu(module(parse_header_error), visibility(pub(crate)))]
pub enum ParseHeaderError {
    #[snafu(display("missing header key in `{input}`"))]
    MissingKey { input: String },
    #[snafu(display("missing header value in `{input}`"))]
    MissingValue { input: String },
}
