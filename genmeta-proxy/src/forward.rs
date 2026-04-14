use hyper::{Request, Response, body::Incoming};
use hyper_util::rt::TokioIo;
use snafu::ResultExt;
use tokio::net::TcpStream;
use tracing::Instrument as _;

use crate::{
    Error, ForwardConnectSnafu, ForwardHandshakeSnafu, ForwardInvalidHostSnafu,
    ForwardMissingHostSnafu, ForwardSendRequestSnafu,
};

/// Forward a plain HTTP/1.1 request to its target host.
///
/// The target host is extracted from the request URI authority, falling back
/// to the `Host` header. Port defaults to 80 if not specified.
pub async fn forward_http(req: Request<Incoming>) -> Result<Response<Incoming>, Error> {
    // Extract host from URI authority or Host header
    let host_port = if let Some(authority) = req.uri().authority() {
        authority.to_string()
    } else if let Some(host_header) = req.headers().get(http::header::HOST) {
        host_header
            .to_str()
            .context(ForwardInvalidHostSnafu)?
            .to_string()
    } else {
        return ForwardMissingHostSnafu.fail();
    };

    // Default to port 80 if no port specified
    let addr = if host_port.contains(':') {
        host_port
    } else {
        format!("{}:80", host_port)
    };

    let stream = TcpStream::connect(&addr)
        .await
        .context(ForwardConnectSnafu { addr: addr.clone() })?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context(ForwardHandshakeSnafu { addr: addr.clone() })?;

    // Terminates when the HTTP/1.1 connection closes.
    tokio::spawn(conn.in_current_span());

    let resp = sender
        .send_request(req)
        .await
        .context(ForwardSendRequestSnafu)?;

    Ok(resp)
}
