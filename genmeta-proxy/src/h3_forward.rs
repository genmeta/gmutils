use h3x::{
    dquic::H3Client,
    message::stream::{MessageStreamError, WriteStream},
};
use http::uri::{self, Uri};
use hyper::{
    Request, Response,
    body::{Body, Incoming},
    header,
};
use snafu::ResultExt;

use crate::Error;

/// Hop-by-hop headers that MUST NOT be forwarded to HTTP/3 (RFC 9110 §7.6.1,
/// RFC 9114 §4.2).
const HOP_BY_HOP_HEADERS: &[header::HeaderName] = &[
    header::CONNECTION,
    header::TRANSFER_ENCODING,
    header::TE,
    header::UPGRADE,
    header::HOST,
    // keep-alive and proxy-connection are not constants in http crate
];

/// Rewrite an HTTP/1.1 proxy request for forwarding over HTTP/3.
///
/// - Changes the URI scheme from `http` to `https` (HTTP/3 mandates TLS).
/// - Strips hop-by-hop headers that are illegal in HTTP/3.
fn rewrite_request_for_h3(mut req: Request<Incoming>) -> Request<Incoming> {
    // Rewrite URI scheme: http → https
    let uri = req.uri().clone();
    let mut parts = uri.into_parts();
    parts.scheme = Some(uri::Scheme::HTTPS);
    if let Ok(new_uri) = Uri::from_parts(parts) {
        *req.uri_mut() = new_uri;
    }

    // Strip hop-by-hop headers
    let headers = req.headers_mut();
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
    headers.remove("proxy-connection");
    headers.remove("keep-alive");

    req
}

/// Close the write stream after request is fully sent.
///
/// Failure to close is non-fatal — the response may already be readable.
async fn close_write_stream(mut write_stream: WriteStream) {
    if let Err(e) = write_stream.close().await {
        tracing::warn!(error = %e, "failed to close h3 request stream");
    }
}

/// Forward a plain HTTP request to a genmeta domain via DHTTP/3.
pub async fn forward_h3(
    req: Request<Incoming>,
    client: &H3Client,
) -> Result<Response<impl Body<Data = bytes::Bytes, Error = MessageStreamError> + use<>>, Error> {
    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| {
            <Error as snafu::FromString>::without_source(
                "missing authority in DHTTP/3 request URI".to_string(),
            )
        })?
        .clone();

    let connection = client
        .connect(authority.clone())
        .await
        .whatever_context::<_, Error>(format!(
            "failed to connect to DHTTP/3 server `{authority}`"
        ))?;

    let (mut read_stream, mut write_stream) = connection
        .initial_message_stream()
        .await
        .whatever_context::<_, Error>("failed to open h3 message stream")?;

    let req = rewrite_request_for_h3(req);

    write_stream
        .send_hyper_request(req)
        .await
        .whatever_context::<_, Error>("failed to send h3 request")?;

    // Read response headers and close write stream concurrently.
    // tokio::join! polls the first future first (biased toward response).
    let (response_result, _) = tokio::join!(
        async {
            let mut parts = read_stream
                .read_hyper_response_parts()
                .await
                .whatever_context::<_, Error>("failed to read h3 response")?;
            while parts.status.is_informational() {
                tracing::debug!(status = %parts.status, "skipping informational response");
                parts = read_stream
                    .read_hyper_response_parts()
                    .await
                    .whatever_context::<_, Error>("failed to read h3 response")?;
            }
            Ok::<_, Error>(parts)
        },
        close_write_stream(write_stream),
    );

    let response_parts = response_result?;
    let body = read_stream.into_hyper_body();
    Ok(Response::from_parts(response_parts, body))
}
