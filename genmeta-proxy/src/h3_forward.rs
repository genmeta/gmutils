use http::uri::{self, Uri};
use http_body_util::BodyExt;
use hyper::{Request, Response, body::Incoming, header};
use snafu::ResultExt;
use tokio::io::AsyncWriteExt;

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

/// Forward a request while polling the upstream response concurrently with upload.
pub async fn forward_h3(
    req: Request<Incoming>,
    client: &genmeta_network::Client,
) -> Result<Response<ForwardBody>, Error> {
    let req = rewrite_request_for_h3(req);
    let (mut parts, mut body) = req.into_parts();
    parts.version = http::Version::HTTP_3;
    let request = Request::from_parts(parts, dhttp::WndBuf::new(64 * 1024));
    let (mut writer, response) = client
        .from_request(request)
        .await
        .whatever_context::<_, Error>("failed to open DHTTP request")?;
    let mut upload = tokio::spawn(async move {
        while let Some(frame) = body.frame().await {
            let frame = frame.whatever_context::<_, Error>("failed to read proxy request body")?;
            match frame.into_data() {
                Ok(data) => writer
                    .write_all(&data)
                    .await
                    .whatever_context::<_, Error>("failed to upload proxy request body")?,
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        for (name, value) in &trailers {
                            writer
                                .append_trailer(name.clone(), value.clone())
                                .whatever_context::<_, Error>(
                                    "failed to set proxy request trailer",
                                )?;
                        }
                    }
                }
            }
        }
        writer
            .shutdown()
            .await
            .whatever_context::<_, Error>("failed to finish proxy request body")
    });
    let mut response = std::pin::pin!(response);
    let (response_result, upload_pending) = tokio::select! {
        biased;
        response = &mut response => (response.whatever_context::<_, Error>("failed to receive DHTTP response"), true),
        uploaded = &mut upload => {
            let result = match uploaded {
                Ok(Ok(())) => response.await.whatever_context::<_, Error>("failed to receive DHTTP response"),
                Ok(Err(error)) => Err(error),
                Err(error) => Err(<Error as snafu::FromString>::without_source(format!("DHTTP upload task failed: {error}"))),
            };
            (result, false)
        }
    };
    let response = match response_result {
        Ok(response) => response,
        Err(error) => {
            upload.abort();
            return Err(error);
        }
    };
    let require_upload = response.status().is_success();
    let mut response = response.map(|body| ForwardBody {
        body,
        upload: upload_pending.then_some(upload),
        require_upload,
    });
    *response.version_mut() = http::Version::HTTP_11;
    Ok(response)
}

/// Keep uploading while hyper drains the response; dropping the response cancels upload.
pub struct ForwardBody {
    body: dhttp::Body,
    upload: Option<tokio::task::JoinHandle<Result<(), Error>>>,
    require_upload: bool,
}
impl Drop for ForwardBody {
    fn drop(&mut self) {
        if let Some(upload) = &self.upload {
            upload.abort();
        }
    }
}
impl hyper::body::Body for ForwardBody {
    type Data = bytes::Bytes;
    type Error = dhttp::BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::{future::Future, task::Poll};
        if let Some(upload) = &mut self.upload
            && let Poll::Ready(result) = std::pin::Pin::new(upload).poll(cx)
        {
            self.upload = None;
            let failure = match result {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(std::io::Error::other(error.to_string())),
                Err(error) => Some(std::io::Error::other(error)),
            };
            if let Some(error) = failure {
                if self.require_upload {
                    return Poll::Ready(Some(Err(Box::new(error))));
                }
                tracing::debug!(%error, "upstream rejected proxy upload");
            }
        }
        std::pin::Pin::new(&mut self.body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropping_response_cancels_blocked_proxy_upload() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        struct Guard(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }
        let upload = tokio::spawn(async move {
            let _guard = Guard(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<Result<(), Error>>().await
        });
        started_rx.await.unwrap();
        let body = http_body_util::Empty::new()
            .map_err(|never| match never {})
            .boxed_unsync();
        drop(ForwardBody {
            body,
            upload: Some(upload),
            require_upload: true,
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .unwrap();
    }
}
