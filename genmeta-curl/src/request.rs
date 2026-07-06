use std::{path::PathBuf, pin::pin};

use dhttp::h3x::dhttp::message::MessageWriter;
use http::{HeaderName, HeaderValue, Method, Request, Uri, header::USER_AGENT};
use snafu::ResultExt;
use tokio::{
    fs,
    io::{self, AsyncWriteExt},
};

use crate::{
    cli::{ACCEPT_ENCODING, Options},
    error::{self, Error},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RequestBody {
    Empty,
    Data(String),
    UploadFile(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrderedHeader {
    name: HeaderName,
    value: HeaderValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct OrderedHeaders(Vec<OrderedHeader>);

impl OrderedHeaders {
    pub(crate) fn push(&mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) {
        self.0.push(OrderedHeader {
            name: name.into(),
            value: value.into(),
        });
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.0.iter().map(|h| (&h.name, &h.value))
    }

    fn apply_to_builder(&self, mut builder: http::request::Builder) -> http::request::Builder {
        for (name, value) in self.iter() {
            builder = builder.header(name, value);
        }
        builder
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RequestPlan {
    pub(crate) uri: Uri,
    pub(crate) method: Method,
    pub(crate) headers: OrderedHeaders,
    pub(crate) body: RequestBody,
}

impl RequestPlan {
    pub(crate) fn initial(options: &Options) -> Self {
        let body = if let Some(data) = &options.data {
            RequestBody::Data(data.clone())
        } else if let Some(path) = &options.upload_file {
            RequestBody::UploadFile(path.clone())
        } else {
            RequestBody::Empty
        };
        let method = Self::effective_method(options.request.clone(), &body);
        let mut headers = OrderedHeaders::default();
        headers.push(
            USER_AGENT,
            HeaderValue::from_str(&format!("genmeta-curl/{}", env!("CARGO_PKG_VERSION")))
                .expect("static user-agent is valid"),
        );
        headers.push(http::header::ACCEPT, HeaderValue::from_static("*/*"));
        if options.compressed && !options.raw {
            headers.push(
                http::header::ACCEPT_ENCODING,
                HeaderValue::from_static(ACCEPT_ENCODING),
            );
        }
        for (name, value) in &options.header {
            let name = HeaderName::from_bytes(name.as_bytes()).expect("clap accepted header name");
            let value = HeaderValue::from_str(value).expect("clap accepted header value");
            headers.push(name, value);
        }
        Self {
            uri: options.uri.clone(),
            method,
            headers,
            body,
        }
    }

    pub(crate) fn effective_method(request: Option<Method>, body: &RequestBody) -> Method {
        request.unwrap_or_else(|| match body {
            RequestBody::Empty => Method::GET,
            RequestBody::Data(_) => Method::POST,
            RequestBody::UploadFile(_) => Method::PUT,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn request_target(uri: &Uri) -> String {
        uri.path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    }


    pub(crate) fn for_redirect(&self, target: crate::redirect::RedirectTarget) -> Self {
        let body = if target.switched_to_get {
            RequestBody::Empty
        } else {
            self.body.clone()
        };
        Self {
            uri: target.uri,
            method: target.method,
            headers: self.headers.clone(),
            body,
        }
    }

    pub(crate) fn request_builder(&self) -> http::request::Builder {
        let builder = Request::builder()
            .uri(self.uri.clone())
            .version(http::Version::HTTP_3)
            .method(self.method.clone());
        self.headers.apply_to_builder(builder)
    }
}

pub(crate) async fn send_request_body(
    plan: &RequestPlan,
    request_stream: &mut MessageWriter,
) -> Result<u64, Error> {
    match &plan.body {
        RequestBody::Empty => {
            let request = plan
                .request_builder()
                .body(String::new())
                .context(error::BuildRequestSnafu)?;
            request_stream
                .send_hyper_request(request)
                .await
                .context(error::SendRequestSnafu)?;
            request_stream
                .close()
                .await
                .context(error::CloseRequestStreamSnafu)?;
            Ok(0)
        }
        RequestBody::Data(data) => {
            let request = plan
                .request_builder()
                .body(data.clone())
                .context(error::BuildRequestSnafu)?;
            request_stream
                .send_hyper_request(request)
                .await
                .context(error::SendRequestSnafu)?;
            request_stream
                .close()
                .await
                .context(error::CloseRequestStreamSnafu)?;
            Ok(data.len() as u64)
        }
        RequestBody::UploadFile(path) => {
            let n = {
                let mut stream_writer = pin!(request_stream.as_writer());
                let mut file = fs::File::open(path)
                    .await
                    .context(error::OpenUploadFileSnafu { path: path.clone() })?;
                let n = io::copy(&mut file, &mut stream_writer)
                    .await
                    .context(error::UploadFileSnafu { path: path.clone() })?;
                stream_writer
                    .flush()
                    .await
                    .context(error::UploadFileSnafu { path: path.clone() })?;
                n
            };
            request_stream
                .close()
                .await
                .context(error::CloseRequestStreamSnafu)?;
            Ok(n)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use http::{Method, Uri};

    use super::{RequestBody, RequestPlan};

    #[test]
    fn request_target_defaults_to_root() {
        let uri: Uri = "https://example.dhttp.net".parse().unwrap();
        assert_eq!(RequestPlan::request_target(&uri), "/");
    }

    #[test]
    fn request_target_keeps_path_and_query() {
        let uri: Uri = "https://example.dhttp.net/a?b=1".parse().unwrap();
        assert_eq!(RequestPlan::request_target(&uri), "/a?b=1");
    }

    #[test]
    fn method_defaults_to_get_without_body() {
        assert_eq!(
            RequestPlan::effective_method(None, &RequestBody::Empty),
            Method::GET
        );
    }

    #[test]
    fn data_body_defaults_to_post() {
        assert_eq!(
            RequestPlan::effective_method(None, &RequestBody::Data("abc".to_string())),
            Method::POST
        );
    }

    #[test]
    fn upload_body_defaults_to_put() {
        assert_eq!(
            RequestPlan::effective_method(None, &RequestBody::UploadFile(PathBuf::from("a.txt"))),
            Method::PUT
        );
    }

    #[test]
    fn explicit_method_overrides_body_default() {
        assert_eq!(
            RequestPlan::effective_method(Some(Method::PATCH), &RequestBody::Data("abc".to_string())),
            Method::PATCH
        );
    }
}
