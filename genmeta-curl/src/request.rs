use std::path::{Path, PathBuf};

use dhttp::RequestWriter;
use http::{HeaderName, HeaderValue, Method, Request, Uri, header::USER_AGENT};
use snafu::ResultExt;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
};

use crate::{
    cli::{ACCEPT_ENCODING, Options},
    error::{self, Error},
    progress::{self, ProgressMode},
    verbose::{CurlVerbose, LineWriter},
};

const UPLOAD_BUFFER_SIZE: usize = 16 * 1024;

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
        request.unwrap_or(match body {
            RequestBody::Empty => Method::GET,
            RequestBody::Data(_) => Method::POST,
            RequestBody::UploadFile(_) => Method::PUT,
        })
    }

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

pub(crate) async fn send_request_body<W: LineWriter>(
    plan: &RequestPlan,
    request_stream: &mut RequestWriter,
    verbose: &CurlVerbose<W>,
    progress_mode: ProgressMode,
) -> Result<u64, Error> {
    let n = match &plan.body {
        RequestBody::Empty => 0,
        RequestBody::Data(data) => {
            verbose
                .upload_data_marker(data.len() as u64)
                .context(error::WriteVerboseSnafu)?;
            request_stream
                .write_all(data.as_bytes())
                .await
                .context(error::SendRequestSnafu)?;
            data.len() as u64
        }
        RequestBody::UploadFile(path) => {
            let len = fs::metadata(path).await.ok().map(|metadata| metadata.len());
            let progress = progress::progress_bar(progress_mode, len, "Uploading");
            let mut file = fs::File::open(path)
                .await
                .context(error::OpenUploadFileSnafu { path: path.clone() })?;
            let n = copy_upload_file(&mut file, request_stream, path, verbose, progress.as_ref())
                .await?;
            if let Some(pb) = progress {
                pb.finish();
            }
            n
        }
    };
    request_stream
        .shutdown()
        .await
        .context(error::CloseRequestStreamSnafu)?;
    if n > 0 {
        verbose
            .upload_complete(n)
            .context(error::WriteVerboseSnafu)?;
    }
    Ok(n)
}

async fn copy_upload_file<W, O>(
    file: &mut fs::File,
    writer: &mut O,
    path: &Path,
    verbose: &CurlVerbose<W>,
    progress: Option<&progress::TransferProgress>,
) -> Result<u64, Error>
where
    W: LineWriter,
    O: AsyncWrite + Unpin,
{
    let mut buf = [0_u8; UPLOAD_BUFFER_SIZE];
    let mut total = 0_u64;
    let mut emitted_marker = false;

    loop {
        let n = file.read(&mut buf).await.context(error::UploadFileSnafu {
            path: path.to_path_buf(),
        })?;
        if n == 0 {
            break;
        }
        if !emitted_marker {
            verbose
                .upload_data_marker(n as u64)
                .context(error::WriteVerboseSnafu)?;
            emitted_marker = true;
        }
        writer
            .write_all(&buf[..n])
            .await
            .context(error::UploadFileSnafu {
                path: path.to_path_buf(),
            })?;
        if let Some(pb) = progress {
            pb.inc(n as u64);
        }
        total += n as u64;
    }

    Ok(total)
}

#[cfg(test)]
#[path = "../tests/unit/request.rs"]
mod tests;
