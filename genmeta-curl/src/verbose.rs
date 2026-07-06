#![allow(dead_code)]

use std::{
    fmt,
    io::{self, Write},
};

use http::{HeaderMap, StatusCode};

use crate::request::RequestPlan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamId(u64);

impl StreamId {
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub(crate) trait LineWriter: Clone + 'static {
    fn write_line(&self, line: &str) -> io::Result<()>;
}

#[derive(Clone)]
pub(crate) struct StderrLineWriter;

impl LineWriter for StderrLineWriter {
    fn write_line(&self, line: &str) -> io::Result<()> {
        if let Some(mut writer) = tracing_indicatif::writer::get_indicatif_stderr_writer() {
            writeln!(writer, "{line}")
        } else {
            let mut stderr = io::stderr().lock();
            writeln!(stderr, "{line}")
        }
    }
}

#[derive(Clone)]
pub(crate) struct CurlVerbose<W = StderrLineWriter> {
    enabled: bool,
    writer: W,
}

impl CurlVerbose<StderrLineWriter> {
    pub(crate) fn stderr(enabled: bool) -> Self {
        Self {
            enabled,
            writer: StderrLineWriter,
        }
    }
}

impl<W: LineWriter> CurlVerbose<W> {
    pub(crate) fn enabled(writer: W) -> Self {
        Self {
            enabled: true,
            writer,
        }
    }

    pub(crate) fn request(&self, stream_id: StreamId, plan: &RequestPlan) -> io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let scheme = plan.uri.scheme_str().unwrap_or("https");
        let authority = plan.uri.authority().map(|a| a.as_str()).unwrap_or("");
        let path = RequestPlan::request_target(&plan.uri);
        self.writer.write_line("* using HTTP/3")?;
        self.writer.write_line(&format!(
            "* [HTTP/3] [{stream_id}] OPENED stream for {}",
            plan.uri
        ))?;
        self.writer.write_line(&format!(
            "* [HTTP/3] [{stream_id}] [:method: {}]",
            plan.method
        ))?;
        self.writer
            .write_line(&format!("* [HTTP/3] [{stream_id}] [:scheme: {scheme}]"))?;
        self.writer.write_line(&format!(
            "* [HTTP/3] [{stream_id}] [:authority: {authority}]"
        ))?;
        self.writer
            .write_line(&format!("* [HTTP/3] [{stream_id}] [:path: {path}]"))?;
        for (name, value) in plan.headers.iter() {
            let value = value.to_str().unwrap_or("<non-utf8>");
            self.writer.write_line(&format!(
                "* [HTTP/3] [{stream_id}] [{}: {value}]",
                name.as_str().to_ascii_lowercase()
            ))?;
        }
        self.writer
            .write_line(&format!("> {} {path} HTTP/3", plan.method))?;
        self.writer.write_line(&format!("> Host: {authority}"))?;
        for (name, value) in plan.headers.iter() {
            let value = value.to_str().unwrap_or("<non-utf8>");
            self.writer
                .write_line(&format!("> {}: {value}", title_header_name(name.as_str())))?;
        }
        self.writer.write_line(">")?;
        Ok(())
    }

    pub(crate) fn request_sent(&self) -> io::Result<()> {
        if self.enabled {
            self.writer.write_line("* Request completely sent off")
        } else {
            Ok(())
        }
    }

    pub(crate) fn response(&self, status: StatusCode, headers: &HeaderMap) -> io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        self.writer
            .write_line(&format!("< HTTP/3 {}", status.as_u16()))?;
        for (name, value) in headers {
            let value = value.to_str().unwrap_or("<non-utf8>");
            self.writer.write_line(&format!(
                "< {}: {value}",
                name.as_str().to_ascii_lowercase()
            ))?;
        }
        self.writer.write_line("<")?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn download_chunk(&self, size: usize) -> io::Result<()> {
        if self.enabled && size > 0 {
            self.writer.write_line(&format!("{{ [{size} bytes data]"))
        } else {
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub(crate) fn upload_complete(&self, bytes: u64) -> io::Result<()> {
        if self.enabled {
            self.writer
                .write_line(&format!("* upload completely sent off: {bytes} bytes"))
        } else {
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub(crate) fn connection_left_intact(&self, authority: &str) -> io::Result<()> {
        if self.enabled {
            self.writer
                .write_line(&format!("* Connection #0 to host {authority} left intact"))
        } else {
            Ok(())
        }
    }
}

fn title_header_name(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let rest = chars.as_str().to_ascii_lowercase();
                    format!("{}{rest}", first.to_ascii_uppercase())
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};

    use crate::{
        request::{OrderedHeaders, RequestBody, RequestPlan},
        verbose::{CurlVerbose, LineWriter, StreamId},
    };

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<String>>>);

    impl LineWriter for Capture {
        fn write_line(&self, line: &str) -> std::io::Result<()> {
            self.0.lock().unwrap().push(line.to_string());
            Ok(())
        }
    }

    impl Capture {
        fn lines(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    #[test]
    fn h3_request_verbose_matches_curl_shape() {
        let writer = Capture::default();
        let verbose = CurlVerbose::enabled(writer.clone());
        let uri: Uri = "https://example.dhttp.net/a?b=1".parse().unwrap();
        let mut headers = OrderedHeaders::default();
        headers.push(
            http::header::USER_AGENT,
            HeaderValue::from_static("genmeta-curl/test"),
        );
        headers.push(http::header::ACCEPT, HeaderValue::from_static("*/*"));
        let plan = RequestPlan {
            uri,
            method: Method::GET,
            headers,
            body: RequestBody::Empty,
        };

        verbose.request(StreamId::new(0), &plan).unwrap();

        let lines = writer.lines();
        assert_eq!(lines[0], "* using HTTP/3");
        assert_eq!(
            lines[1],
            "* [HTTP/3] [0] OPENED stream for https://example.dhttp.net/a?b=1"
        );
        assert_eq!(lines[2], "* [HTTP/3] [0] [:method: GET]");
        assert_eq!(lines[3], "* [HTTP/3] [0] [:scheme: https]");
        assert_eq!(
            lines[4],
            "* [HTTP/3] [0] [:authority: example.dhttp.net]"
        );
        assert_eq!(lines[5], "* [HTTP/3] [0] [:path: /a?b=1]");
        assert_eq!(
            lines[6],
            "* [HTTP/3] [0] [user-agent: genmeta-curl/test]"
        );
        assert_eq!(lines[7], "* [HTTP/3] [0] [accept: */*]");
        assert_eq!(lines[8], "> GET /a?b=1 HTTP/3");
        assert_eq!(lines[9], "> Host: example.dhttp.net");
    }

    #[test]
    fn response_verbose_uses_h3_status_and_lowercase_headers() {
        let writer = Capture::default();
        let verbose = CurlVerbose::enabled(writer.clone());
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));

        verbose.response(StatusCode::OK, &headers).unwrap();

        let lines = writer.lines();
        assert_eq!(lines[0], "< HTTP/3 200");
        assert_eq!(lines[1], "< content-type: text/plain");
        assert_eq!(lines[2], "<");
    }
}
