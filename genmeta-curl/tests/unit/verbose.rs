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
        "* [HTTP/3] [0] OPENED stream for https://example~/a?b=1"
    );
    assert_eq!(lines[2], "* [HTTP/3] [0] [:method: GET]");
    assert_eq!(lines[3], "* [HTTP/3] [0] [:scheme: https]");
    assert_eq!(lines[4], "* [HTTP/3] [0] [:authority: example~]");
    assert_eq!(lines[5], "* [HTTP/3] [0] [:path: /a?b=1]");
    assert_eq!(lines[6], "* [HTTP/3] [0] [user-agent: genmeta-curl/test]");
    assert_eq!(lines[7], "* [HTTP/3] [0] [accept: */*]");
    assert_eq!(lines[8], "> GET /a?b=1 HTTP/3");
    assert_eq!(lines[9], "> Host: example~");
}

#[test]
fn redirect_verbose_lines_match_curl_shape() {
    let writer = Capture::default();
    let verbose = CurlVerbose::enabled(writer.clone());
    let uri: Uri = "https://example.dhttp.net/next".parse().unwrap();

    verbose.redirect_to(&uri).unwrap();
    verbose.switch_to_get().unwrap();

    let lines = writer.lines();
    assert_eq!(
        lines[0],
        "* Issue another request to this URL: 'https://example~/next'"
    );
    assert_eq!(lines[1], "* Switch to GET");
}

#[test]
fn response_verbose_uses_h3_status_and_lowercase_headers() {
    let writer = Capture::default();
    let verbose = CurlVerbose::enabled(writer.clone());
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain"),
    );

    verbose.response(StatusCode::OK, &headers).unwrap();

    let lines = writer.lines();
    assert_eq!(lines[0], "< HTTP/3 200");
    assert_eq!(lines[1], "< content-type: text/plain");
    assert_eq!(lines[2], "<");
}

#[test]
fn diagnostic_identity_headers_are_compact_and_request_values_remain_canonical() {
    let writer = Capture::default();
    let verbose = CurlVerbose::enabled(writer.clone());
    let mut headers = HeaderMap::new();
    headers.insert(
        "pishoo-viewer-name",
        HeaderValue::from_static("alice.dhttp.net"),
    );
    headers.insert(
        "location",
        HeaderValue::from_static("https://alice.dhttp.net.evil/"),
    );
    verbose.response(StatusCode::OK, &headers).unwrap();
    let lines = writer.lines();
    assert!(
        lines
            .iter()
            .any(|line| line == "< pishoo-viewer-name: alice~")
    );
    assert!(
        lines
            .iter()
            .any(|line| line == "< location: https://alice.dhttp.net.evil/")
    );
    assert_eq!(headers["pishoo-viewer-name"], "alice.dhttp.net");
}
