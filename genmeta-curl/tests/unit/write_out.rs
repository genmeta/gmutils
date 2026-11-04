use super::*;

#[test]
fn adjacent_header_tokens_consume_both_closing_braces() {
    let uri: Uri = "https://alice.dhttp.net/app/workspace/".parse().unwrap();
    let method = Method::HEAD;
    let timing = Timing::new();
    let mut response_headers = HeaderMap::new();
    response_headers.insert("pishoo-viewer-name", "alice.dhttp.net".parse().unwrap());
    response_headers.insert("cache-control", "no-store".parse().unwrap());
    let ctx = WriteOutContext {
        status: 200,
        uri: &uri,
        method: &method,
        http_version: http::Version::HTTP_3,
        timing: &timing,
        size_download: 0,
        response_headers: &response_headers,
    };
    assert_eq!(
        expand_write_out(
            "%{response_code}|%{header{Pishoo-Viewer-Name}}|%{header{Cache-Control}}|%{header{missing}}|%{method}",
            &ctx
        ),
        "200|alice.dhttp.net|no-store||HEAD"
    );
    assert_eq!(
        expand_write_out("%% %{http_code} %{header{missing}}end", &ctx),
        "% 200 end"
    );
    assert_eq!(
        expand_write_out("%{header{cache-control}}}", &ctx),
        "no-store}"
    );
}
