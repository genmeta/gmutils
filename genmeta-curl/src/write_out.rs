use http::{HeaderMap, Method, Uri};

use crate::timing::Timing;

/// Context for `--write-out` variable expansion.
pub(crate) struct WriteOutContext<'a> {
    pub(crate) status: u16,
    pub(crate) uri: &'a Uri,
    pub(crate) method: &'a Method,
    pub(crate) http_version: http::Version,
    pub(crate) timing: &'a Timing,
    pub(crate) size_download: u64,
    pub(crate) response_headers: &'a HeaderMap,
}

/// Expand a `--write-out` format string, substituting `%{var}` tokens.
pub(crate) fn expand_write_out(fmt: &str, ctx: &WriteOutContext<'_>) -> String {
    let mut out = String::with_capacity(fmt.len());
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('{') => {
                chars.next();
                let var: String = chars.by_ref().take_while(|&c| c != '}').collect();
                // header{name} has an inner terminator and the token's outer one.
                if var.starts_with("header{") && chars.peek() == Some(&'}') {
                    chars.next();
                }
                let value = expand_variable(&var, ctx);
                out.push_str(&value);
            }
            Some('%') => {
                chars.next();
                out.push('%');
            }
            _ => out.push('%'),
        }
    }
    out.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r")
}

fn expand_variable(var: &str, ctx: &WriteOutContext<'_>) -> String {
    if let Some(rest) = var.strip_prefix("header{") {
        let header_name = rest.trim_end_matches('}');
        return ctx
            .response_headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
    }

    match var {
        "response_code" | "http_code" => ctx.status.to_string(),
        "url" => ctx.uri.to_string(),
        "method" => ctx.method.to_string(),
        "scheme" => ctx.uri.scheme_str().unwrap_or("").to_string(),
        "http_version" => format!("{:?}", ctx.http_version).replace("HTTP/", ""),
        "time_total" => format!("{:.6}", ctx.timing.time_total()),
        "time_connect" => format!("{:.6}", ctx.timing.time_connect()),
        "time_starttransfer" => format!("{:.6}", ctx.timing.time_starttransfer()),
        "size_download" => ctx.size_download.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
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
}
