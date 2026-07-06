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
