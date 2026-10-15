//! HTTP reverse-proxy configuration through the selected identity service.
use std::path::PathBuf;

use http::Method;
use serde_json::{Value, json};
use snafu::{ResultExt, Whatever, ensure_whatever, whatever};

#[derive(clap::Subcommand, Debug, Clone)]
pub(super) enum Command {
    /// List, inspect or change reverse-proxy rules on the running identity service
    Proxy {
        #[arg(short, long)]
        id: Option<String>,
        /// Optional LOCATION and TARGET, or remove LOCATION, clear, or replace FILE.json
        args: Vec<String>,
    },
}

pub(super) async fn run(command: Command) -> Result<(), Whatever> {
    match command {
        Command::Proxy { id, args } => {
            let (method, path, payload) = proxy_operation(&args)?;
            let bytes = payload
                .map(|value| serde_json::to_vec(&value))
                .transpose()
                .whatever_context("Cannot encode proxy configuration")?
                .unwrap_or_default();
            let value =
                crate::install::host_request(id, method, &path, bytes, "application/json").await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).whatever_context("Cannot encode response")?
            );
            Ok(())
        }
    }
}

fn proxy_operation(args: &[String]) -> Result<(Method, String, Option<Value>), Whatever> {
    let uri = "/std/sys/proxies".to_string();
    let words = args.iter().map(String::as_str).collect::<Vec<_>>();
    let query = |location: &str| format!("{uri}?location={}", urlencoding::encode(location));
    match words.as_slice() {
        [] | ["list" | "ls"] => Ok((Method::GET, uri, None)),
        ["clear"] => Ok((Method::PUT, uri, Some(json!([])))),
        ["remove" | "rm", location] if location.starts_with('/') || location.starts_with("= /") => {
            Ok((Method::DELETE, query(location), None))
        }
        ["replace", file] => {
            use std::io::Read;
            let input = std::fs::File::open(PathBuf::from(file))
                .whatever_context("Cannot open proxy JSON")?;
            ensure_whatever!(
                input
                    .metadata()
                    .whatever_context("Cannot inspect proxy JSON")?
                    .is_file(),
                "Proxy JSON must be a regular file"
            );
            let mut bytes = Vec::new();
            input
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)
                .whatever_context("Cannot read proxy JSON")?;
            ensure_whatever!(bytes.len() <= 64 * 1024, "Proxy JSON exceeds 64 KiB");
            let value: Value =
                serde_json::from_slice(&bytes).whatever_context("Invalid proxy JSON")?;
            ensure_whatever!(value.is_array(), "Proxy replacement must be an array");
            Ok((Method::PUT, uri, Some(value)))
        }
        [location] if location.starts_with('/') || location.starts_with("= /") => {
            Ok((Method::GET, query(location), None))
        }
        [location, target] if location.starts_with('/') || location.starts_with("= /") => Ok((
            Method::PATCH,
            uri,
            Some(json!({"location":location,"proxy_pass":target})),
        )),
        _ => whatever!("Use genmeta server proxy --help"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proxy_operations_use_existing_host_api_and_encode_locations() {
        let args = |items: &[&str]| {
            items
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            proxy_operation(&[]).unwrap(),
            (Method::GET, "/std/sys/proxies".into(), None)
        );
        assert_eq!(
            proxy_operation(&args(&["rm", "= /a?x&y"])).unwrap().1,
            "/std/sys/proxies?location=%3D%20%2Fa%3Fx%26y"
        );
        assert_eq!(
            proxy_operation(&args(&["/api", "127.0.0.1:8080"]))
                .unwrap()
                .2
                .unwrap(),
            json!({"location":"/api","proxy_pass":"127.0.0.1:8080"})
        );
        assert!(proxy_operation(&args(&["typo"])).is_err());
    }
}
