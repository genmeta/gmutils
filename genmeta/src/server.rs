//! Local listening configuration and HTTP forwarding rules for identity services.
use std::path::PathBuf;

use http::Method;
use serde_json::{Value, json};
use snafu::{ResultExt, Whatever, ensure_whatever, whatever};

#[derive(clap::Subcommand, Debug, Clone)]
pub(super) enum Command {
    /// Show or change local listening; modes: loopback, internal, external, all, off
    Listen {
        /// Identity whose local service configuration should be read or changed
        #[arg(short, long)]
        id: String,
        /// Omit to query the saved mode; specifying a mode creates missing configuration
        #[arg(value_parser = ["loopback", "internal", "external", "all", "off"])]
        mode: Option<String>,
        /// Use the system-wide DHTTP home
        #[arg(long)]
        global: bool,
    },
    /// List, inspect or change forwarding rules on the running identity service
    Forward {
        #[arg(short, long)]
        id: Option<String>,
        /// Optional LOCATION and TARGET, or remove LOCATION, clear, or replace FILE.json
        args: Vec<String>,
    },
}

pub(super) async fn run(command: Command) -> Result<(), Whatever> {
    match command {
        Command::Listen { id, mode, global } => {
            let scope = if global {
                dhttp_home::HomeScope::Global
            } else {
                dhttp_home::HomeScope::User
            };
            let home =
                dhttp_home::DhttpHome::load(scope).whatever_context("Cannot load DHTTP home")?;
            if global && mode.is_some() {
                tracing::warn!(path = %home.as_path().display(), "using the global dhttp home; this operation may require elevated privileges");
            }
            genmeta_identity::run_listen(&id, mode.as_deref(), &home)
                .await
                .whatever_context("Cannot read or change listening configuration")
        }
        Command::Forward { id, args } => {
            let (method, path, payload) = forward_operation(&args)?;
            let bytes = payload
                .map(|value| serde_json::to_vec(&value))
                .transpose()
                .whatever_context("Cannot encode forward configuration")?
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

fn forward_operation(args: &[String]) -> Result<(Method, String, Option<Value>), Whatever> {
    let uri = "/std/sys/forward".to_string();
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
                .whatever_context("Cannot open forward JSON")?;
            ensure_whatever!(
                input
                    .metadata()
                    .whatever_context("Cannot inspect forward JSON")?
                    .is_file(),
                "Forward JSON must be a regular file"
            );
            let mut bytes = Vec::new();
            input
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)
                .whatever_context("Cannot read forward JSON")?;
            ensure_whatever!(bytes.len() <= 64 * 1024, "Forward JSON exceeds 64 KiB");
            let value: Value =
                serde_json::from_slice(&bytes).whatever_context("Invalid forward JSON")?;
            ensure_whatever!(value.is_array(), "Forward replacement must be an array");
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
        _ => whatever!("Use genmeta forward --help"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forward_operations_use_existing_host_api_and_encode_locations() {
        let args = |items: &[&str]| {
            items
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            forward_operation(&[]).unwrap(),
            (Method::GET, "/std/sys/forward".into(), None)
        );
        assert_eq!(
            forward_operation(&args(&["rm", "= /a?x&y"])).unwrap().1,
            "/std/sys/forward?location=%3D%20%2Fa%3Fx%26y"
        );
        assert_eq!(
            forward_operation(&args(&["/api", "127.0.0.1:8080"]))
                .unwrap()
                .2
                .unwrap(),
            json!({"location":"/api","proxy_pass":"127.0.0.1:8080"})
        );
        assert!(forward_operation(&args(&["typo"])).is_err());
    }
}
