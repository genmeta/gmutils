//! Local listening configuration and HTTP mount rules for identity services.
use std::future::Future;

use http::Method;
use serde_json::json;
use snafu::{ResultExt, Whatever, ensure_whatever};

#[derive(clap::Subcommand, Debug, Clone)]
pub(super) enum Command {
    /// Query local listening or select internal, external, all, or off
    Listen {
        #[arg(short, long)]
        id: String,
        /// Omit to query the saved mode
        #[arg(value_parser = ["internal", "external", "all", "off"])]
        mode: Option<String>,
        #[arg(long)]
        global: bool,
        /// Confirm listen off in scripts
        #[arg(long)]
        yes: bool,
    },
    /// List mounts or set LOCATION and local HTTP TARGET via /std/sys/mount
    Mount {
        #[arg(short, long)]
        id: Option<String>,
        #[arg(requires = "target")]
        location: Option<String>,
        #[arg(requires = "location")]
        target: Option<String>,
    },
    /// Remove the mount matching both LOCATION and TARGET via /std/sys/mount
    Unmount {
        #[arg(short, long)]
        id: Option<String>,
        location: String,
        target: String,
        #[arg(long)]
        yes: bool,
    },
}

pub(super) async fn run(command: Command) -> Result<(), Whatever> {
    run_with(command, |id, method, path, body| async move {
        crate::install::host_request(id, method, &path, body, "application/json").await
    })
    .await
}

async fn run_with<F, Fut>(command: Command, mut request: F) -> Result<(), Whatever>
where
    F: FnMut(Option<String>, Method, String, Vec<u8>) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, Whatever>>,
{
    match command {
        Command::Listen {
            id,
            mode,
            global,
            yes,
        } => {
            if mode.as_deref() == Some("off") && !confirm_delete(&id, "listening", yes)? {
                println!("Cancelled.");
                return Ok(());
            }
            let home = dhttp_home::DhttpHome::load(if global {
                dhttp_home::HomeScope::Global
            } else {
                dhttp_home::HomeScope::User
            })
            .whatever_context("Cannot load DHTTP home")?;
            if global && mode.is_some() {
                tracing::warn!(path = %home.as_path().display(), "using the global dhttp home; this operation may require elevated privileges");
            }
            genmeta_identity::run_listen(&id, mode.as_deref(), &home)
                .await
                .whatever_context("Cannot read or change listening configuration")
        }
        Command::Mount {
            id,
            location,
            target,
        } => {
            let payload = location
                .zip(target)
                .map(|(location, target)| json!({"location":location,"proxy_pass":target}));
            let method = if payload.is_some() {
                Method::PATCH
            } else {
                Method::GET
            };
            let bytes = payload
                .map(|value| serde_json::to_vec(&value))
                .transpose()
                .whatever_context("Cannot encode mount")?
                .unwrap_or_default();
            let value = request(id, method, "/std/sys/mount".into(), bytes).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).whatever_context("Cannot encode response")?
            );
            Ok(())
        }
        Command::Unmount {
            id,
            location,
            target,
            yes,
        } => {
            if !confirm_delete(id.as_deref().unwrap_or("default identity"), "mount", yes)? {
                println!("Cancelled.");
                return Ok(());
            }
            let path = format!(
                "/std/sys/mount?location={}&proxy_pass={}",
                urlencoding::encode(&location),
                urlencoding::encode(&target)
            );
            request(id, Method::DELETE, path, Vec::new()).await?;
            Ok(())
        }
    }
}

fn confirm_delete(id: &str, resource: &str, yes: bool) -> Result<bool, Whatever> {
    use std::io::{IsTerminal, Write};
    if yes {
        return Ok(true);
    }
    ensure_whatever!(
        std::io::stdin().is_terminal(),
        "Non-interactive deletion requires --yes"
    );
    print!("Delete {resource} for {id}? [y/n] ");
    std::io::stdout()
        .flush()
        .whatever_context("Cannot show confirmation")?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .whatever_context("Cannot read confirmation")?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, future::ready};

    use clap::Parser;
    use serde_json::Value;

    use super::*;

    fn command(args: &[&str]) -> Command {
        match crate::Options::try_parse_from(std::iter::once("genmeta").chain(args.iter().copied()))
            .unwrap()
        {
            crate::Options::Server(command) => command,
            _ => panic!("expected a server command"),
        }
    }

    #[tokio::test]
    async fn mount_cli_lists_and_patches_without_listen_fields() {
        let calls = RefCell::new(Vec::new());
        for args in [
            vec!["mount"],
            vec![
                "mount",
                "--id",
                "alice.smith",
                "= /service",
                "http://[::1]:8080/base/",
            ],
        ] {
            run_with(command(&args), |id, method, path, body| {
                calls.borrow_mut().push((id, method, path, body));
                ready(Ok(json!([])))
            })
            .await
            .unwrap();
        }
        let calls = calls.into_inner();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0],
            (None, Method::GET, "/std/sys/mount".into(), Vec::new())
        );
        assert_eq!(calls[1].0.as_deref(), Some("alice.smith"));
        assert_eq!(calls[1].1, Method::PATCH);
        assert_eq!(calls[1].2, "/std/sys/mount");
        assert_eq!(
            serde_json::from_slice::<Value>(&calls[1].3).unwrap(),
            json!({"location":"= /service", "proxy_pass":"http://[::1]:8080/base/"})
        );
    }

    #[tokio::test]
    async fn unmount_cli_encodes_both_match_values_and_sends_no_body() {
        let calls = RefCell::new(Vec::new());
        run_with(
            command(&[
                "unmount",
                "--id",
                "alice.smith",
                "= /a&b",
                "http://[::1]:8080/base/",
                "--yes",
            ]),
            |id, method, path, body| {
                calls.borrow_mut().push((id, method, path, body));
                ready(Ok(Value::Null))
            },
        )
        .await
        .unwrap();
        let calls = calls.into_inner();
        assert_eq!(calls.len(), 1);
        let (id, method, path, body) = &calls[0];
        assert_eq!(id.as_deref(), Some("alice.smith"));
        assert_eq!(method, Method::DELETE);
        let uri: http::Uri = path.parse().unwrap();
        assert_eq!(uri.path(), "/std/sys/mount");
        let query: Vec<_> = url::form_urlencoded::parse(uri.query().unwrap().as_bytes())
            .into_owned()
            .collect();
        assert_eq!(
            query,
            [
                ("location".into(), "= /a&b".into()),
                ("proxy_pass".into(), "http://[::1]:8080/base/".into())
            ]
        );
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn mount_errors_propagate_without_retrying_or_changing_local_configuration() {
        let mut calls = 0;
        let result = run_with(
            command(&["mount", "/api", "127.0.0.1:8080"]),
            |_, _, _, _| {
                calls += 1;
                async { snafu::whatever!("HTTP 403: access denied") }
            },
        )
        .await;
        assert!(
            snafu::Report::from_error(result.unwrap_err())
                .to_string()
                .contains("access denied")
        );
        assert_eq!(calls, 1);
    }
}
