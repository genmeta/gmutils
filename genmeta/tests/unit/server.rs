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
