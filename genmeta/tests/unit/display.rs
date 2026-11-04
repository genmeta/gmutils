use serde_json::json;

use super::*;

#[test]
fn package_list_shows_only_name_author_and_version() {
    let packages = [
        json!({"id":"std.dhttp.net/message","version":"0.2.1","description":"hidden description","author_owner_hash":"hidden owner"}),
        json!({"id":"dev.genmeta.tech.dhttp.net/workspace","name":"workspace","author":"dev.genmeta.tech.dhttp.net","version":"0.3.6"}),
        json!({"id":"legacy","version":"1.0.0","author":null}),
    ];
    let output = package_list(&packages, false);
    let rows = output
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [
            vec!["NAME", "AUTHOR", "VERSION"],
            vec!["message", "std", "0.2.1"],
            vec!["workspace", "dev.genmeta.tech~", "0.3.6"],
            vec!["legacy", "-", "1.0.0"],
        ]
    );
    assert!(!output.contains("hidden"));
}

#[test]
fn verbose_packages_use_readable_fields_dependencies_and_api_lines() {
    let package = json!({
        "id":"dev.genmeta.tech.dhttp.net/workspace", "version":"0.3.6",
        "has_app":true, "has_lib":true, "description":"Personal\nworkspace\u{001b}",
        "license":"MIT", "repository":"https://example.com/workspace",
        "dependencies":[{"publisher":"std.dhttp.net","name":"profile","version":"0.3.0"}],
        "endpoints":[{"method":"GET","path":"/workspace/status"}]
    });
    let output = package_list(std::slice::from_ref(&package), true);
    assert_eq!(output, package_details(&package));
    for expected in [
        "workspace 0.3.6",
        "  Author: dev.genmeta.tech~",
        "  Type: App + Lib",
        "  Description: Personal workspace",
        "  License: MIT",
        "  Repository: https://example.com/workspace",
        "  App: /app/workspace/",
        "  Dependencies:\n    std/profile 0.3.0",
        "  APIs:\n    GET /workspace/status",
    ] {
        assert!(output.contains(expected), "missing {expected:?}: {output}");
    }
    assert!(!output.contains('\u{001b}'));
    assert!(serde_json::from_str::<Value>(&output).is_err());
    assert_eq!(package_list(&[], false), "No packages installed.");
    assert_eq!(package_list(&[], true), "No packages installed.");
}
