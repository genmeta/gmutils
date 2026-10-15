//! Check the installed launcher/tool boundary without loading real credentials.
#![cfg(unix)]
use std::{os::unix::fs::PermissionsExt, path::Path, process::Command};

fn launcher(dir: &Path) -> std::path::PathBuf {
    let file = dir.join("genmeta");
    std::fs::copy(env!("CARGO_BIN_EXE_genmeta"), &file).unwrap();
    file
}
fn tool(path: &Path, script: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn sibling_tool_takes_precedence_and_receives_literal_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let binary = launcher(dir.path());
    let fallback = dir.path().join("path");
    std::fs::create_dir(&fallback).unwrap();
    tool(&fallback.join("pishoo-pack"), "exit 99");
    tool(&dir.path().join("pishoo-pack"), "printf '%s\\n' \"$@\"");
    let output = Command::new(binary)
        .env("PATH", fallback)
        .args([
            "package",
            "build",
            "project with spaces;$(echo danger)",
            "-o",
            "out with spaces.webc",
            "-i",
            "alice~",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "--build\n--output\nout with spaces.webc\n--id\nalice~\n--\nproject with spaces;$(echo danger)\n"
    );
}

#[test]
fn path_fallback_preserves_the_tools_single_json_result() {
    let dir = tempfile::tempdir().unwrap();
    let binaries = dir.path().join("bin");
    let fallback = dir.path().join("path");
    std::fs::create_dir(&binaries).unwrap();
    std::fs::create_dir(&fallback).unwrap();
    let binary = launcher(&binaries);
    tool(
        &fallback.join("pishoo-pack"),
        "printf '%s\\n' '{\"id\":\"alice.dhttp.net/hello\",\"kind\":\"app\"}'",
    );
    let output = Command::new(binary)
        .env("PATH", fallback)
        .args(["package", "build"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["id"], "alice.dhttp.net/hello");
}

#[test]
fn missing_and_failed_tools_never_report_success() {
    let dir = tempfile::tempdir().unwrap();
    let binary = launcher(dir.path());
    let output = Command::new(&binary)
        .env("PATH", "")
        .args(["package", "build"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("install a Pishoo release"));
    tool(
        &dir.path().join("pishoo-pack"),
        "printf '%s\\n' 'signature validation failed' >&2; exit 7",
    );
    let output = Command::new(binary)
        .env("PATH", "")
        .args(["package", "build"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("signature validation failed"));
}
