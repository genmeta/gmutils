//! Source builds run directly; no Pishoo executable or packer is launched.
#![cfg(unix)]
use std::{os::unix::fs::PermissionsExt, process::Command};

#[test]
fn source_recipe_receives_literal_arguments_without_shell_interpolation() {
    let root = tempfile::tempdir().unwrap();
    let literal = "argument with spaces;$(touch unexpected)";
    std::fs::write(
        root.path().join("build.sh"),
        "printf '%s' \"$1\" > received\nexit 17\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("wasmer.toml"),
        format!("[build]\ncommand=['/bin/sh','build.sh','{literal}']\n"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_genmeta"))
        .args(["jade", "build"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("source build failed"));
    assert_eq!(
        std::fs::read_to_string(root.path().join("received")).unwrap(),
        literal
    );
    assert!(!root.path().join("unexpected").exists());
    assert!(!root.path().join("dist").exists());
}

#[test]
fn obsolete_pishoo_tools_on_path_are_never_called() {
    let root = tempfile::tempdir().unwrap();
    for name in ["pishoo", "pishoo-pack"] {
        let file = root.path().join(name);
        std::fs::write(&file, "#!/bin/sh\ntouch invoked\nexit 99\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(root.path().join("wasmer.toml"), "[package]\nname='test'\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_genmeta"))
        .env("PATH", root.path())
        .current_dir(root.path())
        .args(["jade", "build"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("source build requires [build]"));
    assert!(!root.path().join("invoked").exists());
}

#[test]
fn no_build_never_runs_recipe_and_failure_emits_no_success_json() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("wasmer.toml"),
        "[build]\ncommand=['/bin/sh','-c','touch invoked']\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_genmeta"))
        .current_dir(root.path())
        .args(["jade", "build", "--no-build"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!root.path().join("invoked").exists());
}
