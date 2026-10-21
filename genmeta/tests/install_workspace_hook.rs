//! Package-manager auto-install runs once with the installation user's credentials.
#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Output},
};

fn run_hook(
    uid: &str,
    actor: &str,
    cli_status: u8,
    runuser_available: bool,
    cli_available: bool,
) -> (Output, String, String) {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin with spaces");
    fs::create_dir(&bin).unwrap();
    let cli = bin.join("genmeta");
    let calls = root.path().join("calls");
    let roles = root.path().join("roles");
    let helper = root.path().join("install-workspace");
    fs::write(&helper, include_str!("../scripts/install-workspace.sh")).unwrap();
    let id = bin.join("id");
    fs::write(
        &id,
        "#!/bin/sh\nif [ \"$#\" = 1 ]; then printf '%s\\n' \"$TEST_UID\"; elif [ \"$2\" = installer ]; then printf '1001\\n'; elif [ \"$2\" = root ]; then printf '0\\n'; else exit 1; fi\n",
    ).unwrap();
    fs::set_permissions(&id, fs::Permissions::from_mode(0o755)).unwrap();
    if cli_available {
        fs::write(&cli, "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$TEST_CALLS\"\nif [ \"$TEST_CLI_STATUS\" != 0 ]; then printf 'identity or Pishoo unavailable\\n' >&2; fi\nexit \"$TEST_CLI_STATUS\"\n").unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o755)).unwrap();
    }
    if runuser_available {
        let runuser = bin.join("runuser");
        fs::write(&runuser, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TEST_ROLES\"\n[ \"$1\" = -u ] && [ \"$2\" = installer ] && [ \"$3\" = -- ] || exit 2\nshift 3\nexec \"$@\"\n").unwrap();
        fs::set_permissions(&runuser, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let output = Command::new("/bin/sh")
        .arg(&helper)
        .arg(&cli)
        .env_clear()
        .env("PATH", &bin)
        .env("TEST_UID", uid)
        .env("SUDO_USER", actor)
        .env("TEST_CLI_STATUS", cli_status.to_string())
        .env("TEST_CALLS", &calls)
        .env("TEST_ROLES", &roles)
        .output()
        .unwrap();
    let calls = fs::read_to_string(calls).unwrap_or_default();
    let roles = fs::read_to_string(roles).unwrap_or_default();
    (output, calls, roles)
}

#[test]
fn user_install_runs_workspace_once_with_default_identity() {
    let (output, calls, roles) = run_hook("1001", "", 0, false, true);
    assert!(output.status.success());
    assert_eq!(calls, "install\nworkspace\n");
    assert!(roles.is_empty());
}

#[test]
fn missing_identity_or_unavailable_service_never_fails_or_retries_setup() {
    let (output, calls, _) = run_hook("1001", "", 1, false, true);
    assert!(output.status.success());
    assert_eq!(calls, "install\nworkspace\n");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("identity or Pishoo unavailable"));
    assert!(error.contains("gmutils installation succeeded"));
    assert!(error.contains("genmeta install workspace"));
}

#[test]
fn privileged_install_uses_the_account_that_invoked_sudo() {
    let (output, calls, roles) = run_hook("0", "installer", 0, true, true);
    assert!(output.status.success());
    assert_eq!(calls, "install\nworkspace\n");
    let roles: Vec<_> = roles.lines().collect();
    assert_eq!(&roles[..3], &["-u", "installer", "--"]);
    assert!(roles[3].ends_with("bin with spaces/genmeta"));
    assert_eq!(&roles[4..], &["install", "workspace"]);
}

#[test]
fn privileged_cli_failure_is_nonfatal() {
    let (output, calls, _) = run_hook("0", "installer", 17, true, true);
    assert!(output.status.success());
    assert_eq!(calls, "install\nworkspace\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("genmeta install workspace"));
}

#[test]
fn invalid_sudo_account_is_not_replaced_with_another_users_identity() {
    let (output, calls, roles) = run_hook("0", "missing-account", 0, true, true);
    assert!(output.status.success());
    assert!(calls.is_empty());
    assert!(roles.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no invoking user"));
}

#[test]
fn direct_root_install_uses_its_own_default_without_guessing_an_account() {
    for actor in ["", "root"] {
        let (output, calls, roles) = run_hook("0", actor, 0, false, true);
        assert!(output.status.success());
        assert_eq!(calls, "install\nworkspace\n");
        assert!(roles.is_empty());
    }
}

#[test]
fn missing_account_switch_tool_skips_without_running_as_root() {
    let (output, calls, roles) = run_hook("0", "installer", 0, false, true);
    assert!(output.status.success());
    assert!(calls.is_empty());
    assert!(roles.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot switch"));
}

#[test]
fn missing_binary_or_user_detection_does_not_break_package_installation() {
    for (uid, cli_available) in [("1001", false), ("", true)] {
        let (output, calls, _) = run_hook(uid, "", 0, false, cli_available);
        assert!(output.status.success());
        assert!(calls.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("genmeta install workspace"));
    }
}
