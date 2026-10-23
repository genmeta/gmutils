use std::{
    future::Future,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use dhttp_home::DhttpHome;
use snafu::{ResultExt, Whatever, ensure_whatever};
use tokio::process::Command;

use super::transcript;

fn executable_path(current_executable: &Path, name: &str) -> PathBuf {
    let name = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    // Prefer commands from the same installation, including the standalone CLI.
    let sibling = current_executable.with_file_name(&name);
    if sibling.is_file() {
        sibling
    } else {
        PathBuf::from(name)
    }
}

fn reload_command(pishoo: &Path) -> Command {
    let mut command = Command::new(pishoo);
    command
        .arg("reload")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

fn identity_command(launcher: &Path, dhttp_home: &DhttpHome) -> Command {
    let mut command = Command::new(launcher);
    command
        // Both commands load the user home. Pin it to apply's selected home,
        // including when the identity was saved with --global.
        .env("DHTTP_HOME", dhttp_home.as_path())
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

fn readiness_command(launcher: &Path, dhttp_home: &DhttpHome, identity: &str) -> Command {
    let mut command = identity_command(launcher, dhttp_home);
    command
        .args([
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--id",
            identity,
        ])
        .arg(format!("https://{identity}~/std/sys/listen"));
    command
}

fn install_command(launcher: &Path, dhttp_home: &DhttpHome, identity: &str) -> Command {
    let mut command = identity_command(launcher, dhttp_home);
    command.args(["install", "workspace", "--id", identity]);
    command
}

async fn run_quiet(mut command: Command, timeout: Duration) -> Result<(), Whatever> {
    // Capture successful command output so apply only shows its two status lines.
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .whatever_context("Command timed out")?
        .whatever_context("Could not run command")?;
    ensure_whatever!(
        output.status.success(),
        "Command failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

async fn reload() -> Result<(), Whatever> {
    let executable =
        std::env::current_exe().whatever_context("Failed to locate the current executable")?;
    run_quiet(
        reload_command(&executable_path(&executable, "pishoo")),
        Duration::from_secs(30),
    )
    .await
}

async fn wait_for_server<F, Fut>(mut check: F, delay: Duration) -> Result<(), Whatever>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), Whatever>>,
{
    let mut result = check().await;
    for _ in 0..4 {
        if result.is_ok() {
            return result;
        }
        tokio::time::sleep(delay).await;
        result = check().await;
    }
    result
}

async fn install(dhttp_home: &DhttpHome, identity: &str) -> Result<(), Whatever> {
    let executable =
        std::env::current_exe().whatever_context("Failed to locate the genmeta executable")?;
    let launcher = executable_path(&executable, "genmeta");
    // Reload only sends a signal. Retry the read-only check until the identity
    // is reachable, then submit installation once; writes must not be retried.
    wait_for_server(
        || {
            run_quiet(
                readiness_command(&launcher, dhttp_home, identity),
                Duration::from_secs(5),
            )
        },
        Duration::from_millis(500),
    )
    .await
    .whatever_context("Pishoo did not become ready after reload")?;
    run_quiet(
        install_command(&launcher, dhttp_home, identity),
        Duration::from_secs(20 * 60),
    )
    .await
    .whatever_context("Workspace installation did not complete; check its status before retrying")
}

pub(crate) async fn finish_setup(dhttp_home: &DhttpHome, identity: &str, server_enabled: bool) {
    finish_setup_with(
        server_enabled,
        identity,
        reload(),
        install(dhttp_home, identity),
    )
    .await;
}

async fn finish_setup_with(
    server_enabled: bool,
    identity: &str,
    reload: impl Future<Output = Result<(), Whatever>>,
    install: impl Future<Output = Result<(), Whatever>>,
) {
    if !server_enabled {
        return;
    }
    transcript::print_line("Reloading Pishoo...");
    if let Err(error) = reload.await {
        transcript::print_warning(&format!(
            "Identity installed, but Pishoo reload failed: {}",
            snafu::Report::from_error(error)
        ));
        return;
    }
    if let Err(error) = install.await {
        transcript::print_warning(&format!(
            "Identity installed, but Workspace installation did not complete: {}",
            snafu::Report::from_error(error)
        ));
        return;
    }
    transcript::print_line(format!(
        "Workspace installed. Visit: https://{identity}~/app/workspace"
    ));
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    #[tokio::test]
    async fn disabled_server_neither_reloads_nor_installs() {
        finish_setup_with(
            false,
            "alice.smith",
            async { panic!("must not reload a disabled server") },
            async { panic!("must not install for a disabled server") },
        )
        .await;
    }

    #[tokio::test]
    async fn enabled_server_reloads_then_installs_once_without_confirmation() {
        let operations = RefCell::new(Vec::new());
        finish_setup_with(
            true,
            "alice.smith",
            async {
                operations.borrow_mut().push("reload");
                Ok(())
            },
            async {
                operations.borrow_mut().push("install");
                Ok(())
            },
        )
        .await;
        assert_eq!(*operations.borrow(), ["reload", "install"]);
    }

    #[tokio::test]
    async fn reload_failure_skips_install_and_install_failure_is_not_retried() {
        for reload_succeeds in [false, true] {
            let attempts = Cell::new(0);
            finish_setup_with(
                true,
                "alice.smith",
                async {
                    ensure_whatever!(reload_succeeds, "Pishoo is unavailable");
                    Ok(())
                },
                async {
                    attempts.set(attempts.get() + 1);
                    snafu::whatever!("Installation failed");
                },
            )
            .await;
            assert_eq!(attempts.get(), usize::from(reload_succeeds));
        }
    }

    #[tokio::test]
    async fn readiness_retries_until_available_with_a_bounded_attempt_count() {
        for ready_after in [1, 3, 6] {
            let attempts = Cell::new(0);
            let result = wait_for_server(
                || async {
                    attempts.set(attempts.get() + 1);
                    ensure_whatever!(attempts.get() >= ready_after, "Server is loading");
                    Ok(())
                },
                Duration::ZERO,
            )
            .await;
            assert_eq!(result.is_ok(), ready_after <= 5);
            assert_eq!(attempts.get(), ready_after.min(5));
        }
    }

    #[test]
    fn commands_use_the_same_installation_or_fall_back_to_path() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["genmeta", "pishoo"] {
            let executable = directory
                .path()
                .join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
            std::fs::write(&executable, "").unwrap();
            assert_eq!(
                executable_path(&directory.path().join("genmeta-identity"), name),
                executable
            );
            std::fs::remove_file(&executable).unwrap();
            assert_eq!(
                executable_path(&executable, name),
                executable.file_name().unwrap()
            );
        }
    }

    #[cfg(unix)]
    fn script(directory: &Path, content: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let executable = directory.join("command with spaces");
        std::fs::write(&executable, format!("#!/bin/sh\n{content}\n")).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        executable
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn commands_receive_the_applied_identity_and_home_without_stdin() {
        let directory = tempfile::tempdir().unwrap();
        let executable = script(
            directory.path(),
            "printf '%s\\n' \"$DHTTP_HOME\" \"$@\"\nif read -r input; then exit 1; fi\nexit 0",
        );
        let home = DhttpHome::new(directory.path().join("global home"));
        for (mut command, arguments) in [
            (
                install_command(&executable, &home, "alice.smith"),
                "install\nworkspace\n--id\nalice.smith\n",
            ),
            (
                readiness_command(&executable, &home, "alice.smith"),
                "curl\n--fail\n--silent\n--show-error\n--id\nalice.smith\nhttps://alice.smith~/std/sys/listen\n",
            ),
        ] {
            let output = command.output().await.unwrap();
            assert!(output.status.success());
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("{}\n{arguments}", home.as_path().display())
            );
        }
        let output = reload_command(&executable)
            .env_remove("DHTTP_HOME")
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "\nreload\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_failure_and_timeout_are_reported() {
        let directory = tempfile::tempdir().unwrap();
        let executable = script(directory.path(), "echo 'permission denied' >&2\nexit 1");
        let error = run_quiet(reload_command(&executable), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("permission denied"));

        let executable = script(directory.path(), "exec sleep 10");
        let error = run_quiet(reload_command(&executable), Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }
}
