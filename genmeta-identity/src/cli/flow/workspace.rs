use std::{
    future::Future,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use dhttp_home::{DhttpHome, HomeScope};
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
    // Capture successful command output so apply only shows its status lines.
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

async fn wait_for_server<F, Fut>(
    mut check: F,
    timeout: Duration,
    delay: Duration,
) -> Result<(), Whatever>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), Whatever>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let result = tokio::time::timeout_at(deadline, check())
            .await
            .whatever_context("Timed out waiting for Pishoo")?;
        if result.is_ok() || tokio::time::Instant::now() + delay >= deadline {
            return result;
        }
        tokio::time::sleep(delay).await;
    }
}

async fn wait_for_identity(dhttp_home: &DhttpHome, identity: &str) -> Result<(), Whatever> {
    let executable =
        std::env::current_exe().whatever_context("Failed to locate the genmeta executable")?;
    let launcher = executable_path(&executable, "genmeta");
    // Running Pishoo discovers enabled identities automatically, including in
    // foreground mode. Only retry this read-only probe, never installation.
    wait_for_server(
        || {
            run_quiet(
                readiness_command(&launcher, dhttp_home, identity),
                Duration::from_secs(5),
            )
        },
        Duration::from_secs(30),
        Duration::from_secs(1),
    )
    .await
}

async fn install(dhttp_home: &DhttpHome, identity: &str) -> Result<(), Whatever> {
    let executable =
        std::env::current_exe().whatever_context("Failed to locate the genmeta executable")?;
    let launcher = executable_path(&executable, "genmeta");
    run_quiet(
        install_command(&launcher, dhttp_home, identity),
        Duration::from_secs(20 * 60),
    )
    .await
    .whatever_context("Workspace installation did not complete; check its status before retrying")
}

pub(crate) async fn finish_setup(
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    identity: &str,
    server_enabled: bool,
    interactive: bool,
) {
    let mut hint = format!(
        "To install Workspace later, make sure Pishoo is running for this name and run `genmeta install workspace --id {identity}`."
    );
    if home_scope == HomeScope::Global {
        hint.push_str(&format!(
            " Set DHTTP_HOME to {} for this global identity.",
            dhttp_home.as_path().display()
        ));
    }
    finish_setup_with(
        server_enabled,
        interactive,
        identity,
        &hint,
        crate::cli::prompt::prompt_install_workspace(),
        wait_for_identity(dhttp_home, identity),
        install(dhttp_home, identity),
    )
    .await;
}

async fn finish_setup_with(
    server_enabled: bool,
    interactive: bool,
    identity: &str,
    hint: &str,
    confirm: impl Future<Output = Result<bool, inquire::InquireError>>,
    ready: impl Future<Output = Result<(), Whatever>>,
    install: impl Future<Output = Result<(), Whatever>>,
) {
    if !server_enabled || !interactive {
        transcript::print_line(hint);
        return;
    }
    match confirm.await {
        Ok(true) => {}
        Ok(false) => {
            transcript::print_line(hint);
            return;
        }
        Err(error) => {
            transcript::print_warning(&format!(
                "Identity installed, but Workspace installation was not confirmed: {error}"
            ));
            transcript::print_line(hint);
            return;
        }
    }
    transcript::print_line("Waiting for Pishoo to serve this name...");
    if let Err(error) = ready.await {
        transcript::print_warning(&format!(
            "Identity installed, but Pishoo is not ready for this name: {}",
            snafu::Report::from_error(error)
        ));
        transcript::print_line(hint);
        return;
    }
    transcript::print_line("Installing Workspace...");
    if let Err(error) = install.await {
        transcript::print_warning(&format!(
            "Identity installed, but Workspace installation did not complete: {}",
            snafu::Report::from_error(error)
        ));
        transcript::print_line(hint);
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
    async fn disabled_or_noninteractive_setup_neither_prompts_waits_nor_installs() {
        for (server_enabled, interactive) in [(false, true), (true, false), (false, false)] {
            finish_setup_with(
                server_enabled,
                interactive,
                "alice.smith",
                "manual install hint",
                async { panic!("must not prompt without an enabled server and terminal") },
                async { panic!("must not wait for the server without confirmation") },
                async { panic!("must not install without confirmation") },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn declined_or_cancelled_prompt_neither_waits_nor_installs() {
        for answer in [Ok(false), Err(inquire::InquireError::OperationCanceled)] {
            finish_setup_with(
                true,
                true,
                "alice.smith",
                "manual install hint",
                async { answer },
                async { panic!("must not wait for the server without confirmation") },
                async { panic!("must not install without confirmation") },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn confirmation_and_readiness_precede_install() {
        let operations = RefCell::new(Vec::new());
        finish_setup_with(
            true,
            true,
            "alice.smith",
            "manual install hint",
            async {
                operations.borrow_mut().push("confirm");
                Ok(true)
            },
            async {
                operations.borrow_mut().push("ready");
                Ok(())
            },
            async {
                operations.borrow_mut().push("install");
                Ok(())
            },
        )
        .await;
        assert_eq!(*operations.borrow(), ["confirm", "ready", "install"]);
    }

    #[tokio::test]
    async fn readiness_failure_skips_install_and_install_failure_is_not_retried() {
        for server_ready in [false, true] {
            let attempts = Cell::new(0);
            finish_setup_with(
                true,
                true,
                "alice.smith",
                "manual install hint",
                async { Ok(true) },
                async {
                    ensure_whatever!(server_ready, "Pishoo is unavailable");
                    Ok(())
                },
                async {
                    attempts.set(attempts.get() + 1);
                    snafu::whatever!("Installation failed");
                },
            )
            .await;
            assert_eq!(attempts.get(), usize::from(server_ready));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_waits_for_discovery_but_stops_at_the_deadline() {
        for ready_after in [1, 3, 8, 31] {
            let attempts = Cell::new(0);
            let started = tokio::time::Instant::now();
            let result = wait_for_server(
                || async {
                    attempts.set(attempts.get() + 1);
                    ensure_whatever!(attempts.get() >= ready_after, "Server is loading");
                    Ok(())
                },
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(result.is_ok(), ready_after <= 30);
            assert_eq!(attempts.get(), ready_after.min(30));
            assert!(started.elapsed() <= Duration::from_secs(30));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_deadline_also_bounds_a_stuck_probe() {
        let started = tokio::time::Instant::now();
        let error = wait_for_server(
            std::future::pending::<Result<(), Whatever>>,
            Duration::from_secs(30),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Timed out waiting for Pishoo"));
        assert_eq!(started.elapsed(), Duration::from_secs(30));
    }

    #[test]
    fn commands_use_the_same_installation_or_fall_back_to_path() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory
            .path()
            .join(format!("genmeta{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&executable, "").unwrap();
        assert_eq!(
            executable_path(&directory.path().join("genmeta-identity"), "genmeta"),
            executable
        );
        std::fs::remove_file(&executable).unwrap();
        assert_eq!(
            executable_path(&executable, "genmeta"),
            executable.file_name().unwrap()
        );
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
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_failure_and_timeout_are_reported() {
        let directory = tempfile::tempdir().unwrap();
        let home = DhttpHome::new(directory.path().join("home"));
        let executable = script(directory.path(), "echo 'permission denied' >&2\nexit 1");
        let error = run_quiet(identity_command(&executable, &home), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("permission denied"));

        let executable = script(directory.path(), "exec sleep 10");
        let error = run_quiet(
            identity_command(&executable, &home),
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }
}
