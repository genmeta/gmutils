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
