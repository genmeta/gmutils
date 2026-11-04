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
#[path = "../../../tests/unit/cli/flow/workspace.rs"]
mod tests;
