use std::{
    future::Future,
    path::{Path, PathBuf},
    process::Stdio,
};

use dhttp_home::{DhttpHome, HomeScope};
use snafu::{ResultExt, Whatever, ensure_whatever};
use tokio::process::Command;

use super::transcript;

fn launcher_path(current_executable: &Path) -> PathBuf {
    let name = format!("genmeta{}", std::env::consts::EXE_SUFFIX);
    // Use the same installation for both the launcher and standalone identity CLI.
    let sibling = current_executable.with_file_name(&name);
    if sibling.is_file() {
        sibling
    } else {
        PathBuf::from(name)
    }
}

fn install_command(launcher: &Path, dhttp_home: &DhttpHome, identity: &str) -> Command {
    let mut command = Command::new(launcher);
    command
        .args(["install", "workspace", "--id", identity])
        // Package commands load the user home. Pin it to the home used by apply,
        // including when the identity was saved with --global.
        .env("DHTTP_HOME", dhttp_home.as_path())
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

async fn install(dhttp_home: &DhttpHome, identity: &str) -> Result<(), Whatever> {
    let executable =
        std::env::current_exe().whatever_context("Failed to locate the genmeta executable")?;
    let status = install_command(&launcher_path(&executable), dhttp_home, identity)
        .status()
        .await
        .whatever_context("Could not run genmeta install workspace; ensure genmeta is installed")?;
    ensure_whatever!(
        status.success(),
        "genmeta install workspace failed ({status})"
    );
    Ok(())
}

pub(crate) async fn offer_install(
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    identity: &str,
    interactive: bool,
) {
    let mut hint = format!(
        "To install Workspace later, start or enable Pishoo for this name and run `genmeta install workspace --id {identity}`."
    );
    if home_scope == HomeScope::Global {
        hint.push_str(&format!(
            " Set DHTTP_HOME to {} for this global identity.",
            dhttp_home.as_path().display()
        ));
    }
    offer_install_with(
        interactive,
        &hint,
        crate::cli::prompt::prompt_install_workspace(),
        install(dhttp_home, identity),
    )
    .await;
}

async fn offer_install_with(
    interactive: bool,
    hint: &str,
    confirm: impl Future<Output = Result<bool, inquire::InquireError>>,
    install: impl Future<Output = Result<(), Whatever>>,
) {
    if !interactive {
        transcript::print_line(hint);
        return;
    }
    match confirm.await {
        Ok(true) => match install.await {
            Ok(()) => {
                transcript::print_line("✔ Workspace successfully installed for this name.");
                return;
            }
            Err(error) => transcript::print_warning(&format!(
                "The identity was installed, but Workspace installation did not complete: {}",
                snafu::Report::from_error(error)
            )),
        },
        Ok(false) => {}
        Err(error) => transcript::print_warning(&format!(
            "The identity was installed, but Workspace installation was not confirmed: {error}"
        )),
    }
    transcript::print_line(hint);
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[tokio::test]
    async fn noninteractive_apply_neither_prompts_nor_installs() {
        offer_install_with(
            false,
            "manual install hint",
            async { panic!("must not prompt without a terminal") },
            async { panic!("must not install without confirmation") },
        )
        .await;
    }

    #[tokio::test]
    async fn declined_or_cancelled_prompt_does_not_install() {
        for answer in [Ok(false), Err(inquire::InquireError::OperationCanceled)] {
            offer_install_with(true, "manual install hint", async { answer }, async {
                panic!("must not install without confirmation")
            })
            .await;
        }
    }

    #[tokio::test]
    async fn accepted_prompt_installs_once_and_failure_is_nonfatal() {
        for succeeds in [true, false] {
            let attempts = Cell::new(0);
            offer_install_with(true, "manual install hint", async { Ok(true) }, async {
                attempts.set(attempts.get() + 1);
                ensure_whatever!(succeeds, "Pishoo is unavailable");
                Ok(())
            })
            .await;
            assert_eq!(attempts.get(), 1);
        }
    }

    #[test]
    fn launcher_uses_the_same_installation_or_falls_back_to_path() {
        let directory = tempfile::tempdir().unwrap();
        let launcher = directory
            .path()
            .join(format!("genmeta{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&launcher, "").unwrap();
        assert_eq!(launcher_path(&launcher), launcher);
        assert_eq!(
            launcher_path(&directory.path().join("genmeta-identity")),
            launcher
        );
        std::fs::remove_file(&launcher).unwrap();
        assert_eq!(launcher_path(&launcher), launcher.file_name().unwrap());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn installer_receives_the_applied_identity_and_home_without_stdin() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let launcher = directory.path().join("genmeta with spaces");
        std::fs::write(
            &launcher,
            "#!/bin/sh\nprintf '%s\\n' \"$DHTTP_HOME\" \"$@\"\nif read -r input; then exit 1; fi\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = DhttpHome::new(directory.path().join("global home"));
        let output = install_command(&launcher, &home, "alice.smith")
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "{}\ninstall\nworkspace\n--id\nalice.smith\n",
                home.as_path().display()
            )
        );
    }
}
