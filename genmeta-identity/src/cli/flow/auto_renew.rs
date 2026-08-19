use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Stdio,
};

use dhttp::{
    home::{DhttpHome, HomeScope},
    name::DhttpName,
};
use snafu::{ResultExt, Snafu};
use tokio::{io::AsyncWriteExt, process::Command};

const SCHEDULE: &str = "0 3 * * *";
const MARKER_PREFIX: &str = "# genmeta-auto-renew";
const DISABLED_FILE: &str = ".auto-renew-disabled";

#[derive(Debug, Snafu)]
pub(crate) enum Error {
    #[snafu(display("failed to resolve the current executable"))]
    CurrentExecutable { source: std::io::Error },
    #[snafu(display("the current executable path is not valid UTF-8: {}", path.display()))]
    NonUtf8Executable { path: PathBuf },
    #[snafu(display("failed to read the current crontab"))]
    ReadCrontab { source: std::io::Error },
    #[snafu(display("crontab -l failed with {status}: {stderr}"))]
    ListCrontab { status: String, stderr: String },
    #[snafu(display("the current crontab is not valid UTF-8"))]
    NonUtf8Crontab { source: std::string::FromUtf8Error },
    #[snafu(display("failed to start crontab update"))]
    StartCrontabUpdate { source: std::io::Error },
    #[snafu(display("failed to write the updated crontab"))]
    WriteCrontab { source: std::io::Error },
    #[snafu(display("failed to wait for the crontab update"))]
    WaitForCrontab { source: std::io::Error },
    #[snafu(display("crontab update failed with {status}: {stderr}"))]
    UpdateCrontab { status: String, stderr: String },
    #[snafu(display("failed to inspect automatic renewal state at {}", path.display()))]
    InspectRenewalState {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("failed to disable automatic renewal at {}", path.display()))]
    DisableRenewal {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("failed to enable automatic renewal at {}", path.display()))]
    EnableRenewal {
        path: PathBuf,
        source: std::io::Error,
    },
}

fn scope_name(home_scope: HomeScope) -> &'static str {
    match home_scope {
        HomeScope::Global => "global",
        HomeScope::User => "user",
    }
}

fn marker(home_scope: HomeScope) -> String {
    format!("{MARKER_PREFIX}:{}", scope_name(home_scope))
}

fn shell_quote(value: &str) -> String {
    let quoted = format!("'{}'", value.replace('\'', "'\"'\"'"));
    // cron treats an unescaped percent sign as the start of command input,
    // including percent signs inside shell quotes.
    quoted.replace('%', "\\%")
}

fn is_standalone_identity_binary(executable: &Path) -> bool {
    executable
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "genmeta-identity")
}

fn points_to_current_executable(candidate: &Path, current_executable: &Path) -> bool {
    candidate
        .canonicalize()
        .ok()
        .zip(current_executable.canonicalize().ok())
        .is_some_and(|(candidate, current)| candidate == current)
}

fn scheduled_executable(
    current_executable: &Path,
    invoked_as: Option<&OsStr>,
    search_path: Option<&OsStr>,
    current_dir: Option<&Path>,
) -> PathBuf {
    let Some(invoked_as) = invoked_as else {
        return current_executable.to_path_buf();
    };
    let invoked_path = Path::new(invoked_as);

    if invoked_path.is_absolute() {
        if points_to_current_executable(invoked_path, current_executable) {
            return invoked_path.to_path_buf();
        }
    } else if invoked_path.components().count() > 1 {
        if let Some(current_dir) = current_dir {
            let candidate = current_dir.join(invoked_path);
            if points_to_current_executable(&candidate, current_executable) {
                return candidate;
            }
        }
    } else if let Some(search_path) = search_path {
        for directory in std::env::split_paths(search_path) {
            let candidate = directory.join(invoked_path);
            let comparison_candidate = if candidate.is_absolute() {
                candidate.clone()
            } else if let Some(current_dir) = current_dir {
                current_dir.join(&candidate)
            } else {
                continue;
            };
            if points_to_current_executable(&comparison_candidate, current_executable) {
                return comparison_candidate;
            }
        }
    }

    current_executable.to_path_buf()
}

fn build_entry(executable: &Path, home_scope: HomeScope) -> Result<(String, String), Error> {
    let executable = executable
        .to_str()
        .ok_or_else(|| Error::NonUtf8Executable {
            path: executable.to_path_buf(),
        })?;
    let marker = marker(home_scope);
    let mut arguments = Vec::new();
    if !is_standalone_identity_binary(Path::new(executable)) {
        arguments.push("identity");
    }
    if matches!(home_scope, HomeScope::Global) {
        arguments.push("--global");
    }
    arguments.extend(["renew", "--all"]);
    let command = std::iter::once(shell_quote(executable))
        .chain(arguments.into_iter().map(shell_quote))
        .collect::<Vec<_>>()
        .join(" ");
    Ok((
        format!("{SCHEDULE} {command} >/dev/null 2>&1 {marker}"),
        marker,
    ))
}

fn updated_crontab(existing: &str, entry: &str, marker: &str) -> Option<String> {
    let mut lines = Vec::new();
    let mut kept_entry = false;
    let mut changed = false;

    for line in existing.lines() {
        if line.trim_end().ends_with(marker) {
            if !kept_entry && line == entry {
                lines.push(line);
                kept_entry = true;
            } else {
                changed = true;
            }
        } else {
            lines.push(line);
        }
    }

    if !kept_entry {
        lines.push(entry);
        changed = true;
    }
    if !changed {
        return None;
    }

    let mut updated = lines.join("\n");
    updated.push('\n');
    Some(updated)
}

fn no_crontab_exists(status_success: bool, stdout: &[u8], stderr: &[u8]) -> bool {
    !status_success
        && stdout.is_empty()
        && String::from_utf8_lossy(stderr)
            .to_ascii_lowercase()
            .contains("no crontab")
}

async fn read_crontab(crontab: &Path) -> Result<String, Error> {
    let output = Command::new(crontab)
        .arg("-l")
        .output()
        .await
        .context(ReadCrontabSnafu)?;
    if no_crontab_exists(output.status.success(), &output.stdout, &output.stderr) {
        return Ok(String::new());
    }
    if !output.status.success() {
        return Err(Error::ListCrontab {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    String::from_utf8(output.stdout).context(NonUtf8CrontabSnafu)
}

async fn install_crontab(crontab: &Path, contents: &str) -> Result<(), Error> {
    let mut child = Command::new(crontab)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(StartCrontabUpdateSnafu)?;
    child
        .stdin
        .take()
        .expect("piped crontab stdin is available")
        .write_all(contents.as_bytes())
        .await
        .context(WriteCrontabSnafu)?;
    let output = child
        .wait_with_output()
        .await
        .context(WaitForCrontabSnafu)?;
    if !output.status.success() {
        return Err(Error::UpdateCrontab {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
}

async fn ensure_with(
    crontab: &Path,
    executable: &Path,
    home_scope: HomeScope,
) -> Result<(), Error> {
    let (entry, marker) = build_entry(executable, home_scope)?;
    let existing = read_crontab(crontab).await?;
    if let Some(updated) = updated_crontab(&existing, &entry, &marker) {
        install_crontab(crontab, &updated).await?;
    }
    Ok(())
}

pub(crate) async fn ensure_schedule(home_scope: HomeScope) -> Result<(), Error> {
    let current_executable = std::env::current_exe().context(CurrentExecutableSnafu)?;
    let invoked_as = std::env::args_os().next();
    let search_path = std::env::var_os("PATH");
    let current_dir = std::env::current_dir().ok();
    let executable = scheduled_executable(
        &current_executable,
        invoked_as.as_deref(),
        search_path.as_deref(),
        current_dir.as_deref(),
    );
    ensure_with(Path::new("crontab"), &executable, home_scope).await
}

fn disabled_path(dhttp_home: &DhttpHome, identity: DhttpName<'_>) -> PathBuf {
    dhttp_home.identity_profile(identity).join(DISABLED_FILE)
}

pub(crate) async fn is_identity_enabled(
    dhttp_home: &DhttpHome,
    identity: DhttpName<'_>,
) -> Result<bool, Error> {
    let path = disabled_path(dhttp_home, identity);
    match tokio::fs::symlink_metadata(&path).await {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(source) => Err(Error::InspectRenewalState { path, source }),
    }
}

pub(crate) async fn disable_identity(
    dhttp_home: &DhttpHome,
    identity: DhttpName<'_>,
    reason: &str,
) -> Result<(), Error> {
    let path = disabled_path(dhttp_home, identity);
    let mut options = tokio::fs::OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW);
    let mut file = options
        .open(&path)
        .await
        .context(DisableRenewalSnafu { path: &path })?;
    file.write_all(format!("{reason}\n").as_bytes())
        .await
        .context(DisableRenewalSnafu { path: &path })?;
    file.sync_all()
        .await
        .context(DisableRenewalSnafu { path: &path })?;
    Ok(())
}

pub(crate) async fn enable_identity(
    dhttp_home: &DhttpHome,
    identity: DhttpName<'_>,
) -> Result<(), Error> {
    let path = disabled_path(dhttp_home, identity);
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::EnableRenewal { path, source }),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use dhttp::{
        home::{DhttpHome, HomeScope},
        name::DhttpName,
    };

    use super::{
        build_entry, disable_identity, enable_identity, ensure_with, is_identity_enabled,
        scheduled_executable, updated_crontab,
    };

    fn unique_test_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("genmeta-auto-renew-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn preserves_a_stable_symlink_from_the_invocation_path() {
        let test_dir = unique_test_dir();
        let cellar_dir = test_dir.join("Cellar/gmutils/0.5.0/bin");
        let stable_bin_dir = test_dir.join("bin");
        std::fs::create_dir_all(&cellar_dir).unwrap();
        std::fs::create_dir_all(&stable_bin_dir).unwrap();
        let versioned_executable = cellar_dir.join("genmeta");
        std::fs::write(&versioned_executable, b"test executable").unwrap();
        let stable_executable = stable_bin_dir.join("genmeta");
        std::os::unix::fs::symlink(&versioned_executable, &stable_executable).unwrap();

        let resolved = scheduled_executable(
            &versioned_executable,
            Some(std::ffi::OsStr::new("genmeta")),
            Some(stable_bin_dir.as_os_str()),
            None,
        );

        assert_eq!(resolved, stable_executable);
        std::fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn absolutizes_a_stable_symlink_found_through_a_relative_path_entry() {
        let test_dir = unique_test_dir();
        let versioned_dir = test_dir.join("Cellar/gmutils/0.5.0/bin");
        let stable_dir = test_dir.join("bin");
        std::fs::create_dir_all(&versioned_dir).unwrap();
        std::fs::create_dir_all(&stable_dir).unwrap();
        let versioned_executable = versioned_dir.join("genmeta");
        std::fs::write(&versioned_executable, b"test executable").unwrap();
        let stable_executable = stable_dir.join("genmeta");
        std::os::unix::fs::symlink(&versioned_executable, &stable_executable).unwrap();

        let resolved = scheduled_executable(
            &versioned_executable,
            Some(std::ffi::OsStr::new("genmeta")),
            Some(std::ffi::OsStr::new("bin")),
            Some(&test_dir),
        );

        assert_eq!(resolved, stable_executable);
        assert!(resolved.is_absolute());
        std::fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn builds_scope_aware_commands_for_launcher_and_standalone_binaries() {
        let (user_entry, _) =
            build_entry(Path::new("/opt/Genmeta Tools/genmeta"), HomeScope::User).unwrap();
        let (global_entry, _) = build_entry(
            Path::new("/usr/local/bin/genmeta-identity"),
            HomeScope::Global,
        )
        .unwrap();

        assert_eq!(
            user_entry,
            "0 3 * * * '/opt/Genmeta Tools/genmeta' 'identity' 'renew' '--all' >/dev/null 2>&1 # genmeta-auto-renew:user"
        );
        assert_eq!(
            global_entry,
            "0 3 * * * '/usr/local/bin/genmeta-identity' '--global' 'renew' '--all' >/dev/null 2>&1 # genmeta-auto-renew:global"
        );
    }

    #[test]
    fn repeated_registration_does_not_rewrite_or_duplicate_the_entry() {
        let (entry, marker) = build_entry(Path::new("/usr/bin/genmeta"), HomeScope::User).unwrap();
        let existing = format!("MAILTO=ops@example.test\n{entry}\n");

        assert_eq!(updated_crontab(&existing, &entry, &marker), None);
    }

    #[test]
    fn stale_and_duplicate_aggregate_entries_collapse_to_one() {
        let (entry, marker) = build_entry(Path::new("/usr/bin/genmeta"), HomeScope::User).unwrap();
        let existing = format!(
            "15 1 * * * /usr/bin/backup\n0 2 * * * /old/genmeta identity renew --all {marker}\n{entry}\n{entry}\n"
        );

        let updated = updated_crontab(&existing, &entry, &marker).unwrap();
        assert_eq!(updated.matches(&marker).count(), 1);
        assert_eq!(updated.matches(&entry).count(), 1);
        assert!(updated.contains("15 1 * * * /usr/bin/backup"));
    }

    #[test]
    fn other_scope_and_unmanaged_entries_are_preserved() {
        let (entry, marker) = build_entry(Path::new("/usr/bin/genmeta"), HomeScope::User).unwrap();
        let unmanaged = "0 3 * * * /usr/bin/backup";
        let global =
            "0 3 * * * /usr/bin/genmeta identity --global renew --all # genmeta-auto-renew:global";
        let existing = format!("{unmanaged}\n{global}\n");

        let updated = updated_crontab(&existing, &entry, &marker).unwrap();
        assert!(updated.contains(unmanaged));
        assert!(updated.contains(global));
        assert_eq!(updated.matches("genmeta-auto-renew").count(), 2);
    }

    #[tokio::test]
    async fn command_round_trip_installs_idempotently_through_crontab_interface() {
        let test_dir = unique_test_dir();
        let crontab = test_dir.join("crontab");
        let state = test_dir.join("state");
        let update_count = test_dir.join("update-count");
        tokio::fs::create_dir_all(&test_dir).await.unwrap();
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n  -l)\n    if [ -f \"{}\" ]; then cat \"{}\"; else echo 'no crontab for test' >&2; exit 1; fi\n    ;;\n  -)\n    cat > \"{}\"\n    printf x >> \"{}\"\n    ;;\n  *) exit 2 ;;\nesac\n",
            state.display(),
            state.display(),
            state.display(),
            update_count.display(),
        );
        tokio::fs::write(&crontab, script).await.unwrap();
        let mut permissions = tokio::fs::metadata(&crontab).await.unwrap().permissions();
        permissions.set_mode(0o700);
        tokio::fs::set_permissions(&crontab, permissions)
            .await
            .unwrap();

        for _ in 0..2 {
            ensure_with(&crontab, Path::new("/usr/bin/genmeta"), HomeScope::User)
                .await
                .unwrap();
        }

        let installed = tokio::fs::read_to_string(&state).await.unwrap();
        assert_eq!(installed.matches("genmeta-auto-renew").count(), 1);
        assert_eq!(tokio::fs::read_to_string(&update_count).await.unwrap(), "x");
        tokio::fs::remove_dir_all(test_dir).await.unwrap();
    }

    #[tokio::test]
    async fn identity_disable_state_round_trips_with_the_terminal_reason() {
        let test_dir = unique_test_dir();
        let dhttp_home = DhttpHome::new(test_dir.clone());
        let identity = DhttpName::try_from("alice.smith").unwrap();
        tokio::fs::create_dir_all(dhttp_home.identity_profile(identity.borrow()).path())
            .await
            .unwrap();

        assert!(
            is_identity_enabled(&dhttp_home, identity.borrow())
                .await
                .unwrap()
        );
        disable_identity(&dhttp_home, identity.borrow(), "domain_expired")
            .await
            .unwrap();
        assert!(
            !is_identity_enabled(&dhttp_home, identity.borrow())
                .await
                .unwrap()
        );
        assert_eq!(
            tokio::fs::read_to_string(test_dir.join("alice.smith/.auto-renew-disabled"))
                .await
                .unwrap(),
            "domain_expired\n"
        );

        enable_identity(&dhttp_home, identity.borrow())
            .await
            .unwrap();
        enable_identity(&dhttp_home, identity.borrow())
            .await
            .unwrap();
        assert!(
            is_identity_enabled(&dhttp_home, identity.borrow())
                .await
                .unwrap()
        );
        tokio::fs::remove_dir_all(test_dir).await.unwrap();
    }
}
