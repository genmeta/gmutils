use std::{
    path::{Path, PathBuf},
    process::Stdio,
};

use dhttp::home::HomeScope;
use snafu::{ResultExt, Snafu};
use tokio::{io::AsyncWriteExt, process::Command};

const SCHEDULE: &str = "0 3 * * *";
const MARKER_PREFIX: &str = "# genmeta-auto-renew";

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
}

fn scope_name(home_scope: HomeScope) -> &'static str {
    match home_scope {
        HomeScope::Global => "global",
        HomeScope::User => "user",
    }
}

fn marker(identity: &str, home_scope: HomeScope) -> String {
    format!("{MARKER_PREFIX}:{}:{identity}", scope_name(home_scope))
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

fn build_entry(
    executable: &Path,
    identity: &str,
    home_scope: HomeScope,
) -> Result<(String, String), Error> {
    let executable = executable
        .to_str()
        .ok_or_else(|| Error::NonUtf8Executable {
            path: executable.to_path_buf(),
        })?;
    let marker = marker(identity, home_scope);
    let mut arguments = Vec::new();
    if !is_standalone_identity_binary(Path::new(executable)) {
        arguments.push("identity");
    }
    if matches!(home_scope, HomeScope::Global) {
        arguments.push("--global");
    }
    arguments.extend(["renew", identity]);
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

fn removed_crontab(existing: &str, marker: &str) -> Option<String> {
    let mut removed = false;
    let lines = existing
        .lines()
        .filter(|line| {
            let matches = line.trim_end().ends_with(marker);
            removed |= matches;
            !matches
        })
        .collect::<Vec<_>>();
    if !removed {
        return None;
    }

    let mut updated = lines.join("\n");
    if !updated.is_empty() {
        updated.push('\n');
    }
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
    identity: &str,
    home_scope: HomeScope,
) -> Result<(), Error> {
    let (entry, marker) = build_entry(executable, identity, home_scope)?;
    let existing = read_crontab(crontab).await?;
    if let Some(updated) = updated_crontab(&existing, &entry, &marker) {
        install_crontab(crontab, &updated).await?;
    }
    Ok(())
}

async fn remove_with(crontab: &Path, identity: &str, home_scope: HomeScope) -> Result<(), Error> {
    let marker = marker(identity, home_scope);
    let existing = read_crontab(crontab).await?;
    if let Some(updated) = removed_crontab(&existing, &marker) {
        install_crontab(crontab, &updated).await?;
    }
    Ok(())
}

pub(crate) async fn ensure(identity: &str, home_scope: HomeScope) -> Result<(), Error> {
    let executable = std::env::current_exe().context(CurrentExecutableSnafu)?;
    ensure_with(Path::new("crontab"), &executable, identity, home_scope).await
}

pub(crate) async fn remove(identity: &str, home_scope: HomeScope) -> Result<(), Error> {
    remove_with(Path::new("crontab"), identity, home_scope).await
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use dhttp::home::HomeScope;

    use super::{build_entry, ensure_with, remove_with, removed_crontab, updated_crontab};

    fn unique_test_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("genmeta-auto-renew-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn builds_scope_aware_commands_for_launcher_and_standalone_binaries() {
        let (user_entry, _) = build_entry(
            Path::new("/opt/Genmeta Tools/genmeta"),
            "alice.smith",
            HomeScope::User,
        )
        .unwrap();
        let (global_entry, _) = build_entry(
            Path::new("/usr/local/bin/genmeta-identity"),
            "alice.smith",
            HomeScope::Global,
        )
        .unwrap();

        assert_eq!(
            user_entry,
            "0 3 * * * '/opt/Genmeta Tools/genmeta' 'identity' 'renew' 'alice.smith' >/dev/null 2>&1 # genmeta-auto-renew:user:alice.smith"
        );
        assert_eq!(
            global_entry,
            "0 3 * * * '/usr/local/bin/genmeta-identity' '--global' 'renew' 'alice.smith' >/dev/null 2>&1 # genmeta-auto-renew:global:alice.smith"
        );
    }

    #[test]
    fn repeated_registration_does_not_rewrite_or_duplicate_the_entry() {
        let (entry, marker) = build_entry(
            Path::new("/usr/bin/genmeta"),
            "alice.smith",
            HomeScope::User,
        )
        .unwrap();
        let existing = format!("MAILTO=ops@example.test\n{entry}\n");

        assert_eq!(updated_crontab(&existing, &entry, &marker), None);
    }

    #[test]
    fn stale_and_duplicate_managed_entries_collapse_to_one() {
        let (entry, marker) = build_entry(
            Path::new("/usr/bin/genmeta"),
            "alice.smith",
            HomeScope::User,
        )
        .unwrap();
        let existing = format!(
            "15 1 * * * /usr/bin/backup\n0 2 * * * /old/genmeta identity renew alice.smith {marker}\n{entry}\n{entry}\n"
        );

        let updated = updated_crontab(&existing, &entry, &marker).unwrap();
        assert_eq!(updated.matches(&marker).count(), 1);
        assert_eq!(updated.matches(&entry).count(), 1);
        assert!(updated.contains("15 1 * * * /usr/bin/backup"));
    }

    #[test]
    fn different_identities_and_scopes_are_preserved() {
        let (entry, marker) = build_entry(
            Path::new("/usr/bin/genmeta"),
            "alice.smith",
            HomeScope::User,
        )
        .unwrap();
        let other = "0 3 * * * /usr/bin/genmeta identity renew bob.smith # genmeta-auto-renew:user:bob.smith";
        let global = "0 3 * * * /usr/bin/genmeta identity --global renew alice.smith # genmeta-auto-renew:global:alice.smith";
        let existing = format!("{other}\n{global}\n");

        let updated = updated_crontab(&existing, &entry, &marker).unwrap();
        assert!(updated.contains(other));
        assert!(updated.contains(global));
        assert_eq!(updated.matches("genmeta-auto-renew").count(), 3);
    }

    #[test]
    fn removing_an_identity_preserves_other_entries_and_scopes() {
        let marker = super::marker("alice.smith", HomeScope::User);
        let same_identity_global = "0 3 * * * /usr/bin/genmeta identity --global renew alice.smith # genmeta-auto-renew:global:alice.smith";
        let other_identity = "0 3 * * * /usr/bin/genmeta identity renew bob.smith # genmeta-auto-renew:user:bob.smith";
        let existing = format!(
            "MAILTO=ops@example.test\n0 3 * * * /usr/bin/genmeta identity renew alice.smith {marker}\n{same_identity_global}\n{other_identity}\n"
        );

        let updated = removed_crontab(&existing, &marker).unwrap();
        assert!(!updated.contains(&marker));
        assert!(updated.contains("MAILTO=ops@example.test"));
        assert!(updated.contains(same_identity_global));
        assert!(updated.contains(other_identity));
        assert_eq!(removed_crontab(&updated, &marker), None);
    }

    #[tokio::test]
    async fn command_round_trip_installs_and_removes_through_crontab_interface() {
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
            ensure_with(
                &crontab,
                Path::new("/usr/bin/genmeta"),
                "alice.smith",
                HomeScope::User,
            )
            .await
            .unwrap();
        }

        let installed = tokio::fs::read_to_string(&state).await.unwrap();
        assert_eq!(installed.matches("genmeta-auto-renew").count(), 1);
        assert_eq!(tokio::fs::read_to_string(&update_count).await.unwrap(), "x");

        remove_with(&crontab, "alice.smith", HomeScope::User)
            .await
            .unwrap();
        assert_eq!(tokio::fs::read_to_string(&state).await.unwrap(), "");
        assert_eq!(
            tokio::fs::read_to_string(&update_count).await.unwrap(),
            "xx"
        );

        remove_with(&crontab, "alice.smith", HomeScope::User)
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read_to_string(&update_count).await.unwrap(),
            "xx"
        );
        tokio::fs::remove_dir_all(test_dir).await.unwrap();
    }
}
