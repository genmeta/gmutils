use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Stdio,
};

use dhttp_home::{DhttpHome, HomeScope};
use dhttp_identity::name::DhttpName;
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
    dhttp_home
        .identity_profile((identity).as_full())
        .expect("validated identity name")
        .join(DISABLED_FILE)
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
#[path = "../../../tests/unit/cli/flow/auto_renew.rs"]
mod tests;
