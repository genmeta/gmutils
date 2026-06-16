#![allow(dead_code)]

use std::{io::IsTerminal, sync::OnceLock};

use snafu::{ResultExt, Snafu, ensure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwriteDecision {
    Write,
    Skip,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum OverwriteManifestError {
    #[snafu(display("package manifest already exists; pass --overwrite-manifest to replace it"))]
    NotInteractive,
    #[snafu(display("failed to read overwrite confirmation"))]
    Prompt { source: inquire::InquireError },
    #[snafu(display("prompt task panicked"))]
    PromptTaskPanic { source: tokio::task::JoinError },
}

pub fn decide_manifest_overwrite(
    manifest_exists: bool,
    overwrite_manifest: bool,
    interactive: bool,
    prompt: impl FnOnce() -> Result<bool, inquire::InquireError>,
) -> Result<OverwriteDecision, OverwriteManifestError> {
    if !manifest_exists || overwrite_manifest {
        return Ok(OverwriteDecision::Write);
    }
    ensure!(interactive, overwrite_manifest_error::NotInteractiveSnafu);
    if prompt().context(overwrite_manifest_error::PromptSnafu)? {
        Ok(OverwriteDecision::Write)
    } else {
        Ok(OverwriteDecision::Skip)
    }
}

fn prompt_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub async fn confirm_manifest_overwrite(
    manifest_exists: bool,
    overwrite_manifest: bool,
) -> Result<OverwriteDecision, OverwriteManifestError> {
    if !manifest_exists || overwrite_manifest {
        return Ok(OverwriteDecision::Write);
    }
    ensure!(
        std::io::stdin().is_terminal(),
        overwrite_manifest_error::NotInteractiveSnafu
    );
    let _guard = prompt_lock().lock().await;
    let answer = tokio::task::spawn_blocking(|| {
        inquire::Confirm::new("package manifest already exists; overwrite it?")
            .with_default(false)
            .prompt()
    })
    .await
    .context(overwrite_manifest_error::PromptTaskPanicSnafu)?
    .context(overwrite_manifest_error::PromptSnafu)?;
    Ok(if answer {
        OverwriteDecision::Write
    } else {
        OverwriteDecision::Skip
    })
}

#[cfg(test)]
mod tests {
    use super::{OverwriteDecision, decide_manifest_overwrite};

    #[test]
    fn missing_manifest_writes_without_prompt() {
        let decision = decide_manifest_overwrite(false, false, false, || unreachable!())
            .expect("missing manifest should write");
        assert_eq!(decision, OverwriteDecision::Write);
    }

    #[test]
    fn overwrite_flag_writes_existing_manifest() {
        let decision = decide_manifest_overwrite(true, true, false, || unreachable!())
            .expect("overwrite flag should write");
        assert_eq!(decision, OverwriteDecision::Write);
    }

    #[test]
    fn non_interactive_existing_manifest_fails_without_flag() {
        let error = decide_manifest_overwrite(true, false, false, || unreachable!())
            .expect_err("non-interactive overwrite should fail");
        assert_eq!(
            error.to_string(),
            "package manifest already exists; pass --overwrite-manifest to replace it"
        );
    }

    #[test]
    fn interactive_decline_skips_write() {
        let decision = decide_manifest_overwrite(true, false, true, || Ok(false))
            .expect("decline should be a decision");
        assert_eq!(decision, OverwriteDecision::Skip);
    }
}
