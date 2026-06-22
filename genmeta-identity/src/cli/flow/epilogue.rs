use std::io::IsTerminal;

use dhttp::{home::DhttpHome, name::DhttpName};

use super::{local, output, transcript};
use crate::cli::{self, Error, prompt::InquireResultExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentDefaultSummary {
    pub(crate) name: String,
    pub(crate) status: local::LocalIdentityStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DefaultSuggestion {
    pub(crate) prompt: String,
    pub(crate) default: bool,
}

pub(crate) fn suggest_default_change(
    saved_name: &str,
    current_default: Option<&CurrentDefaultSummary>,
    ansi: bool,
) -> Option<DefaultSuggestion> {
    match current_default {
        Some(current) if current.name == saved_name => None,
        Some(current) => Some(DefaultSuggestion {
            prompt: format!(
                "Set {saved_name} as the default identity on this device? {}",
                output::format_current_default_suffix(&current.name, &current.status, ansi)
            ),
            default: false,
        }),
        None => Some(DefaultSuggestion {
            prompt: format!("Set {saved_name} as the default identity on this device?"),
            default: true,
        }),
    }
}

pub(crate) fn default_block(
    before: Option<&str>,
    after: Option<&str>,
) -> output::DefaultIdentityBlock {
    match (before, after) {
        (_, None) => output::DefaultIdentityBlock::None,
        (None, Some(current)) => output::DefaultIdentityBlock::NewlySet {
            name: current.to_string(),
        },
        (Some(old), Some(current)) if old == current => output::DefaultIdentityBlock::Unchanged {
            name: current.to_string(),
        },
        (Some(old), Some(current)) => output::DefaultIdentityBlock::Changed {
            old: old.to_string(),
            new: current.to_string(),
        },
    }
}

async fn current_default_name(dhttp_home: &DhttpHome) -> Result<Option<DhttpName<'static>>, Error> {
    Ok(cli::load_current_settings(dhttp_home)
        .await?
        .and_then(|config| config.settings().default_identity_name().cloned()))
}

pub(crate) async fn current_default_summary(
    dhttp_home: &DhttpHome,
) -> Result<Option<CurrentDefaultSummary>, Error> {
    let Some(name) = current_default_name(dhttp_home).await? else {
        return Ok(None);
    };

    let status = match local::try_load_summary(dhttp_home, name.borrow(), None).await? {
        Some(summary) => summary.status,
        None => local::LocalIdentityStatus::Invalid {
            detail: "identity is not saved on this device".to_string(),
        },
    };

    Ok(Some(CurrentDefaultSummary {
        name: name.as_partial().to_string(),
        status,
    }))
}

async fn save_default_name(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
) -> Result<DhttpName<'static>, Error> {
    let mut settings = cli::load_current_settings(dhttp_home)
        .await?
        .unwrap_or_else(|| dhttp_home.new_settings());
    let name = name.into_owned();
    settings
        .settings_mut()
        .set_default_identity_name(name.clone());
    cli::save_settings(&settings).await?;
    Ok(name)
}

pub(crate) async fn run_lifecycle_epilogue(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
    default_at_start: Option<DhttpName<'static>>,
    interactive: bool,
) -> Result<(), Error> {
    let ansi = std::io::stdout().is_terminal();
    let mut default_after = current_default_name(dhttp_home).await?;
    let current_default = current_default_summary(dhttp_home).await?;
    let summary = local::load_summary(
        dhttp_home,
        name.clone(),
        default_after.as_ref().map(|default| default.borrow()),
    )
    .await?;

    transcript::print_block(&output::format_info(&summary, ansi));
    transcript::print_line(output::format_safekeeping_reminder(ansi));

    if interactive
        && let Some(suggestion) = suggest_default_change(
            name.as_partial(),
            current_default.as_ref(),
            ansi,
        )
    {
        let accepted = crate::cli::prompt::sync(move || {
            inquire::Confirm::new(&suggestion.prompt)
                .with_default(suggestion.default)
                .prompt()
        })
        .await
        .require_interactive("interactive input")?;

        if accepted {
            default_after = Some(save_default_name(dhttp_home, name.clone()).await?);
        }
    }

    let block = default_block(
        default_at_start
            .as_ref()
            .map(|default| default.as_partial()),
        default_after.as_ref().map(|default| default.as_partial()),
    );
    transcript::print_line(output::format_default_identity_block(&block));
    Ok(())
}

pub(crate) async fn run_local_epilogue(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
) -> Result<(), Error> {
    let ansi = std::io::stdout().is_terminal();
    let default_name = current_default_name(dhttp_home).await?;
    let summary = local::load_summary(
        dhttp_home,
        name,
        default_name.as_ref().map(|default| default.borrow()),
    )
    .await?;
    transcript::print_block(&output::format_info(&summary, ansi));
    transcript::print_line(output::format_safekeeping_reminder(ansi));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use dhttp::{home::DhttpHome, name::DhttpName};
    use tokio::fs;

    use super::{CurrentDefaultSummary, DefaultSuggestion, default_block, suggest_default_change};
    use crate::cli::flow::{
        local::LocalIdentityStatus,
        output::DefaultIdentityBlock,
    };

    fn unique_test_home_path(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "genmeta-identity-epilogue-{test_name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn suggest_fill_empty_default_uses_yes_by_default() {
        let suggestion = suggest_default_change("alice.smith", None, false).unwrap();

        assert!(suggestion.default);
        assert_eq!(
            suggestion.prompt,
            "Set alice.smith as the default identity on this device?"
        );
    }

    #[test]
    fn suggest_replacing_default_uses_no_by_default_and_shows_current_status() {
        let suggestion = suggest_default_change(
            "alice.smith",
            Some(&CurrentDefaultSummary {
                name: "meng.lin".to_string(),
                status: LocalIdentityStatus::Invalid {
                    detail: "certificate is unreadable".to_string(),
                },
            }),
            false,
        )
        .unwrap();

        assert_eq!(
            suggestion,
            DefaultSuggestion {
                prompt: "Set alice.smith as the default identity on this device? (current: meng.lin [invalid])".to_string(),
                default: false,
            }
        );
    }

    #[test]
    fn default_block_reports_changed_identity() {
        assert_eq!(
            default_block(Some("meng.lin"), Some("alice.smith")),
            DefaultIdentityBlock::Changed {
                old: "meng.lin".to_string(),
                new: "alice.smith".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn non_interactive_lifecycle_epilogue_keeps_default_unset_when_none_exists() {
        let home_path = unique_test_home_path("keeps-default-unset");
        let dhttp_home = DhttpHome::new(home_path.clone());
        let name = DhttpName::try_from("alice.smith").unwrap();
        let profile = dhttp_home.identity_profile(name.borrow());
        fs::create_dir_all(profile.ssl_dir()).await.unwrap();

        super::run_lifecycle_epilogue(&dhttp_home, name.borrow(), None, false)
            .await
            .unwrap();

        assert!(
            super::current_default_name(&dhttp_home)
                .await
                .unwrap()
                .is_none()
        );

        fs::remove_dir_all(home_path).await.unwrap();
    }
}
