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
                "Set this name({saved_name}) as default? {}",
                output::format_current_default_suffix(&current.name, &current.status, ansi)
            ),
            default: false,
        }),
        None => Some(DefaultSuggestion {
            prompt: format!("Set this name({saved_name}) as default?"),
            default: true,
        }),
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
            detail: "identity is not saved here".to_string(),
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
    _default_at_start: Option<DhttpName<'static>>,
    interactive: bool,
    action: output::SavedIdentityAction,
    welcome: Option<&super::welcome::WelcomeServiceCreated>,
) -> Result<(), Error> {
    let ansi = std::io::stdout().is_terminal();
    let default_after = current_default_name(dhttp_home).await?;
    let current_default = current_default_summary(dhttp_home).await?;
    let summary = local::load_summary(
        dhttp_home,
        name.clone(),
        default_after.as_ref().map(|default| default.borrow()),
    )
    .await?;

    transcript::print_block(&output::format_saved_identity_result(
        action, &summary, ansi,
    ));

    if interactive
        && let Some(suggestion) =
            suggest_default_change(name.as_partial(), current_default.as_ref(), ansi)
    {
        let accepted = crate::cli::prompt::sync(move || {
            inquire::Confirm::new(&suggestion.prompt)
                .with_default(suggestion.default)
                .prompt()
        })
        .await
        .require_interactive("interactive input")?;

        if accepted {
            save_default_name(dhttp_home, name.clone()).await?;
        }
    }

    if let Some(welcome) = welcome {
        transcript::print_block(&super::welcome::format_welcome_service_created(welcome));
    }
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

    use super::{CurrentDefaultSummary, DefaultSuggestion, suggest_default_change};
    use crate::cli::flow::local::LocalIdentityStatus;

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
        assert_eq!(suggestion.prompt, "Set this name(alice.smith) as default?");
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
                prompt: "Set this name(alice.smith) as default? (current: meng.lin [invalid])"
                    .to_string(),
                default: false,
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

        super::run_lifecycle_epilogue(
            &dhttp_home,
            name.borrow(),
            None,
            false,
            crate::cli::flow::output::SavedIdentityAction::Applied,
            None,
        )
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
