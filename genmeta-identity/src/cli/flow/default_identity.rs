use std::io::IsTerminal;

use dhttp::home::DhttpHome;
use snafu::{OptionExt, whatever};

use super::{
    local::{self, InteractiveInventoryChoice, LocalIdentitySummary},
    output,
    target::IdentityTarget,
};
use crate::{
    cert_server::CertServer,
    cli::{self, Default, Error, prompt::InquireResultExt},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefaultOrganizationAction {
    ApplyToLocalDevice,
    ChooseAnotherIdentity,
}

fn default_organization_actions(target: &str) -> Vec<String> {
    let short_name = IdentityTarget::parse(target)
        .map(|target| target.short_name().to_string())
        .unwrap_or_else(|_| target.to_string());
    vec![
        format!("Apply {short_name} here"),
        "Choose another identity".to_string(),
    ]
}

fn organization_action_from_selection(
    options: &[String],
    selected: &str,
) -> Result<DefaultOrganizationAction, Error> {
    options
        .iter()
        .find_map(|label| {
            if label == selected {
                Some(match label.as_str() {
                    "Choose another identity" => DefaultOrganizationAction::ChooseAnotherIdentity,
                    _ => DefaultOrganizationAction::ApplyToLocalDevice,
                })
            } else {
                None
            }
        })
        .whatever_context::<_, Error>("selected default action is unavailable")
}

async fn set_default_summary(
    dhttp_home: &DhttpHome,
    current_config: Option<dhttp::home::identity::settings::DhttpSettingsFile>,
    summary: LocalIdentitySummary,
) -> Result<(), Error> {
    let mut current_config = current_config.unwrap_or_else(|| {
        dhttp::home::identity::settings::DhttpSettingsFile::new(dhttp_home.settings_path())
    });
    current_config
        .settings_mut()
        .set_default_identity_name(summary.target.into_dhttp_name());
    cli::save_settings(&current_config).await
}

async fn confirm_default_target(
    command: &Default,
    summary: &LocalIdentitySummary,
    current_default: Option<&super::epilogue::CurrentDefaultSummary>,
    ansi: bool,
) -> Result<(), Error> {
    if !summary.status.is_ready() && !command.allow_nonready {
        let message = format!(
            "{} is {}. Set it as the default identity anyway?",
            summary.target.short_name(),
            summary.status.label()
        );
        let confirmed =
            cli::prompt::sync(move || inquire::Confirm::new(&message).with_default(false).prompt())
                .await
                .require_interactive("--allow-nonready")?;
        if !confirmed {
            whatever!("default identity was not changed");
        }
        return Ok(());
    }

    if let Some(suggestion) =
        super::epilogue::suggest_default_change(summary.target.short_name(), current_default, ansi)
    {
        let accepted = cli::prompt::sync(move || {
            inquire::Confirm::new(&suggestion.prompt)
                .with_default(suggestion.default)
                .prompt()
        })
        .await
        .require_interactive("IDENTITY")?;
        if !accepted {
            whatever!("default identity was not changed");
        }
    }

    Ok(())
}

async fn run_helper_apply(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    target: &IdentityTarget,
) -> Result<(), Error> {
    crate::cli::flow::transcript::print_block(&format!(
        "{} is not saved here.\n\nTo use it as the default identity, this command will first apply {} here, then return here and set it as the default identity.",
        target.short_name(),
        target.short_name()
    ));
    let command = helper_apply_command(target);
    super::apply::run_with_policy(
        &command,
        dhttp_home,
        cert_server,
        super::apply::ApplyPostSavePolicy::SkipDefaultSuggestion,
    )
    .await
}

fn helper_apply_command(target: &IdentityTarget) -> crate::cli::Apply {
    crate::cli::Apply {
        name: Some(target.short_name().to_string()),
        kind: None,
        replace_local: false,
        device_name: None,
        email: None,
        send_code: false,
        verify_code: None,
        auth: None,
    }
}

async fn summary_for_named_default_target(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    target: &IdentityTarget,
    configured_default_name: Option<dhttp::name::DhttpName<'_>>,
) -> Result<LocalIdentitySummary, Error> {
    if let Some(summary) = local::try_load_summary(
        dhttp_home,
        target.dhttp_name(),
        configured_default_name.clone(),
    )
    .await?
    {
        return Ok(summary);
    }

    if !std::io::stdin().is_terminal() {
        whatever!(
            "{} is not saved here.\n\nTo use it as the default identity, apply {} here first or rerun this command interactively.",
            target.short_name(),
            target.short_name(),
        );
    }

    run_helper_apply(dhttp_home, cert_server, target).await?;
    local::try_load_summary(dhttp_home, target.dhttp_name(), configured_default_name)
        .await?
        .whatever_context::<_, Error>("helper apply did not save the requested identity")
}

async fn select_interactive_default_summary(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    configured_default_name: Option<dhttp::name::DhttpName<'_>>,
) -> Result<LocalIdentitySummary, Error> {
    loop {
        let inventory = local::load_inventory(dhttp_home, configured_default_name.clone()).await?;
        let choices = local::build_default_inventory_choices(&inventory);
        if choices.is_empty() {
            whatever!("No identities found here");
        }

        let ansi = std::io::stdout().is_terminal();
        let labels = choices
            .iter()
            .map(|choice| output::render_choice_label(choice, ansi))
            .collect::<Vec<_>>();
        let selected = crate::cli::prompt::prompt_select_string(
            "Select an identity to set as the default here:",
            labels.clone(),
        )
        .await
        .require_interactive("IDENTITY")?;
        let choice = choices
            .into_iter()
            .zip(labels)
            .find_map(|(choice, label)| (label == selected).then_some(choice))
            .whatever_context::<_, Error>("selected identity choice is unavailable")?;
        match choice {
            InteractiveInventoryChoice::Saved(summary) => return Ok(summary),
            InteractiveInventoryChoice::Organization { target } => {
                let options = default_organization_actions(target.full_name());
                let selected = crate::cli::prompt::prompt_select_string(
                    &format!("{} is not saved here. Choose what to do next:", target.short_name()),
                    options.clone(),
                )
                .await
                .require_interactive("IDENTITY")?;
                match organization_action_from_selection(&options, &selected)? {
                    DefaultOrganizationAction::ApplyToLocalDevice => {
                        return summary_for_named_default_target(
                            dhttp_home,
                            cert_server,
                            &target,
                            configured_default_name,
                        )
                        .await;
                    }
                    DefaultOrganizationAction::ChooseAnotherIdentity => continue,
                }
            }
        }
    }
}

pub(crate) async fn run(
    command: &Default,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    let current_config = cli::load_current_settings(dhttp_home).await?;
    let configured_default_name = current_config
        .as_ref()
        .and_then(|config| config.settings().default_identity_name().cloned());
    let current_default = super::epilogue::current_default_summary(dhttp_home).await?;
    let ansi = std::io::stdout().is_terminal();

    match command.name.as_ref() {
        None => {
            let name = match configured_default_name.clone() {
                Some(n) => n,
                None => whatever!(
                    "No default identity configured. Use `genmeta identity default <name>` to set one."
                ),
            };
            let summary = local::load_summary(
                dhttp_home,
                name.borrow(),
                configured_default_name
                    .as_ref()
                    .map(|default| default.borrow()),
            )
            .await?;
            crate::cli::flow::transcript::print_block(&output::format_default_summary(
                &summary,
                std::io::stdout().is_terminal(),
            ));

            if !std::io::stdin().is_terminal() {
                return Ok(());
            }

            let switch_default = cli::prompt::sync(|| {
                inquire::Confirm::new("Change the default identity here?")
                    .with_default(false)
                    .prompt()
            })
            .await
            .require_interactive("IDENTITY")?;
            if !switch_default {
                return Ok(());
            }

            let selected_summary = select_interactive_default_summary(
                dhttp_home,
                cert_server,
                configured_default_name
                    .as_ref()
                    .map(|default| default.borrow()),
            )
            .await?;
            confirm_default_target(command, &selected_summary, current_default.as_ref(), ansi)
                .await?;
            set_default_summary(dhttp_home, current_config, selected_summary).await
        }
        Some(name) => {
            let target = IdentityTarget::parse(name)?;
            let summary = summary_for_named_default_target(
                dhttp_home,
                cert_server,
                &target,
                configured_default_name
                    .as_ref()
                    .map(|default| default.borrow()),
            )
            .await?;
            confirm_default_target(command, &summary, current_default.as_ref(), ansi).await?;
            set_default_summary(dhttp_home, current_config, summary).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DefaultOrganizationAction, default_organization_actions, helper_apply_command,
        organization_action_from_selection,
    };
    use crate::cli::flow::target::IdentityTarget;

    #[test]
    fn organization_action_menu_matches_spec_copy() {
        assert_eq!(
            default_organization_actions("alice.smith.dhttp.net"),
            vec![
                "Apply alice.smith here".to_string(),
                "Choose another identity".to_string(),
            ]
        );
    }

    #[test]
    fn organization_action_selection_can_apply_to_local_device() {
        let options = default_organization_actions("alice.smith.dhttp.net");

        assert_eq!(
            organization_action_from_selection(&options, "Apply alice.smith here").unwrap(),
            DefaultOrganizationAction::ApplyToLocalDevice,
        );
    }

    #[test]
    fn organization_action_selection_can_choose_another_identity() {
        let options = default_organization_actions("alice.smith.dhttp.net");

        assert_eq!(
            organization_action_from_selection(&options, "Choose another identity").unwrap(),
            DefaultOrganizationAction::ChooseAnotherIdentity,
        );
    }

    #[test]
    fn helper_apply_command_uses_explicit_name_without_default_lookup() {
        let command = helper_apply_command(&IdentityTarget::parse("alice.smith").unwrap());

        assert_eq!(command.name.as_deref(), Some("alice.smith"));
        assert!(command.kind.is_none());
    }
}
