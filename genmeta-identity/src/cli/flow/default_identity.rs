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
        format!("Apply {short_name} to this device"),
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
    command: &Default,
    dhttp_home: &DhttpHome,
    current_config: Option<dhttp::home::identity::settings::DhttpSettingsFile>,
    summary: LocalIdentitySummary,
) -> Result<(), Error> {
    if !summary.status.is_ready() && !command.allow_nonready {
        let confirmed = cli::prompt::sync({
            let message = format!(
                "{} is {}. Set it as the default identity anyway?",
                summary.target.short_name(),
                summary.status.label()
            );
            move || inquire::Confirm::new(&message).with_default(false).prompt()
        })
        .await
        .require_interactive("--allow-nonready")?;
        if !confirmed {
            whatever!("default identity was not changed");
        }
    }

    let mut current_config = current_config.unwrap_or_else(|| {
        dhttp::home::identity::settings::DhttpSettingsFile::new(dhttp_home.settings_path())
    });
    current_config
        .settings_mut()
        .set_default_identity_name(summary.target.into_dhttp_name());
    cli::save_settings(&current_config).await
}

async fn run_helper_apply(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    target: &IdentityTarget,
) -> Result<(), Error> {
    crate::cli::flow::transcript::print_block(&format!(
        "{} is not saved on this device.\n\nTo use it as the default identity, this command will first apply {} to this device, then return here and set it as the default identity.",
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

async fn select_interactive_default_summary(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    configured_default_name: Option<dhttp::name::DhttpName<'_>>,
) -> Result<LocalIdentitySummary, Error> {
    loop {
        let inventory = local::load_inventory(dhttp_home, configured_default_name.clone()).await?;
        let choices = local::build_default_inventory_choices(&inventory);
        if choices.is_empty() {
            whatever!("No local identities found");
        }

        let ansi = std::io::stdout().is_terminal();
        let labels = choices
            .iter()
            .map(|choice| output::render_choice_label(choice, ansi))
            .collect::<Vec<_>>();
        let selected = crate::cli::prompt::prompt_select_string(
            "Select an identity to set as the default on this device:",
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
                    &format!(
                        "{} is not saved on this device. Choose what to do next:",
                        target.short_name()
                    ),
                    options.clone(),
                )
                .await
                .require_interactive("IDENTITY")?;
                match organization_action_from_selection(&options, &selected)? {
                    DefaultOrganizationAction::ApplyToLocalDevice => {
                        run_helper_apply(dhttp_home, cert_server, &target).await?;
                        return local::load_summary(
                            dhttp_home,
                            target.dhttp_name(),
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
                inquire::Confirm::new("Change the default identity on this device?")
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
            set_default_summary(command, dhttp_home, current_config, selected_summary).await
        }
        Some(name) => {
            let name = cli::parse_identity_name(name)?;
            let summary = local::load_summary(
                dhttp_home,
                name.borrow(),
                configured_default_name
                    .as_ref()
                    .map(|default| default.borrow()),
            )
            .await?;
            set_default_summary(command, dhttp_home, current_config, summary).await
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cli::flow::target::IdentityTarget;

    use super::{
        DefaultOrganizationAction, default_organization_actions, helper_apply_command,
        organization_action_from_selection,
    };

    #[test]
    fn organization_action_menu_matches_spec_copy() {
        assert_eq!(
            default_organization_actions("alice.smith.dhttp.net"),
            vec![
                "Apply alice.smith to this device".to_string(),
                "Choose another identity".to_string(),
            ]
        );
    }

    #[test]
    fn organization_action_selection_can_apply_to_local_device() {
        let options = default_organization_actions("alice.smith.dhttp.net");

        assert_eq!(
            organization_action_from_selection(&options, "Apply alice.smith to this device")
                .unwrap(),
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
