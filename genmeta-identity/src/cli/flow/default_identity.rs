use std::io::IsTerminal;

use dhttp::home::{DhttpHome, HomeScope};
use snafu::whatever;

use super::{local, output, target::IdentityTarget};
use crate::{
    cert_server::CertServer,
    cli::{self, Default, Error},
};

fn default_not_found_message(short_name: &str) -> String {
    format!("Failed to set default identity: {short_name} not found!")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefaultSetDecision {
    Allow,
    RequireForce,
}

fn default_set_decision(summary: &local::LocalIdentitySummary, force: bool) -> DefaultSetDecision {
    if summary.status.is_ready() || force {
        DefaultSetDecision::Allow
    } else {
        DefaultSetDecision::RequireForce
    }
}

async fn set_default_summary(
    dhttp_home: &DhttpHome,
    current_config: Option<dhttp::home::identity::settings::DhttpSettingsFile>,
    summary: local::LocalIdentitySummary,
) -> Result<(), Error> {
    let mut current_config = current_config.unwrap_or_else(|| {
        dhttp::home::identity::settings::DhttpSettingsFile::new(dhttp_home.settings_path())
    });
    current_config
        .settings_mut()
        .set_default_identity_name(summary.target.into_dhttp_name());
    cli::save_settings(&current_config).await
}

pub(crate) async fn run(
    command: &Default,
    dhttp_home: &DhttpHome,
    _home_scope: HomeScope,
    _cert_server: &CertServer,
) -> Result<(), Error> {
    let current_config = cli::load_current_settings(dhttp_home).await?;
    let configured_default_name = current_config
        .as_ref()
        .and_then(|config| config.settings().default_identity_name().cloned());

    let Some(name) = command.name.as_deref() else {
        let name = match configured_default_name.as_ref() {
            Some(name) => name.borrow(),
            None => whatever!(
                "No default identity configured. Use `genmeta identity default <name>` to set one."
            ),
        };
        let summary =
            local::load_summary_exact(dhttp_home, name, configured_default_name.clone()).await?;
        let rendered = if command.verbose {
            output::format_info(
                &summary,
                local::now_unix_timestamp(),
                std::io::stdout().is_terminal(),
            )
        } else {
            output::format_default_query(&summary, local::now_unix_timestamp())
        };
        crate::cli::flow::transcript::print_block(&rendered);
        return Ok(());
    };

    let target = IdentityTarget::parse(name)?;
    let Some(summary) = local::try_load_summary_exact(
        dhttp_home,
        target.dhttp_name(),
        configured_default_name
            .as_ref()
            .map(dhttp::name::DhttpName::borrow),
    )
    .await?
    else {
        whatever!("{}", default_not_found_message(target.short_name()));
    };

    if default_set_decision(&summary, command.force) == DefaultSetDecision::RequireForce {
        whatever!(
            "{} is {} and cannot be set as the default identity without --force",
            summary.target.short_name(),
            summary.status.label(),
        );
    }

    set_default_summary(dhttp_home, current_config, summary).await
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{DefaultSetDecision, default_not_found_message, default_set_decision};
    use crate::cli::flow::{
        local::{IdentityUsage, LocalIdentityStatus, LocalIdentitySummary},
        target::IdentityTarget,
    };

    fn summary(status: LocalIdentityStatus) -> LocalIdentitySummary {
        LocalIdentitySummary {
            target: IdentityTarget::parse("alice.smith").unwrap(),
            usage: Some(IdentityUsage::BothClientAndServer),
            sequence: Some(0),
            valid_from: Some(1_700_000_000),
            expires_at: Some(1_900_000_000),
            status,
            dir: PathBuf::from("/tmp/alice.smith"),
            is_default: false,
        }
    }

    #[test]
    fn missing_default_target_matches_the_edited_document() {
        assert_eq!(
            default_not_found_message("alice.smith"),
            "Failed to set default identity: alice.smith not found!"
        );
    }

    #[test]
    fn default_setter_requires_force_for_every_nonready_status() {
        let ready = summary(LocalIdentityStatus::Ready {
            expires_at: 1_900_000_000,
        });
        assert_eq!(
            default_set_decision(&ready, false),
            DefaultSetDecision::Allow
        );

        for nonready in [
            LocalIdentityStatus::Expired {
                expired_at: 1_700_000_000,
            },
            LocalIdentityStatus::Invalid {
                detail: "certificate is invalid".to_string(),
            },
            LocalIdentityStatus::Incomplete {
                detail: "private key is missing".to_string(),
            },
        ] {
            let summary = summary(nonready);
            assert_eq!(
                default_set_decision(&summary, false),
                DefaultSetDecision::RequireForce
            );
            assert_eq!(
                default_set_decision(&summary, true),
                DefaultSetDecision::Allow
            );
        }
    }
}
