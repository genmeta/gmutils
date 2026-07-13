use std::io::IsTerminal;

use dhttp::home::{DhttpHome, HomeScope};
use snafu::whatever;

use super::{local, output, target::IdentityTarget};
use crate::{
    cert_server::CertServer,
    cli::{self, Default, Error},
};

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
            local::load_summary(dhttp_home, name, configured_default_name.clone()).await?;
        let rendered = if command.verbose {
            output::format_info(&summary, std::io::stdout().is_terminal())
        } else {
            output::format_default_query(&summary)
        };
        crate::cli::flow::transcript::print_block(&rendered);
        return Ok(());
    };

    let target = IdentityTarget::parse(name)?;
    let Some(summary) = local::try_load_summary(
        dhttp_home,
        target.dhttp_name(),
        configured_default_name
            .as_ref()
            .map(dhttp::name::DhttpName::borrow),
    )
    .await?
    else {
        whatever!(
            "{} is not saved here.\n\nApply {} here first, then set it as the default identity.",
            target.short_name(),
            target.short_name(),
        );
    };

    if !summary.status.is_ready() && !command.allow_nonready {
        whatever!(
            "{} is {} and cannot be set as the default identity without --allow-nonready",
            summary.target.short_name(),
            summary.status.label(),
        );
    }

    set_default_summary(dhttp_home, current_config, summary).await
}
