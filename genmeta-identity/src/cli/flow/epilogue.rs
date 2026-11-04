use dhttp_home::DhttpHome;
use dhttp_identity::name::DhttpName;
use snafu::FromString;

use crate::cli::{self, Error, prompt::InquireResultExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DefaultSuggestion {
    pub(crate) question: String,
    pub(crate) help: String,
    pub(crate) default: bool,
}

pub(crate) fn suggest_default_change(
    saved_name: &str,
    current_default: Option<&str>,
) -> Option<DefaultSuggestion> {
    match current_default {
        Some(current) if current == saved_name => None,
        Some(current) => Some(DefaultSuggestion {
            question: format!("Set this name({saved_name}) as default?"),
            help: format!("current: {current}"),
            default: false,
        }),
        None => Some(DefaultSuggestion {
            question: format!("Set this name({saved_name}) as default?"),
            help: "current: none".to_string(),
            default: true,
        }),
    }
}

async fn current_default_name(dhttp_home: &DhttpHome) -> Result<Option<DhttpName<'static>>, Error> {
    Ok(cli::load_current_settings(dhttp_home)
        .await?
        .and_then(|config| config.settings().default_identity_name().cloned()))
}

async fn save_default_name(dhttp_home: &DhttpHome, name: DhttpName<'_>) -> Result<(), Error> {
    let mut settings = cli::load_current_settings(dhttp_home)
        .await?
        .unwrap_or_else(|| dhttp_home.new_settings());
    settings
        .settings_mut()
        .set_default_identity_name(name.into_owned());
    cli::save_settings(&settings).await
}

pub(crate) async fn run_lifecycle_epilogue(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
    interactive: bool,
) -> Result<(), Error> {
    if !interactive {
        return Ok(());
    }

    let current = current_default_name(dhttp_home).await?;
    let current_short = current.as_ref().map(|name| name.as_partial());
    let Some(suggestion) = suggest_default_change(name.as_partial(), current_short) else {
        return Ok(());
    };

    let accepted = crate::cli::prompt::sync(move || {
        inquire::Confirm::new(&suggestion.question)
            .with_help_message(&suggestion.help)
            .with_default(suggestion.default)
            .prompt()
    })
    .await
    .require_interactive("interactive input")?;

    if accepted && let Err(error) = save_default_name(dhttp_home, name).await {
        return Err(Error::with_source(
            Box::new(error),
            "Identity was installed, but the default identity was not updated.".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/epilogue.rs"]
mod tests;
