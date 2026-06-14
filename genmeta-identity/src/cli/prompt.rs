use std::{borrow::Cow, fmt::Display};

use crate::cli::{flow::kind::IdentityKind, validator};

pub(crate) const MORE_OPTIONS_LABEL: &str = "More options...";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TextPromptResult {
    Submitted(String),
    MoreOptions,
}

#[derive(Clone)]
pub(crate) struct MoreOptionsFriendlyValidator<V> {
    inner: V,
}

impl<V> MoreOptionsFriendlyValidator<V> {
    pub(crate) fn new(inner: V) -> Self {
        Self { inner }
    }
}

impl<V> inquire::validator::StringValidator for MoreOptionsFriendlyValidator<V>
where
    V: inquire::validator::StringValidator + Clone,
{
    fn validate(
        &self,
        input: &str,
    ) -> Result<inquire::validator::Validation, inquire::CustomUserError> {
        if input == "?" {
            return Ok(inquire::validator::Validation::Valid);
        }

        self.inner.validate(input)
    }
}

#[derive(Debug)]
pub enum Error {
    /// An inquire prompt error (invariant: never contains NotTTY).
    Prompt { source: inquire::InquireError },
    /// The terminal is not interactive and user input is required.
    NotInteractive { hint: Cow<'static, str> },
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Inquire error output is too messy, implement custom display
            Error::Prompt { source } => match source {
                inquire::InquireError::IO(error) => error.fmt(f),
                inquire::InquireError::Custom(error) => error.fmt(f),
                source => source.fmt(f),
            },
            Error::NotInteractive { hint } => {
                write!(f, "non-interactive terminal, use {hint} to provide input")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Prompt { source } => match source {
                inquire::InquireError::IO(error) => error.source(),
                inquire::InquireError::Custom(error) => error.source(),
                _ => None,
            },
            Error::NotInteractive { .. } => None,
        }
    }
}

pub(crate) trait InquireResultExt<T> {
    /// On `NotTTY`, return `Err(Error::NotInteractive { hint })`.
    fn require_interactive(self, hint: impl Into<Cow<'static, str>>) -> Result<T, Error>;
}

impl<T> InquireResultExt<T> for Result<T, inquire::InquireError> {
    fn require_interactive(self, hint: impl Into<Cow<'static, str>>) -> Result<T, Error> {
        match self {
            Ok(value) => Ok(value),
            Err(inquire::InquireError::NotTTY) => Err(Error::NotInteractive { hint: hint.into() }),
            Err(source) => Err(Error::Prompt { source }),
        }
    }
}

pub(crate) async fn sync<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f)
        .await
        .expect("BUG: blocking task should not panic")
}

/// sync!( sync_code() )
macro_rules! sync {
    ($body:expr) => {
        sync(move || $body).await
    };
}

pub(crate) async fn prompt_email() -> Result<String, inquire::InquireError> {
    sync!(
        inquire::Text::new("Enter your email address:")
            .with_validator(inquire::required!("Email address cannot be empty."))
            .with_validator(validator::EmailValidator)
            .prompt()
    )
}

pub(crate) async fn prompt_identity_name(
    opening: &'static str,
) -> Result<String, inquire::InquireError> {
    prompt_identity_name_with_default(opening, None).await
}

pub(crate) async fn prompt_identity_name_with_default(
    opening: &'static str,
    default: Option<&str>,
) -> Result<String, inquire::InquireError> {
    if !opening.is_empty() {
        crate::cli::flow::transcript::print_block(opening);
    }
    let default = default.map(ToOwned::to_owned);
    sync!({
        let mut prompt = inquire::Text::new("Enter the identity name:")
            .with_validator(inquire::required!("Identity name cannot be empty."))
            .with_validator(|value: &str| {
                match crate::cli::flow::target::IdentityTarget::parse(value) {
                    Ok(_) => Ok(inquire::validator::Validation::Valid),
                    Err(error) => Ok(inquire::validator::Validation::Invalid(
                        inquire::validator::ErrorMessage::Custom(error.to_string()),
                    )),
                }
            });
        if let Some(default) = default.as_deref() {
            prompt = prompt.with_default(default);
        }
        prompt.prompt()
    })
}

pub(crate) async fn prompt_select_string(
    message: &str,
    options: Vec<String>,
) -> Result<String, inquire::InquireError> {
    prompt_select_string_with_cursor(message, options, None).await
}

pub(crate) async fn prompt_verify_code() -> Result<String, inquire::InquireError> {
    sync!(
        inquire::Text::new("Enter the verification code sent to your email:")
            .with_validator(inquire::required!("Verification code cannot be empty."))
            .with_validator(inquire::length!(
                6,
                "Verification code must be exactly 6 characters."
            ))
            .prompt()
    )
}

pub(crate) async fn prompt_kind() -> Result<String, inquire::InquireError> {
    prompt_kind_with_cursor(None).await
}

pub(crate) async fn prompt_kind_with_cursor(
    selected_kind: Option<IdentityKind>,
) -> Result<String, inquire::InquireError> {
    let prompt = format!(
        "{}\n\n{}\n\n{}",
        IdentityKind::SELECT_PROMPT,
        IdentityKind::PRIMARY_HELP,
        IdentityKind::SECONDARY_HELP
    );
    let starting_cursor = match selected_kind {
        Some(IdentityKind::Primary) => Some(0),
        Some(IdentityKind::Secondary) => Some(1),
        None => None,
    };
    sync!(
        inquire::Select::new(
            &prompt,
            vec![
                IdentityKind::Primary.to_string(),
                IdentityKind::Secondary.to_string()
            ]
        )
        .with_starting_cursor(starting_cursor.unwrap_or(0))
        .prompt()
    )
}

fn text_prompt_result(answer: String) -> TextPromptResult {
    if answer == "?" {
        TextPromptResult::MoreOptions
    } else {
        TextPromptResult::Submitted(answer)
    }
}

pub(crate) async fn prompt_email_with_more_options(
    default: Option<&str>,
) -> Result<TextPromptResult, inquire::InquireError> {
    let default = default.map(ToOwned::to_owned);
    sync!({
        let mut prompt = inquire::Text::new("Email:")
            .with_help_message("Type ? for more options.")
            .with_validator(MoreOptionsFriendlyValidator::new(inquire::required!(
                "Email address cannot be empty."
            )))
            .with_validator(MoreOptionsFriendlyValidator::new(validator::EmailValidator));
        if let Some(default) = default.as_deref() {
            prompt = prompt.with_default(default);
        }
        prompt.prompt()
    })
    .map(text_prompt_result)
}

pub(crate) async fn prompt_verify_code_with_more_options(
    default: Option<&str>,
) -> Result<TextPromptResult, inquire::InquireError> {
    let default = default.map(ToOwned::to_owned);
    sync!({
        let mut prompt = inquire::Text::new("Verification code:")
            .with_help_message("Type ? for more options.")
            .with_validator(MoreOptionsFriendlyValidator::new(inquire::required!(
                "Verification code cannot be empty."
            )))
            .with_validator(MoreOptionsFriendlyValidator::new(inquire::length!(
                6,
                "Verification code must be exactly 6 characters."
            )));
        if let Some(default) = default.as_deref() {
            prompt = prompt.with_default(default);
        }
        prompt.prompt()
    })
    .map(text_prompt_result)
}

pub(crate) async fn prompt_select_string_with_cursor(
    message: &str,
    options: Vec<String>,
    starting_cursor: Option<usize>,
) -> Result<String, inquire::InquireError> {
    let message = message.to_string();
    sync!({
        let mut prompt = inquire::Select::new(&message, options);
        if let Some(starting_cursor) = starting_cursor {
            prompt = prompt.with_starting_cursor(starting_cursor);
        }
        prompt.prompt()
    })
}

#[cfg(test)]
mod tests {
    use inquire::validator::{StringValidator, Validation};

    use super::{MORE_OPTIONS_LABEL, MoreOptionsFriendlyValidator};

    #[test]
    fn question_mark_bypasses_inner_validation() {
        #[derive(Clone)]
        struct RejectAll;

        impl StringValidator for RejectAll {
            fn validate(&self, _input: &str) -> Result<Validation, inquire::CustomUserError> {
                Ok(Validation::Invalid(inquire::validator::ErrorMessage::from(
                    "always invalid",
                )))
            }
        }

        let validator = MoreOptionsFriendlyValidator::new(RejectAll);

        assert_eq!(validator.validate("?").unwrap(), Validation::Valid);
        assert_eq!(
            validator.validate("value").unwrap(),
            Validation::Invalid(inquire::validator::ErrorMessage::from("always invalid"))
        );
    }

    #[test]
    fn more_options_label_matches_spec_copy() {
        assert_eq!(MORE_OPTIONS_LABEL, "More options...");
    }
}
