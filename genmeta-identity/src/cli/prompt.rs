use std::{borrow::Cow, fmt::Display};

use dhttp_identity::name::DhttpName as Name;

use crate::cli::validator;

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
    /// On `NotTTY`, return `Ok(default())` instead of propagating the error.
    fn or_not_tty(self, default: impl FnOnce() -> T) -> Result<T, Error>;

    /// On `NotTTY`, return `Err(Error::NotInteractive { hint })`.
    fn require_interactive(self, hint: impl Into<Cow<'static, str>>) -> Result<T, Error>;
}

impl<T> InquireResultExt<T> for Result<T, inquire::InquireError> {
    fn or_not_tty(self, default: impl FnOnce() -> T) -> Result<T, Error> {
        match self {
            Ok(value) => Ok(value),
            Err(inquire::InquireError::NotTTY) => Ok(default()),
            Err(source) => Err(Error::Prompt { source }),
        }
    }

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

pub(crate) async fn prompt_given_name() -> Result<String, inquire::InquireError> {
    sync!(
        inquire::Text::new("Enter your given name:")
            .with_validator(inquire::required!("Given name cannot be empty."))
            .prompt()
    )
}

pub(crate) async fn prompt_surname() -> Result<String, inquire::InquireError> {
    sync!(
        inquire::Text::new("Enter your surname:")
            .with_validator(inquire::required!("Surname cannot be empty."))
            .prompt()
    )
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
    sync!(
        inquire::Text::new("Enter certificate chain kind (primary or secondary):")
            .with_validator(inquire::required!("Kind cannot be empty."))
            .with_validator(validator::KindValidator)
            .prompt()
    )
}

pub(crate) async fn prompt_sequence() -> Result<i32, inquire::InquireError> {
    sync!(
        inquire::Text::new("Enter certificate chain sequence:")
            .with_validator(inquire::required!("Sequence cannot be empty."))
            .prompt()
    )
    .and_then(|value| {
        value
            .parse::<i32>()
            .map_err(|error| inquire::InquireError::Custom(Box::new(error)))
    })
}

pub(crate) async fn prompt_confirm_set_as_default_name(
    name: Name<'_>,
) -> Result<bool, inquire::InquireError> {
    let message = format!("Set {name} as the default identity?");
    sync!(inquire::Confirm::new(&message).with_default(true).prompt())
}

pub(crate) async fn prompt_confirm_chain_selector_mismatch(
    requested_kind: &str,
    requested_sequence: i32,
    local_kind: &str,
    local_sequence: i32,
) -> Result<bool, inquire::InquireError> {
    let message = format!(
        "Requested certificate chain {requested_kind}/{requested_sequence} differs from local certificate SKI {local_kind}/{local_sequence}. Continue?"
    );
    sync!(inquire::Confirm::new(&message).with_default(false).prompt())
}

pub(crate) async fn prompt_select_default_identity(
    names: Vec<Name<'static>>,
) -> Result<Option<Name<'static>>, inquire::InquireError> {
    let mut options: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    options.push("(skip)".to_string());
    let selected = sync!(
        inquire::Select::new(
            "No default identity configured. Select one as the default identity:",
            options
        )
        .prompt()
    )?;
    if selected == "(skip)" {
        Ok(None)
    } else {
        Ok(names.into_iter().find(|n| n.to_string() == selected))
    }
}
