use std::{borrow::Cow, fmt::Display};

use dhttp_home::identity::Name;

use crate::{
    REGISTERABLE_SUFFIXES,
    cert_server::{CertServer, LoginResponse, RegisterResponse},
    cli::validator,
};

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

pub(crate) async fn prompt_suffix() -> Result<&'static str, inquire::InquireError> {
    sync!(
        inquire::Select::new(
            "Select a suffix for registration:",
            REGISTERABLE_SUFFIXES.to_vec()
        )
        .prompt()
    )
}

pub(crate) async fn prompt_available_name(
    cert_server: CertServer,
    suffix: impl Into<Cow<'static, str>> + Send + 'static,
) -> Result<String, inquire::InquireError> {
    sync!(
        inquire::Text::new("Enter your desired name:")
            .with_validator(inquire::required!("Name cannot be empty."))
            .with_validator(validator::UsernameValidator::new(suffix))
            .with_validator(validator::OnlineAvailableUsernameValidator::new(
                cert_server
            ))
            .prompt()
    )
}

pub(crate) async fn prompt_email() -> Result<String, inquire::InquireError> {
    sync!(
        inquire::Text::new("Enter your email address:")
            .with_validator(inquire::required!("Email address cannot be empty."))
            .with_validator(validator::EmailValidator)
            .prompt()
    )
}

pub(crate) async fn prompt_available_email(
    cert_server: CertServer,
) -> Result<String, inquire::InquireError> {
    sync!(
        inquire::Text::new("Enter your email address:")
            .with_validator(inquire::required!("Email address cannot be empty."))
            .with_validator(validator::EmailValidator)
            .with_validator(validator::OnlineAvailableEmailValidator::new(cert_server))
            .prompt()
    )
}

pub(crate) async fn prompt_register_catpcha(
    cert_server: CertServer,
    username: String,
    email: String,
    csr_pem: String,
) -> Result<RegisterResponse, inquire::InquireError> {
    let (validate_captcha, get_response) =
        validator::RegisterCaptchaValidator::new(cert_server, username, email, csr_pem);
    sync!(
        inquire::Text::new("Enter the verification code sent to your email:")
            .with_validator(inquire::required!("Verification code cannot be empty."))
            .with_validator(inquire::length!(
                6,
                "Verification code must be exactly 6 characters."
            ))
            .with_validator(validate_captcha)
            .prompt()
    )?;
    Ok(get_response.await)
}

pub(crate) async fn prompt_login_catpcha(
    cert_server: CertServer,
    email: String,
) -> Result<LoginResponse, inquire::InquireError> {
    let (validate_captcha, get_response) =
        validator::LoginCaptchaValidator::new(cert_server, email);
    sync!(
        inquire::Text::new("Enter the verification code sent to your email:")
            .with_validator(inquire::required!("Verification code cannot be empty."))
            .with_validator(inquire::length!(
                6,
                "Verification code must be exactly 6 characters."
            ))
            .with_validator(validate_captcha)
            .prompt()
    )?;
    Ok(get_response.await)
}

pub(crate) async fn prompt_select_identities(
    names: Vec<Name<'static>>,
) -> Result<Vec<Name<'static>>, inquire::InquireError> {
    sync!(inquire::MultiSelect::new("Select the identities to re-sign:", names.to_vec()).prompt())
}

pub(crate) async fn prompt_confirm_set_as_default_name(
    name: Name<'_>,
) -> Result<bool, inquire::InquireError> {
    let message = format!("Set {name} as the default identity?");
    sync!(inquire::Confirm::new(&message).with_default(true).prompt())
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
