use std::{borrow::Cow, fmt::Display};

use genmeta_home::identity::{Identities, Name, fs::LoadIdentityError};
use snafu::Report;

use crate::{
    REGISTERABLE_DOMAINS,
    cert_server::{CertServer, LoginResponse, RegisterResponse},
    cli::validator,
};

#[derive(Debug)]
pub struct Error {
    source: inquire::InquireError,
}

impl From<inquire::InquireError> for Error {
    fn from(source: inquire::InquireError) -> Self {
        Self { source }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Inquire 的错误打印太垃圾了，自己实现一下
        match &self.source {
            inquire::InquireError::IO(error) => error.fmt(f),
            inquire::InquireError::Custom(error) => error.fmt(f),
            source => source.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.source {
            inquire::InquireError::IO(error) => error.source(),
            inquire::InquireError::Custom(error) => error.source(),
            _ => None,
        }
    }
}

pub(crate) async fn sync<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f)
        .await
        .expect("blocking task panicked")
}

/// sync!( sync_code() )
macro_rules! sync {
    ($body:expr) => {
        sync(move || $body).await
    };
}

pub(crate) async fn prompt_domain() -> Result<&'static str, inquire::InquireError> {
    sync!(
        inquire::Select::new(
            "Select a domain suffix for registration",
            REGISTERABLE_DOMAINS.to_vec()
        )
        .prompt()
    )
}

pub(crate) async fn prompt_available_username(
    cert_server: CertServer,
    domain: impl Into<Cow<'static, str>> + Send + 'static,
) -> Result<String, inquire::InquireError> {
    sync!(
        inquire::Text::new("Enter your desired username:")
            .with_validator(inquire::required!("Username cannot be empty."))
            .with_validator(validator::UsernameValidator::new(domain))
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
        inquire::Text::new("Enter the registration verification code sent to your email:")
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
        inquire::Text::new("Enter the login verification code sent to your email:")
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

pub(crate) async fn prompt_select_one_name(
    message: impl Into<Cow<'static, str>> + Send + 'static,
    names: Vec<Name<'static>>,
) -> Result<Name<'static>, inquire::InquireError> {
    sync!(inquire::Select::new(&message.into(), names).prompt())
}

pub(crate) async fn prompt_select_resign_domains(
    domains: Vec<Name<'static>>,
) -> Result<Vec<Name<'static>>, inquire::InquireError> {
    sync!(inquire::MultiSelect::new("Select domains to re-sign:", domains.to_vec()).prompt())
}

pub(crate) async fn prompt_select_default_name(
    current: Option<Name<'_>>,
    names: Vec<Name<'static>>,
) -> Result<Name<'static>, inquire::InquireError> {
    let message: Cow<'static, str> = match current {
        Some(ref domain) => format!("Select default identity (current: {domain}):",).into(),
        None => "Select default identity:".into(),
    };
    prompt_select_one_name(message, names).await
}

pub(crate) async fn prompt_confirm_set_as_default_name(
    name: Name<'_>,
) -> Result<bool, inquire::InquireError> {
    let message = format!("Set {name} as the default identity? (default: yes)");
    sync!(inquire::Confirm::new(&message).with_default(true).prompt())
}

pub(crate) async fn prompt_confim_update_default_name(
    current: Name<'_>,
    new: Name<'_>,
) -> Result<bool, inquire::InquireError> {
    let message = format!("Current default identity is {current}, change to {new}? (default: no)");
    sync!(inquire::Confirm::new(&message).with_default(false).prompt())
}

pub(crate) async fn prompt_confirm_select_default_name_not_exist(
    identities: &Identities,
    selected: Name<'_>,
    load_error: LoadIdentityError,
) -> Result<bool, inquire::InquireError> {
    let message = format!(
        "Selected identity {selected} could not be loaded from {}: {}.\nProceed anyway? (default: no)",
        identities.as_path().display(),
        Report::from_error(load_error)
    );
    sync!(inquire::Confirm::new(&message).with_default(false).prompt())
}
