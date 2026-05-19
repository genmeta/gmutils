use std::{borrow::Cow, fmt::Debug, sync::Arc};

use dhttp_identity::name::DhttpName as Name;
use inquire::validator::{StringValidator, Validation};
use snafu::Report;
use tokio::sync::mpsc;

use crate::cert_server::{
    self, CertServer, CheckEmailResponse, CheckUsernameResponse, LoginResponse, RegisterResponse,
};

pub(crate) fn validation_failed(message: impl ToString) -> Validation {
    Validation::Invalid(inquire::validator::ErrorMessage::from(message))
}

#[derive(Debug, Clone, Copy)]
pub struct EmailValidator;

impl StringValidator for EmailValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::CustomUserError> {
        if input.contains('@') && input.contains('.') {
            Ok(Validation::Valid)
        } else {
            Ok(validation_failed("Invalid email format."))
        }
    }
}

#[derive(Debug, Clone)]
pub struct OnlineAvailableEmailValidator {
    rt_handle: tokio::runtime::Handle,
    cert_server: CertServer,
}

impl OnlineAvailableEmailValidator {
    pub fn new(cert_server: CertServer) -> Self {
        Self {
            rt_handle: tokio::runtime::Handle::current(),
            cert_server,
        }
    }
}

impl StringValidator for OnlineAvailableEmailValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::CustomUserError> {
        self.rt_handle.block_on(async {
            match self.cert_server.check_email(input).await {
                Ok(CheckEmailResponse { exists: false }) => Ok(Validation::Valid),
                Ok(CheckEmailResponse { exists: true }) => {
                    Ok(validation_failed("Email is already registered."))
                }
                Err(error @ cert_server::Error::Code { .. }) => Ok(validation_failed(format!(
                    "Server: {}",
                    Report::from_error(error)
                ))),
                Err(error) => Err(Box::new(error) as inquire::CustomUserError),
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct UsernameValidator<'d> {
    suffix: Cow<'d, str>,
}

impl<'d> UsernameValidator<'d> {
    pub fn new(suffix: impl Into<Cow<'d, str>>) -> Self {
        Self {
            suffix: suffix.into(),
        }
    }
}

impl StringValidator for UsernameValidator<'_> {
    fn validate(&self, input: &str) -> Result<Validation, inquire::CustomUserError> {
        let name = format!("{}.{}{}", input, self.suffix, Name::SUFFIX);
        if let Err(error) = Name::validate(name.as_bytes()) {
            return Ok(validation_failed(error.to_string()));
        }
        Ok(Validation::Valid)
    }
}

#[derive(Debug, Clone)]
pub struct OnlineAvailableUsernameValidator {
    rt_handle: tokio::runtime::Handle,
    cert_server: CertServer,
}

impl OnlineAvailableUsernameValidator {
    pub fn new(cert_server: CertServer) -> Self {
        Self {
            rt_handle: tokio::runtime::Handle::current(),
            cert_server,
        }
    }
}

impl StringValidator for OnlineAvailableUsernameValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::CustomUserError> {
        self.rt_handle.block_on(async {
            match self.cert_server.check_name(input).await {
                Ok(CheckUsernameResponse { exists: false }) => Ok(Validation::Valid),
                Ok(CheckUsernameResponse { exists: true }) => {
                    Ok(validation_failed("Username is not available."))
                }
                Err(error @ cert_server::Error::Code { .. }) => Ok(validation_failed(format!(
                    "Server: {}",
                    Report::from_error(error)
                ))),
                Err(error) => Err(Box::new(error) as inquire::CustomUserError),
            }
        })
    }
}

#[derive(Clone)]
pub struct AsyncValidator {
    #[allow(clippy::type_complexity)]
    validate:
        Arc<dyn Fn(&str) -> Result<Validation, inquire::CustomUserError> + Send + Sync + 'static>,
}

impl Debug for AsyncValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnValidator").finish()
    }
}

impl AsyncValidator {
    pub fn new<F>(validate: F) -> Self
    where
        F: for<'i> AsyncFn(&'i str) -> Result<Validation, inquire::CustomUserError>
            + Send
            + Sync
            + 'static,
    {
        let rt_handle = tokio::runtime::Handle::current();
        Self {
            validate: Arc::new(move |arg: &str| rt_handle.block_on(validate(arg))),
        }
    }
}

impl StringValidator for AsyncValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::CustomUserError> {
        (self.validate)(input)
    }
}

pub(crate) fn cell<T>() -> (impl Fn(T), impl Future<Output = T>) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let set = move |value: T| _ = tx.send(value);
    let get = async move {
        match rx.recv().await {
            Some(value) => value,
            None => std::future::pending().await,
        }
    };
    (set, get)
}

#[derive(Debug, Clone)]
pub struct RegisterCaptchaValidator {
    validate: AsyncValidator,
}

impl RegisterCaptchaValidator {
    pub fn new(
        cert_server: CertServer,
        username: String,
        email: String,
        csr_pem: String,
    ) -> (
        RegisterCaptchaValidator,
        impl Future<Output = RegisterResponse>,
    ) {
        let (set_response, get_response) = cell();
        let validate = AsyncValidator::new(async move |captcha| {
            match cert_server
                .register(&username, &email, captcha, &csr_pem)
                .await
            {
                Ok(response) => {
                    set_response(response);
                    Ok(Validation::Valid)
                }
                Err(error @ cert_server::Error::Code { .. }) => Ok(validation_failed(format!(
                    "Server: {}",
                    Report::from_error(error)
                ))),
                Err(error) => Err(Box::new(error) as inquire::CustomUserError),
            }
        });

        (RegisterCaptchaValidator { validate }, get_response)
    }
}

impl StringValidator for RegisterCaptchaValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::CustomUserError> {
        self.validate.validate(input)
    }
}

#[derive(Debug, Clone)]
pub struct LoginCaptchaValidator {
    validate: AsyncValidator,
}

impl LoginCaptchaValidator {
    pub fn new(
        cert_server: CertServer,
        email: String,
    ) -> (LoginCaptchaValidator, impl Future<Output = LoginResponse>) {
        let (set_response, get_response) = cell();
        let validate = AsyncValidator::new(async move |captcha| {
            match cert_server.login(&email, captcha).await {
                Ok(response) => {
                    set_response(response);
                    Ok(Validation::Valid)
                }
                Err(error @ cert_server::Error::Code { .. }) => Ok(validation_failed(format!(
                    "Server: {}",
                    Report::from_error(error)
                ))),
                Err(error) => Err(Box::new(error) as inquire::CustomUserError),
            }
        });

        (LoginCaptchaValidator { validate }, get_response)
    }
}

impl StringValidator for LoginCaptchaValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::CustomUserError> {
        self.validate.validate(input)
    }
}
