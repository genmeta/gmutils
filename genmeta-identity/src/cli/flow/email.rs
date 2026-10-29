use std::fmt;

use snafu::FromString;

use super::recovery::{VerificationRecovery, classify_verify_submit_error};
use crate::{
    cert_server::CertServer,
    cli::{Error, prompt::InquireResultExt},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EmailLogin {
    Account,
    Domain(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MoreAction {
    Resend,
    ChangeEmail,
    Cancel,
}

impl MoreAction {
    fn label(self) -> &'static str {
        match self {
            Self::Resend => "Resend verification code",
            Self::ChangeEmail => "Change email",
            Self::Cancel => "Cancel",
        }
    }

    fn all() -> [Self; 3] {
        [Self::Resend, Self::ChangeEmail, Self::Cancel]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EmailSessionError {
    Cancelled,
    NonInteractivePairRequired,
}

impl fmt::Display for EmailSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Email verification was cancelled."),
            Self::NonInteractivePairRequired => {
                f.write_str("Email verification requires an interactive terminal for this command.")
            }
        }
    }
}

impl std::error::Error for EmailSessionError {}

fn session_error(error: EmailSessionError) -> Error {
    Error::without_source(error.to_string())
}

trait EmailApi {
    async fn send(&self, email: &str) -> Result<(), crate::cert_server::Error>;

    async fn verify(
        &self,
        login: &EmailLogin,
        email: &str,
        code: &str,
    ) -> Result<String, crate::cert_server::Error>;
}

trait EmailUi {
    async fn prompt_email(&self, default: Option<&str>) -> Result<String, Error>;
    async fn prompt_code(&self) -> Result<crate::cli::prompt::TextPromptResult, Error>;
    async fn choose_more_action(&self) -> Result<MoreAction, Error>;
    async fn confirm_resend(&self) -> Result<bool, Error>;
    fn print_server_message(&self, message: &str);
}

struct CertServerEmailApi<'a> {
    cert_server: &'a CertServer,
}

impl<'a> CertServerEmailApi<'a> {
    fn new(cert_server: &'a CertServer) -> Self {
        Self { cert_server }
    }
}

impl EmailApi for CertServerEmailApi<'_> {
    async fn send(&self, email: &str) -> Result<(), crate::cert_server::Error> {
        self.cert_server
            .send_email_verification(email)
            .await
            .map(|_| ())
    }

    async fn verify(
        &self,
        login: &EmailLogin,
        email: &str,
        code: &str,
    ) -> Result<String, crate::cert_server::Error> {
        match login {
            EmailLogin::Account => self
                .cert_server
                .login(email, code)
                .await
                .map(|response| response.access_token),
            EmailLogin::Domain(domain) => self
                .cert_server
                .domain_login(domain, email, code)
                .await
                .map(|response| response.access_token),
        }
    }
}

struct InquireEmailUi;

impl EmailUi for InquireEmailUi {
    async fn prompt_email(&self, default: Option<&str>) -> Result<String, Error> {
        crate::cli::prompt::prompt_email_with_default(default)
            .await
            .require_interactive("--email")
            .map_err(Error::from)
    }

    async fn prompt_code(&self) -> Result<crate::cli::prompt::TextPromptResult, Error> {
        crate::cli::prompt::prompt_verify_code_with_more_options(None)
            .await
            .require_interactive("--verify-code")
            .map_err(Error::from)
    }

    async fn choose_more_action(&self) -> Result<MoreAction, Error> {
        let actions = MoreAction::all();
        let labels = actions
            .iter()
            .map(|action| action.label().to_string())
            .collect::<Vec<_>>();
        let selected = crate::cli::prompt::prompt_select_string("More options:", labels)
            .await
            .require_interactive("interactive input")?;
        Ok(actions
            .into_iter()
            .find(|action| action.label() == selected)
            .expect("inquire returned an option that was not provided"))
    }

    async fn confirm_resend(&self) -> Result<bool, Error> {
        crate::cli::prompt::confirm_send_new_verification_code()
            .await
            .require_interactive("interactive input")
            .map_err(Error::from)
    }

    fn print_server_message(&self, message: &str) {
        super::transcript::print_line(message);
    }
}

pub(crate) async fn run_cert_server_email_session(
    cert_server: &CertServer,
    login: EmailLogin,
    email: Option<&str>,
    verify_code: Option<&str>,
    interactive: bool,
) -> Result<String, Error> {
    run_email_session(
        &CertServerEmailApi::new(cert_server),
        &InquireEmailUi,
        login,
        email,
        verify_code,
        interactive,
    )
    .await
}

async fn run_email_session<A, U>(
    api: &A,
    ui: &U,
    login: EmailLogin,
    initial_email: Option<&str>,
    initial_verify_code: Option<&str>,
    interactive: bool,
) -> Result<String, Error>
where
    A: EmailApi,
    U: EmailUi,
{
    if !interactive {
        let (Some(email), Some(code)) = (initial_email, initial_verify_code) else {
            return Err(session_error(EmailSessionError::NonInteractivePairRequired));
        };
        if !crate::cli::validator::is_valid_email(email) {
            return Err(Error::without_source(
                "Invalid email address. Please enter a valid email address.".to_string(),
            ));
        }
        return super::progress::run(
            super::progress::VERIFY_EMAIL,
            api.verify(&login, email, code),
        )
        .await
        .map_err(Error::from);
    }

    let mut email = initial_email
        .filter(|email| crate::cli::validator::is_valid_email(email))
        .map(ToOwned::to_owned);
    let mut verify_code = initial_verify_code.map(ToOwned::to_owned);
    let mut sent_to = initial_verify_code
        .is_some()
        .then(|| initial_email.map(ToOwned::to_owned))
        .flatten();

    loop {
        let current_email = match email.clone() {
            Some(email) => email,
            None => {
                let prompted = ui.prompt_email(None).await?;
                if initial_verify_code.is_some() && verify_code.is_some() {
                    sent_to = Some(prompted.clone());
                }
                email = Some(prompted.clone());
                prompted
            }
        };

        if verify_code.is_none() && sent_to.as_deref() != Some(current_email.as_str()) {
            super::progress::run(super::progress::SEND_CODE, api.send(&current_email))
                .await
                .map_err(Error::from)?;
            sent_to = Some(current_email.clone());
        }

        if verify_code.is_none() {
            match ui.prompt_code().await? {
                crate::cli::prompt::TextPromptResult::Submitted(code) => {
                    verify_code = Some(code);
                }
                crate::cli::prompt::TextPromptResult::MoreOptions => {
                    match ui.choose_more_action().await? {
                        MoreAction::Resend => {
                            super::progress::run(
                                super::progress::SEND_CODE,
                                api.send(&current_email),
                            )
                            .await
                            .map_err(Error::from)?;
                            sent_to = Some(current_email);
                        }
                        MoreAction::ChangeEmail => {
                            email = None;
                            sent_to = None;
                        }
                        MoreAction::Cancel => {
                            return Err(session_error(EmailSessionError::Cancelled));
                        }
                    }
                    continue;
                }
            }
        }

        let code = verify_code
            .as_deref()
            .expect("verification code was collected before verification");
        match super::progress::run(
            super::progress::VERIFY_EMAIL,
            api.verify(&login, &current_email, code),
        )
        .await
        {
            Ok(token) => return Ok(token),
            Err(error) => match classify_verify_submit_error(&error) {
                VerificationRecovery::RetryCode { message } => {
                    ui.print_server_message(&message);
                    verify_code = None;
                }
                VerificationRecovery::OfferResend { message } => {
                    ui.print_server_message(&message);
                    verify_code = None;
                    if ui.confirm_resend().await? {
                        sent_to = None;
                    }
                }
                VerificationRecovery::ChangeEmail { message } => {
                    ui.print_server_message(&message);
                    email = None;
                    verify_code = None;
                    sent_to = None;
                }
                VerificationRecovery::Stop => return Err(Error::from(error)),
            },
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/email.rs"]
mod tests;
