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
mod tests {
    use std::{cell::RefCell, collections::VecDeque};

    use super::*;

    fn api_error(
        status: reqwest::StatusCode,
        code: &str,
        message: &str,
    ) -> crate::cert_server::Error {
        crate::cert_server::Error::Api {
            status,
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    fn request_error(message: &str) -> crate::cert_server::Error {
        use snafu::FromString;

        crate::cert_server::Error::Whatever {
            source: snafu::Whatever::without_source(message.to_string()),
        }
    }

    struct FakeEmailApi {
        calls: RefCell<Vec<String>>,
        send_results: RefCell<VecDeque<Result<(), crate::cert_server::Error>>>,
        verify_results: RefCell<VecDeque<Result<String, crate::cert_server::Error>>>,
    }

    impl FakeEmailApi {
        fn accepting(token: &str) -> Self {
            Self::with_verify_results([Ok(token.to_string())])
        }

        fn with_verify_results(
            results: impl IntoIterator<Item = Result<String, crate::cert_server::Error>>,
        ) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                send_results: RefCell::new(VecDeque::new()),
                verify_results: RefCell::new(results.into_iter().collect()),
            }
        }

        fn failing_send(error: crate::cert_server::Error) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                send_results: RefCell::new([Err(error)].into()),
                verify_results: RefCell::new(VecDeque::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn send_count(&self) -> usize {
            self.calls
                .borrow()
                .iter()
                .filter(|call| call.starts_with("send:"))
                .count()
        }
    }

    impl EmailApi for FakeEmailApi {
        async fn send(&self, email: &str) -> Result<(), crate::cert_server::Error> {
            self.calls.borrow_mut().push(format!("send:{email}"));
            self.send_results.borrow_mut().pop_front().unwrap_or(Ok(()))
        }

        async fn verify(
            &self,
            login: &EmailLogin,
            email: &str,
            code: &str,
        ) -> Result<String, crate::cert_server::Error> {
            let login = match login {
                EmailLogin::Account => "account",
                EmailLogin::Domain(_) => "domain",
            };
            self.calls
                .borrow_mut()
                .push(format!("verify-{login}:{email}:{code}"));
            self.verify_results
                .borrow_mut()
                .pop_front()
                .expect("test must provide a verification result")
        }
    }

    enum UiEvent {
        Email(String),
        Code(String),
        MoreOptions,
        Choose(MoreAction),
        Confirm(bool),
    }

    fn email(value: &str) -> UiEvent {
        UiEvent::Email(value.to_string())
    }

    fn code(value: &str) -> UiEvent {
        UiEvent::Code(value.to_string())
    }

    fn more_options() -> UiEvent {
        UiEvent::MoreOptions
    }

    fn choose(value: &str) -> UiEvent {
        UiEvent::Choose(
            MoreAction::all()
                .into_iter()
                .find(|action| action.label() == value)
                .expect("test action label must be valid"),
        )
    }

    fn confirm(value: bool) -> UiEvent {
        UiEvent::Confirm(value)
    }

    struct ScriptedEmailUi {
        events: RefCell<VecDeque<UiEvent>>,
        messages: RefCell<Vec<String>>,
        confirm_questions: RefCell<Vec<String>>,
        code_prompt_count: RefCell<usize>,
    }

    impl ScriptedEmailUi {
        fn new(events: impl IntoIterator<Item = UiEvent>) -> Self {
            Self {
                events: RefCell::new(events.into_iter().collect()),
                messages: RefCell::new(Vec::new()),
                confirm_questions: RefCell::new(Vec::new()),
                code_prompt_count: RefCell::new(0),
            }
        }

        fn next(&self) -> UiEvent {
            self.events
                .borrow_mut()
                .pop_front()
                .expect("scripted UI event is missing")
        }

        fn printed_messages(&self) -> Vec<String> {
            self.messages.borrow().clone()
        }

        fn confirm_questions(&self) -> Vec<String> {
            self.confirm_questions.borrow().clone()
        }

        fn code_prompt_count(&self) -> usize {
            *self.code_prompt_count.borrow()
        }
    }

    impl EmailUi for ScriptedEmailUi {
        async fn prompt_email(&self, _default: Option<&str>) -> Result<String, Error> {
            match self.next() {
                UiEvent::Email(email) => Ok(email),
                _ => panic!("expected a scripted email"),
            }
        }

        async fn prompt_code(&self) -> Result<crate::cli::prompt::TextPromptResult, Error> {
            *self.code_prompt_count.borrow_mut() += 1;
            match self.next() {
                UiEvent::Code(code) => Ok(crate::cli::prompt::TextPromptResult::Submitted(code)),
                UiEvent::MoreOptions => Ok(crate::cli::prompt::TextPromptResult::MoreOptions),
                _ => panic!("expected a scripted verification code action"),
            }
        }

        async fn choose_more_action(&self) -> Result<MoreAction, Error> {
            match self.next() {
                UiEvent::Choose(action) => Ok(action),
                _ => panic!("expected a scripted more-options choice"),
            }
        }

        async fn confirm_resend(&self) -> Result<bool, Error> {
            self.confirm_questions
                .borrow_mut()
                .push("Send a new verification code?".to_string());
            match self.next() {
                UiEvent::Confirm(confirm) => Ok(confirm),
                _ => panic!("expected a scripted resend confirmation"),
            }
        }

        fn print_server_message(&self, message: &str) {
            self.messages.borrow_mut().push(message.to_string());
        }
    }

    #[tokio::test]
    async fn interactive_session_sends_once_then_verifies() {
        let api = FakeEmailApi::accepting("token");
        let ui = ScriptedEmailUi::new([email("alice@example.test"), code("123456")]);

        let token = run_email_session(&api, &ui, EmailLogin::Account, None, None, true)
            .await
            .unwrap();

        assert_eq!(token, "token");
        assert_eq!(
            api.calls(),
            [
                "send:alice@example.test",
                "verify-account:alice@example.test:123456"
            ]
        );
    }

    #[tokio::test]
    async fn invalid_prefilled_email_returns_to_email_input_before_sending() {
        let api = FakeEmailApi::accepting("token");
        let ui = ScriptedEmailUi::new([email("alice@example.test"), code("123456")]);

        let token = run_email_session(
            &api,
            &ui,
            EmailLogin::Account,
            Some("not-an-email"),
            None,
            true,
        )
        .await
        .unwrap();

        assert_eq!(token, "token");
        assert_eq!(
            api.calls(),
            [
                "send:alice@example.test",
                "verify-account:alice@example.test:123456"
            ]
        );
    }

    #[tokio::test]
    async fn question_mark_keeps_resend_change_email_and_cancel() {
        let api = FakeEmailApi::accepting("token");
        let ui = ScriptedEmailUi::new([
            email("old@example.test"),
            more_options(),
            choose("Change email"),
            email("new@example.test"),
            code("123456"),
        ]);

        run_email_session(&api, &ui, EmailLogin::Account, None, None, true)
            .await
            .unwrap();

        assert_eq!(
            api.calls(),
            [
                "send:old@example.test",
                "send:new@example.test",
                "verify-account:new@example.test:123456",
            ]
        );
    }

    #[tokio::test]
    async fn question_mark_can_resend_without_changing_email() {
        let api = FakeEmailApi::accepting("token");
        let ui = ScriptedEmailUi::new([
            email("alice@example.test"),
            more_options(),
            choose("Resend verification code"),
            code("123456"),
        ]);

        run_email_session(&api, &ui, EmailLogin::Account, None, None, true)
            .await
            .unwrap();

        assert_eq!(
            api.calls(),
            [
                "send:alice@example.test",
                "send:alice@example.test",
                "verify-account:alice@example.test:123456",
            ]
        );
    }

    #[tokio::test]
    async fn question_mark_can_cancel_without_verifying() {
        let api = FakeEmailApi::accepting("token");
        let ui = ScriptedEmailUi::new([
            email("alice@example.test"),
            more_options(),
            choose("Cancel"),
        ]);

        let error = run_email_session(&api, &ui, EmailLogin::Account, None, None, true)
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), "Email verification was cancelled.");
        assert_eq!(api.calls(), ["send:alice@example.test"]);
    }

    #[tokio::test]
    async fn invalid_code_reprompts_without_resending() {
        let api = FakeEmailApi::with_verify_results([
            Err(api_error(
                reqwest::StatusCode::UNAUTHORIZED,
                "verify_code_invalid",
                "verification code is incorrect",
            )),
            Ok("token".to_string()),
        ]);
        let ui =
            ScriptedEmailUi::new([email("alice@example.test"), code("111111"), code("222222")]);

        let token = run_email_session(&api, &ui, EmailLogin::Account, None, None, true)
            .await
            .unwrap();

        assert_eq!(token, "token");
        assert_eq!(api.send_count(), 1);
        assert_eq!(ui.printed_messages(), ["verification code is incorrect"]);
    }

    #[tokio::test]
    async fn expired_code_resends_only_after_yes() {
        let api = FakeEmailApi::with_verify_results([
            Err(api_error(
                reqwest::StatusCode::UNAUTHORIZED,
                "verify_code_expired",
                "verification code expired",
            )),
            Ok("token".to_string()),
        ]);
        let ui = ScriptedEmailUi::new([
            email("alice@example.test"),
            code("111111"),
            confirm(true),
            code("222222"),
        ]);

        run_email_session(&api, &ui, EmailLogin::Account, None, None, true)
            .await
            .unwrap();

        assert_eq!(api.send_count(), 2);
        assert_eq!(ui.confirm_questions(), ["Send a new verification code?"]);
    }

    #[tokio::test]
    async fn expired_code_no_returns_to_code_without_send() {
        let api = FakeEmailApi::with_verify_results([
            Err(api_error(
                reqwest::StatusCode::UNAUTHORIZED,
                "verify_code_expired",
                "verification code expired",
            )),
            Ok("token".to_string()),
        ]);
        let ui = ScriptedEmailUi::new([
            email("alice@example.test"),
            code("111111"),
            confirm(false),
            code("222222"),
        ]);

        run_email_session(&api, &ui, EmailLogin::Account, None, None, true)
            .await
            .unwrap();

        assert_eq!(api.send_count(), 1);
    }

    #[tokio::test]
    async fn send_failure_does_not_enter_code_input_or_mark_sent() {
        let api = FakeEmailApi::failing_send(request_error("network unavailable"));
        let ui = ScriptedEmailUi::new([email("alice@example.test")]);

        assert!(
            run_email_session(&api, &ui, EmailLogin::Account, None, None, true)
                .await
                .is_err()
        );
        assert_eq!(api.send_count(), 1);
        assert_eq!(ui.code_prompt_count(), 0);
    }

    async fn run_noninteractive_fixture(
        email: Option<&str>,
        code: Option<&str>,
    ) -> Result<FakeEmailApi, Error> {
        let api = FakeEmailApi::accepting("token");
        run_email_session(
            &api,
            &ScriptedEmailUi::new([]),
            EmailLogin::Account,
            email,
            code,
            false,
        )
        .await?;
        Ok(api)
    }

    #[tokio::test]
    async fn noninteractive_email_requires_both_email_and_hidden_code_and_never_sends() {
        for (email, code) in [
            (None, None),
            (Some("a@b.test"), None),
            (None, Some("000000")),
        ] {
            let error = match run_noninteractive_fixture(email, code).await {
                Ok(_) => panic!("incomplete hidden test input unexpectedly authenticated"),
                Err(error) => error,
            };
            assert!(
                !error.to_string().contains("--verify-code"),
                "hidden test input leaked into public error copy: {error}"
            );
            assert!(
                error.to_string().contains("interactive terminal"),
                "{error}"
            );
        }

        let api = run_noninteractive_fixture(Some("a@b.test"), Some("000000"))
            .await
            .unwrap();
        assert_eq!(api.calls(), ["verify-account:a@b.test:000000"]);
    }
}
