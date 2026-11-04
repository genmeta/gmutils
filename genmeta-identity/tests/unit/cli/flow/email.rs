use std::{cell::RefCell, collections::VecDeque};

use super::*;

fn api_error(status: reqwest::StatusCode, code: &str, message: &str) -> crate::cert_server::Error {
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
        Some("luffy.a@b"),
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
    let ui = ScriptedEmailUi::new([email("alice@example.test"), code("111111"), code("222222")]);

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

#[tokio::test]
async fn noninteractive_email_rejects_the_same_invalid_shape_before_verifying() {
    let api = FakeEmailApi::accepting("token");
    let error = run_email_session(
        &api,
        &ScriptedEmailUi::new([]),
        EmailLogin::Account,
        Some("luffy.a@b"),
        Some("000000"),
        false,
    )
    .await
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "Invalid email address. Please enter a valid email address."
    );
    assert!(api.calls().is_empty());
}
