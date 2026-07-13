use std::io::IsTerminal;

use dhttp::home::{DhttpHome, HomeScope};
use snafu::{OptionExt, whatever};
use tracing::Instrument;

use super::local;
use crate::{
    auth::AuthMethod,
    cert_server::CertServer,
    cli::{self, Error, Renew, prompt::InquireResultExt},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum RenewApprovalPlan {
    Email,
    Identity { auth_domain: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RenewEmailAction {
    SwitchVerificationMethod,
    ChangeIdentitySelection,
}

impl RenewEmailAction {
    fn label(&self) -> String {
        match self {
            Self::SwitchVerificationMethod => {
                "Switch verification method (go back to verification method selection)".to_string()
            }
            Self::ChangeIdentitySelection => {
                "Change identity (go back to identity selection)".to_string()
            }
        }
    }
}

fn renew_email_actions() -> Vec<RenewEmailAction> {
    vec![
        RenewEmailAction::SwitchVerificationMethod,
        RenewEmailAction::ChangeIdentitySelection,
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RenewVerifyCodeAction {
    ResendVerificationCode,
    ChangeEmail,
    SwitchVerificationMethod,
    ChangeIdentitySelection,
}

impl RenewVerifyCodeAction {
    fn label(&self) -> String {
        match self {
            Self::ResendVerificationCode => "Resend verification code".to_string(),
            Self::ChangeEmail => "Send code to another email (go back to email)".to_string(),
            Self::SwitchVerificationMethod => {
                "Switch verification method (go back to verification method selection)".to_string()
            }
            Self::ChangeIdentitySelection => {
                "Change identity (go back to identity selection)".to_string()
            }
        }
    }
}

fn renew_verify_code_actions() -> Vec<RenewVerifyCodeAction> {
    vec![
        RenewVerifyCodeAction::ResendVerificationCode,
        RenewVerifyCodeAction::ChangeEmail,
        RenewVerifyCodeAction::SwitchVerificationMethod,
        RenewVerifyCodeAction::ChangeIdentitySelection,
    ]
}

#[derive(Debug, Clone)]
struct InteractiveRenewState {
    target: Option<dhttp::name::DhttpName<'static>>,
    approval_plan: Option<RenewApprovalPlan>,
    email: Option<String>,
    email_prompt_required: bool,
    verify_code: Option<String>,
    verification_code_sent_to: Option<String>,
}

impl InteractiveRenewState {
    fn from_command(command: &Renew, target: Option<dhttp::name::DhttpName<'static>>) -> Self {
        Self {
            target,
            approval_plan: None,
            email: command.email.clone(),
            email_prompt_required: command.email.is_none(),
            verify_code: command.verify_code.clone(),
            verification_code_sent_to: None,
        }
    }

    fn revisit_target_selection(&mut self) {
        self.target = None;
        self.approval_plan = None;
        self.email = None;
        self.email_prompt_required = true;
        self.verify_code = None;
        self.verification_code_sent_to = None;
    }

    fn revisit_email(&mut self) {
        self.email_prompt_required = true;
        self.verify_code = None;
        self.verification_code_sent_to = None;
    }

    fn revisit_verification_method(&mut self) {
        self.approval_plan = None;
        self.email = None;
        self.email_prompt_required = true;
        self.verify_code = None;
        self.verification_code_sent_to = None;
    }
}

fn apply_verification_recovery(
    state: &mut InteractiveRenewState,
    recovery: &crate::cli::flow::recovery::VerificationRecovery,
) -> bool {
    match recovery {
        crate::cli::flow::recovery::VerificationRecovery::StayCurrentStep { message } => {
            crate::cli::flow::transcript::print_line(message);
            true
        }
        crate::cli::flow::recovery::VerificationRecovery::OfferResend { message } => {
            crate::cli::flow::transcript::print_line(message);
            true
        }
        crate::cli::flow::recovery::VerificationRecovery::BackToEmail { message } => {
            crate::cli::flow::transcript::print_line(message);
            state.revisit_email();
            true
        }
        crate::cli::flow::recovery::VerificationRecovery::Abort => false,
    }
}

async fn offer_expired_code_resend(
    state: &mut InteractiveRenewState,
    cert_server: &CertServer,
    email: &str,
    message: &str,
) -> Result<(), Error> {
    crate::cli::flow::transcript::print_line(message);
    let resend = crate::cli::prompt::sync(|| {
        inquire::Confirm::new("Send a new verification code?")
            .with_default(true)
            .prompt()
    })
    .await
    .require_interactive("interactive input")?;
    if resend {
        super::progress::run_with_spinner(
            "Sending verification code...",
            cert_server.send_email_verification(email),
        )
        .await?;
        state.verification_code_sent_to = Some(email.to_string());
    }
    state.verify_code = None;
    Ok(())
}

fn renew_not_saved_root_message(short_name: &str) -> String {
    format!(
        "The identity {short_name} is not saved here.\n\nRenew updates an identity already saved here.\nThis identity has not been applied here yet.\n\nApply {short_name} here first, then return to renew."
    )
}

async fn ensure_saved_renew_target(
    dhttp_home: &DhttpHome,
    name: dhttp::name::DhttpName<'_>,
) -> Result<(), Error> {
    if local::try_load_summary(dhttp_home, name.borrow(), None)
        .await?
        .is_some()
    {
        return Ok(());
    }

    whatever!("{}", renew_not_saved_root_message(name.as_partial()));
}

fn resolve_non_interactive_approval_plan(
    target: &str,
    requested_auth: Option<AuthMethod>,
    ready_identity: Option<&str>,
) -> Result<RenewApprovalPlan, Error> {
    match requested_auth {
        Some(AuthMethod::Email) => Ok(RenewApprovalPlan::Email),
        Some(AuthMethod::Identity) => ready_identity
            .map(|auth_domain| RenewApprovalPlan::Identity {
                auth_domain: auth_domain.to_string(),
            })
            .whatever_context::<_, Error>(format!(
                "renewing {target} cannot use local identity verification because neither it nor its parent has a ready local certificate; use --auth email"
            )),
        None => Ok(match ready_identity {
            Some(auth_domain) => RenewApprovalPlan::Identity {
                auth_domain: auth_domain.to_string(),
            },
            None => RenewApprovalPlan::Email,
        }),
    }
}

async fn resolve_target(
    command: &Renew,
    dhttp_home: &DhttpHome,
) -> Result<dhttp::name::DhttpName<'static>, Error> {
    match command.name.as_deref() {
        Some(name) => cli::parse_identity_name(name),
        None => cli::resolve_default_target_name(dhttp_home).await,
    }
}

async fn resolve_email(command: &Renew) -> Result<String, Error> {
    match command.email.clone() {
        Some(email) => Ok(email),
        None => Ok(crate::cli::prompt::prompt_email()
            .await
            .require_interactive("--email")?),
    }
}

async fn prompt_renew_email_action() -> Result<RenewEmailAction, Error> {
    let actions = renew_email_actions();
    let labels = actions
        .iter()
        .map(RenewEmailAction::label)
        .collect::<Vec<_>>();
    let selected = crate::cli::prompt::prompt_select_string("More options:", labels.clone())
        .await
        .require_interactive("interactive input")?;
    actions
        .into_iter()
        .zip(labels)
        .find_map(|(action, label)| (label == selected).then_some(action))
        .whatever_context::<_, Error>("selected renew email action is unavailable")
}

async fn prompt_renew_verify_code_action() -> Result<RenewVerifyCodeAction, Error> {
    let actions = renew_verify_code_actions();
    let labels = actions
        .iter()
        .map(RenewVerifyCodeAction::label)
        .collect::<Vec<_>>();
    let selected = crate::cli::prompt::prompt_select_string("More options:", labels.clone())
        .await
        .require_interactive("interactive input")?;
    actions
        .into_iter()
        .zip(labels)
        .find_map(|(action, label)| (label == selected).then_some(action))
        .whatever_context::<_, Error>("selected renew action is unavailable")
}

async fn run_interactive(
    command: &Renew,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
) -> Result<(), Error> {
    let initial_target = match command.name.as_deref() {
        Some(name) => cli::parse_identity_name(name)?,
        None => cli::resolve_default_target_name(dhttp_home).await?,
    };
    let mut state = InteractiveRenewState::from_command(command, Some(initial_target));

    loop {
        let domain = state
            .target
            .clone()
            .whatever_context::<_, Error>("interactive renew target is unavailable")?;
        ensure_saved_renew_target(dhttp_home, domain.borrow()).await?;

        if state.approval_plan.is_none() {
            let target = crate::cli::flow::target::IdentityTarget::parse(domain.as_partial())?;
            let auth_plan = super::auth_plan::load_apply_auth_plan(dhttp_home, &target).await?;
            for warning in &auth_plan.warnings {
                crate::cli::flow::transcript::print_err_block(warning);
            }
            state.approval_plan = Some(resolve_non_interactive_approval_plan(
                domain.as_partial(),
                command.auth,
                auth_plan.first_identity_full_name(),
            )?);
            continue;
        }

        let approval_plan = state
            .approval_plan
            .clone()
            .whatever_context::<_, Error>("interactive renew approval plan is unavailable")?;
        if matches!(approval_plan, RenewApprovalPlan::Email)
            && (state.email.is_none() || state.email_prompt_required)
        {
            match crate::cli::prompt::prompt_email_with_more_options(state.email.as_deref())
                .await
                .require_interactive("--email")?
            {
                crate::cli::prompt::TextPromptResult::Submitted(email) => {
                    state.email = Some(email);
                    state.email_prompt_required = false;
                }
                crate::cli::prompt::TextPromptResult::MoreOptions => {
                    match prompt_renew_email_action().await? {
                        RenewEmailAction::SwitchVerificationMethod => {
                            state.revisit_verification_method();
                        }
                        RenewEmailAction::ChangeIdentitySelection => {
                            state.revisit_target_selection();
                        }
                    }
                }
            }
            continue;
        }

        if matches!(approval_plan, RenewApprovalPlan::Email) && state.verify_code.is_none() {
            let email = state
                .email
                .clone()
                .whatever_context::<_, Error>("interactive renew email is unavailable")?;
            if state.verification_code_sent_to.as_deref() != Some(email.as_str()) {
                match super::progress::run_with_spinner(
                    "Sending verification code...",
                    cert_server.send_email_verification(&email),
                )
                .await
                {
                    Ok(_) => {
                        state.verification_code_sent_to = Some(email.clone());
                    }
                    Err(error) => {
                        let recovery = crate::cli::flow::recovery::classify_resend_error(&error);
                        if matches!(
                            recovery,
                            crate::cli::flow::recovery::VerificationRecovery::StayCurrentStep { .. }
                        ) {
                            state.verification_code_sent_to = Some(email.clone());
                        }
                        if apply_verification_recovery(&mut state, &recovery) {
                            continue;
                        }
                        return Err(Error::from(error));
                    }
                }
            }
            match crate::cli::prompt::prompt_verify_code_with_more_options(None)
                .await
                .require_interactive("--verify-code")?
            {
                crate::cli::prompt::TextPromptResult::Submitted(code) => {
                    state.verify_code = Some(code);
                }
                crate::cli::prompt::TextPromptResult::MoreOptions => {
                    match prompt_renew_verify_code_action().await? {
                        RenewVerifyCodeAction::ResendVerificationCode => {
                            match super::progress::run_with_spinner(
                                "Sending verification code...",
                                cert_server.send_email_verification(&email),
                            )
                            .await
                            {
                                Ok(_) => {
                                    state.verification_code_sent_to = Some(email);
                                }
                                Err(error) => {
                                    let recovery =
                                        crate::cli::flow::recovery::classify_resend_error(&error);
                                    if apply_verification_recovery(&mut state, &recovery) {
                                        continue;
                                    }
                                    return Err(Error::from(error));
                                }
                            }
                        }
                        RenewVerifyCodeAction::ChangeEmail => state.revisit_email(),
                        RenewVerifyCodeAction::SwitchVerificationMethod => {
                            state.revisit_verification_method();
                        }
                        RenewVerifyCodeAction::ChangeIdentitySelection => {
                            state.revisit_target_selection();
                        }
                    }
                }
            }
            continue;
        }

        let identity_profile = dhttp_home.resolve_identity_profile(domain.borrow()).await?;
        let local_identity = identity_profile.load_identity().await?;
        let chain_key = cli::certificate_chain_key_from_identity(&local_identity)?
            .whatever_context::<_, Error>("local identity does not expose a certificate chain")?;
        let kind = chain_key.kind().as_str();
        let sequence = chain_key.sequence().get();
        let device_name =
            super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
        let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&domain)?;

        let detail = match approval_plan {
            RenewApprovalPlan::Email => {
                let email = state
                    .email
                    .clone()
                    .whatever_context::<_, Error>("interactive renew email is unavailable")?;
                let verify_code = state.verify_code.as_deref().whatever_context::<_, Error>(
                    "interactive renew verification code is unavailable",
                )?;
                let token = match super::progress::run_with_spinner(
                    "Verifying with email...",
                    cert_server.domain_login(domain.as_full(), &email, verify_code),
                )
                .await
                {
                    Ok(login) => login.access_token,
                    Err(error) => {
                        let recovery =
                            crate::cli::flow::recovery::classify_verify_submit_error(&error);
                        if let crate::cli::flow::recovery::VerificationRecovery::OfferResend {
                            message,
                        } = &recovery
                        {
                            offer_expired_code_resend(&mut state, cert_server, &email, message)
                                .await?;
                            continue;
                        }
                        if matches!(
                            recovery,
                            crate::cli::flow::recovery::VerificationRecovery::StayCurrentStep { .. }
                        ) {
                            state.verify_code = None;
                        }
                        if apply_verification_recovery(&mut state, &recovery) {
                            continue;
                        }
                        return Err(Error::from(error));
                    }
                };
                super::progress::run_with_spinner(
                    "Renewing identity...",
                    cert_server.renew_cert(
                        &token,
                        domain.as_full(),
                        kind,
                        sequence,
                        Some(&device_name),
                        &csr_pem,
                    ),
                )
                .await?
            }
            RenewApprovalPlan::Identity { auth_domain } => {
                super::progress::run_with_spinner(
                    "Renewing identity...",
                    cert_server.renew_cert_with_identity(
                        &auth_domain,
                        domain.as_full(),
                        kind,
                        sequence,
                        Some(&device_name),
                        &csr_pem,
                    ),
                )
                .await?
            }
        };

        cli::save_identity(
            dhttp_home,
            &domain,
            key_pem.as_bytes(),
            detail.cert_pem.as_bytes(),
        )
        .instrument(super::progress::save_identity_span())
        .await?;
        return Ok(());
    }
}

pub(crate) async fn run(
    command: &Renew,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
) -> Result<(), Error> {
    let is_interactive = std::io::stdin().is_terminal();
    if is_interactive && !command.send_code {
        return run_interactive(command, dhttp_home, home_scope, cert_server).await;
    }
    let domain = resolve_target(command, dhttp_home).await?;
    ensure_saved_renew_target(dhttp_home, domain.borrow()).await?;
    let target = crate::cli::flow::target::IdentityTarget::parse(domain.as_partial())?;
    let auth_plan = super::auth_plan::load_apply_auth_plan(dhttp_home, &target).await?;
    for warning in &auth_plan.warnings {
        crate::cli::flow::transcript::print_err_block(warning);
    }
    let approval_plan = resolve_non_interactive_approval_plan(
        domain.as_partial(),
        command.auth,
        auth_plan.first_identity_full_name(),
    )?;
    let identity_profile = dhttp_home.resolve_identity_profile(domain.borrow()).await?;
    let local_identity = identity_profile.load_identity().await?;
    let chain_key = cli::certificate_chain_key_from_identity(&local_identity)?
        .whatever_context::<_, Error>("local identity does not expose a certificate chain")?;
    let kind = chain_key.kind().as_str();
    let sequence = chain_key.sequence().get();
    let device_name =
        super::device::resolve_device_name(command.device_name.as_deref(), home_scope);

    if command.send_code {
        if !matches!(command.auth, Some(AuthMethod::Email)) {
            whatever!("--send-code requires --auth email");
        }
        let email = resolve_email(command).await?;
        super::progress::run_with_spinner(
            "Sending verification code...",
            cert_server.send_email_verification(&email),
        )
        .await?;
        return Ok(());
    }

    let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&domain)?;
    let detail = match approval_plan {
        RenewApprovalPlan::Email => {
            let token = cli::login_with_email(
                cert_server,
                Some(&domain),
                command.email.clone(),
                command.verify_code.clone(),
            )
            .await?;
            super::progress::run_with_spinner(
                "Renewing identity...",
                cert_server.renew_cert(
                    &token,
                    domain.as_full(),
                    kind,
                    sequence,
                    Some(&device_name),
                    &csr_pem,
                ),
            )
            .await?
        }
        RenewApprovalPlan::Identity { auth_domain } => {
            super::progress::run_with_spinner(
                "Renewing identity...",
                cert_server.renew_cert_with_identity(
                    &auth_domain,
                    domain.as_full(),
                    kind,
                    sequence,
                    Some(&device_name),
                    &csr_pem,
                ),
            )
            .await?
        }
    };

    cli::save_identity(
        dhttp_home,
        &domain,
        key_pem.as_bytes(),
        detail.cert_pem.as_bytes(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use dhttp::home::{DhttpHome, HomeScope};

    use super::{
        InteractiveRenewState, RenewApprovalPlan, RenewEmailAction, RenewVerifyCodeAction,
        renew_email_actions, renew_not_saved_root_message, renew_verify_code_actions,
        resolve_non_interactive_approval_plan,
    };
    use crate::{auth::AuthMethod, cli::Renew};

    fn unique_test_home_path(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "genmeta-identity-renew-{test_name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn dummy_cert_server() -> crate::cert_server::CertServer {
        _ = rustls::crypto::ring::default_provider().install_default();
        crate::cert_server::CertServer::new("https://license.genmeta.net").unwrap()
    }

    #[test]
    fn stay_recovery_keeps_renew_verify_state() {
        let mut state = InteractiveRenewState::from_command(
            &Renew {
                name: Some("alice.smith".to_string()),
                device_name: None,
                email: Some("alice@example.test".to_string()),
                send_code: false,
                verify_code: None,
                auth: None,
            },
            None,
        );
        state.verify_code = Some("123456".to_string());

        super::apply_verification_recovery(
            &mut state,
            &crate::cli::flow::recovery::VerificationRecovery::StayCurrentStep {
                message: "retry later".to_string(),
            },
        );

        assert_eq!(state.verify_code.as_deref(), Some("123456"));
    }

    #[test]
    fn back_to_email_recovery_reopens_renew_email_prompt() {
        let mut state = InteractiveRenewState::from_command(
            &Renew {
                name: Some("alice.smith".to_string()),
                device_name: None,
                email: Some("alice@example.test".to_string()),
                send_code: false,
                verify_code: None,
                auth: None,
            },
            None,
        );
        state.email_prompt_required = false;

        super::apply_verification_recovery(
            &mut state,
            &crate::cli::flow::recovery::VerificationRecovery::BackToEmail {
                message: "start over".to_string(),
            },
        );

        assert!(state.email_prompt_required);
        assert!(state.verify_code.is_none());
    }

    #[test]
    fn renew_prefers_ready_identity_non_interactively() {
        assert_eq!(
            resolve_non_interactive_approval_plan(
                "alice.smith",
                None,
                Some("alice.smith.dhttp.net")
            )
            .unwrap(),
            RenewApprovalPlan::Identity {
                auth_domain: "alice.smith.dhttp.net".to_string()
            }
        );
    }

    #[test]
    fn renew_identity_auth_is_allowed() {
        assert_eq!(
            resolve_non_interactive_approval_plan(
                "alice.smith",
                Some(AuthMethod::Identity),
                Some("alice.smith.dhttp.net")
            )
            .unwrap(),
            RenewApprovalPlan::Identity {
                auth_domain: "alice.smith.dhttp.net".to_string()
            },
        );
    }

    #[test]
    fn renew_email_auth_is_allowed() {
        assert_eq!(
            resolve_non_interactive_approval_plan("alice.smith", Some(AuthMethod::Email), None)
                .unwrap(),
            RenewApprovalPlan::Email,
        );
    }

    #[test]
    fn renew_not_saved_root_message_mentions_apply_and_return() {
        assert_eq!(
            renew_not_saved_root_message("alice.ma"),
            "The identity alice.ma is not saved here.

Renew updates an identity already saved here.
This identity has not been applied here yet.

Apply alice.ma here first, then return to renew."
        );
    }

    #[tokio::test]
    async fn renew_reports_saved_local_requirement_when_named_identity_is_missing() {
        let home_path = unique_test_home_path("renew-unsaved");
        let dhttp_home = DhttpHome::new(home_path);
        let command = Renew {
            name: Some("alice.smith".to_string()),
            device_name: None,
            email: None,
            send_code: false,
            verify_code: None,
            auth: None,
        };

        let error = super::run(&command, &dhttp_home, HomeScope::User, &dummy_cert_server())
            .await
            .unwrap_err();
        let rendered = error.to_string();

        assert!(
            rendered.contains("Apply alice.smith here first"),
            "{rendered}"
        );
    }

    #[test]
    fn renew_email_actions_include_explicit_return_points() {
        assert_eq!(
            renew_email_actions()
                .into_iter()
                .map(|action| action.label())
                .collect::<Vec<_>>(),
            vec![
                "Switch verification method (go back to verification method selection)".to_string(),
                "Change identity (go back to identity selection)".to_string(),
            ]
        );
        assert_eq!(
            renew_email_actions(),
            vec![
                RenewEmailAction::SwitchVerificationMethod,
                RenewEmailAction::ChangeIdentitySelection,
            ]
        );
    }

    #[test]
    fn renew_verify_code_actions_include_resend_and_return_points() {
        assert_eq!(
            renew_verify_code_actions()
                .into_iter()
                .map(|action| action.label())
                .collect::<Vec<_>>(),
            vec![
                "Resend verification code".to_string(),
                "Send code to another email (go back to email)".to_string(),
                "Switch verification method (go back to verification method selection)".to_string(),
                "Change identity (go back to identity selection)".to_string(),
            ]
        );
        assert_eq!(
            renew_verify_code_actions(),
            vec![
                RenewVerifyCodeAction::ResendVerificationCode,
                RenewVerifyCodeAction::ChangeEmail,
                RenewVerifyCodeAction::SwitchVerificationMethod,
                RenewVerifyCodeAction::ChangeIdentitySelection,
            ]
        );
    }
}
