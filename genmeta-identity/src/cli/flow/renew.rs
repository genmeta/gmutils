use std::io::IsTerminal;

use dhttp::home::{DhttpHome, HomeScope};
use snafu::{OptionExt, whatever};

use super::local;
use crate::{
    cert_server::CertServer,
    cli::{self, Error, Renew, prompt::InquireResultExt},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum RenewApprovalPlan {
    Email,
    Identity { auth_domain: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RenewVerifyCodeAction {
    ResendVerificationCode,
    ChangeEmail,
    Cancel,
}

impl RenewVerifyCodeAction {
    fn label(&self) -> String {
        match self {
            Self::ResendVerificationCode => "Resend verification code".to_string(),
            Self::ChangeEmail => "Change email".to_string(),
            Self::Cancel => "Cancel".to_string(),
        }
    }
}

fn renew_verify_code_actions() -> Vec<RenewVerifyCodeAction> {
    vec![
        RenewVerifyCodeAction::ResendVerificationCode,
        RenewVerifyCodeAction::ChangeEmail,
        RenewVerifyCodeAction::Cancel,
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

    fn revisit_email(&mut self) {
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
    crate::cli::flow::transcript::print_block(&crate::cli::flow::recovery::format_resend_offer(
        message,
    ));
    let resend = crate::cli::prompt::sync(|| {
        inquire::Confirm::new("Send a new verification code?")
            .with_default(true)
            .prompt()
    })
    .await
    .require_interactive("interactive input")?;
    if resend {
        super::progress::run(
            super::progress::SEND_CODE,
            cert_server.send_email_verification(email),
        )
        .await?;
        state.verification_code_sent_to = Some(email.to_string());
    }
    state.verify_code = None;
    Ok(())
}

fn renew_not_saved_root_message(short_name: &str) -> String {
    format!("Failed to renew: {short_name} not found!")
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

fn resolve_non_interactive_approval_plan(ready_identity: Option<&str>) -> RenewApprovalPlan {
    match ready_identity {
        Some(auth_domain) => RenewApprovalPlan::Identity {
            auth_domain: auth_domain.to_string(),
        },
        None => RenewApprovalPlan::Email,
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
                auth_plan.first_identity_full_name(),
            ));
            continue;
        }

        let approval_plan = state
            .approval_plan
            .clone()
            .whatever_context::<_, Error>("interactive renew approval plan is unavailable")?;
        if matches!(approval_plan, RenewApprovalPlan::Email)
            && (state.email.is_none() || state.email_prompt_required)
        {
            let email = crate::cli::prompt::prompt_email_with_default(state.email.as_deref())
                .await
                .require_interactive("--email")?;
            state.email = Some(email);
            state.email_prompt_required = false;
            continue;
        }

        if matches!(approval_plan, RenewApprovalPlan::Email) && state.verify_code.is_none() {
            let email = state
                .email
                .clone()
                .whatever_context::<_, Error>("interactive renew email is unavailable")?;
            if state.verification_code_sent_to.as_deref() != Some(email.as_str()) {
                match super::progress::run(
                    super::progress::SEND_CODE,
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
                            match super::progress::run(
                                super::progress::SEND_CODE,
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
                        RenewVerifyCodeAction::Cancel => {
                            whatever!(
                                "Renew was cancelled.\nNo local identity files were changed."
                            );
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
                let token = match super::progress::run(
                    super::progress::VERIFY_EMAIL,
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
                super::progress::run(
                    super::progress::RENEW_IDENTITY,
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
                super::progress::run(
                    super::progress::RENEW_IDENTITY,
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
    if is_interactive {
        return run_interactive(command, dhttp_home, home_scope, cert_server).await;
    }
    let domain = resolve_target(command, dhttp_home).await?;
    ensure_saved_renew_target(dhttp_home, domain.borrow()).await?;
    let target = crate::cli::flow::target::IdentityTarget::parse(domain.as_partial())?;
    let auth_plan = super::auth_plan::load_apply_auth_plan(dhttp_home, &target).await?;
    for warning in &auth_plan.warnings {
        crate::cli::flow::transcript::print_err_block(warning);
    }
    let approval_plan = resolve_non_interactive_approval_plan(auth_plan.first_identity_full_name());
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
            let token = cli::login_with_email(
                cert_server,
                Some(&domain),
                command.email.clone(),
                command.verify_code.clone(),
            )
            .await?;
            super::progress::run(
                super::progress::RENEW_IDENTITY,
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
            super::progress::run(
                super::progress::RENEW_IDENTITY,
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
        InteractiveRenewState, RenewApprovalPlan, RenewVerifyCodeAction,
        renew_not_saved_root_message, renew_verify_code_actions,
        resolve_non_interactive_approval_plan,
    };
    use crate::cli::Renew;

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
                force: false,
                device_name: None,
                email: Some("alice@example.test".to_string()),
                verify_code: None,
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
                force: false,
                device_name: None,
                email: Some("alice@example.test".to_string()),
                verify_code: None,
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
            resolve_non_interactive_approval_plan(Some("alice.smith.dhttp.net")),
            RenewApprovalPlan::Identity {
                auth_domain: "alice.smith.dhttp.net".to_string()
            }
        );
    }

    #[test]
    fn renew_without_ready_identity_uses_email_non_interactively() {
        assert_eq!(
            resolve_non_interactive_approval_plan(None),
            RenewApprovalPlan::Email,
        );
    }

    #[test]
    fn renew_not_saved_message_matches_the_edited_document() {
        assert_eq!(
            renew_not_saved_root_message("alice.ma"),
            "Failed to renew: alice.ma not found!"
        );
    }

    #[tokio::test]
    async fn renew_reports_saved_local_requirement_when_named_identity_is_missing() {
        let home_path = unique_test_home_path("renew-unsaved");
        let dhttp_home = DhttpHome::new(home_path);
        let command = Renew {
            name: Some("alice.smith".to_string()),
            force: false,
            device_name: None,
            email: None,
            verify_code: None,
        };

        let error = super::run(&command, &dhttp_home, HomeScope::User, &dummy_cert_server())
            .await
            .unwrap_err();
        let rendered = error.to_string();

        assert_eq!(rendered, "Failed to renew: alice.smith not found!");
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
                "Change email".to_string(),
                "Cancel".to_string(),
            ]
        );
        assert_eq!(
            renew_verify_code_actions(),
            vec![
                RenewVerifyCodeAction::ResendVerificationCode,
                RenewVerifyCodeAction::ChangeEmail,
                RenewVerifyCodeAction::Cancel,
            ]
        );
    }
}
