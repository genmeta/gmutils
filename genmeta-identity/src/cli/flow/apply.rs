use std::io::IsTerminal;

use dhttp::home::{DhttpHome, HomeScope};
use snafu::{FromString, OptionExt, whatever};

use super::{
    kind::IdentityKind,
    target::{IdentityLevel, IdentityTarget},
};
use crate::{
    auth::AuthMethod,
    cert_server::CertServer,
    cli::{self, Apply, Error, prompt::InquireResultExt},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApplyApprovalPlan {
    Email,
    DirectIdentity { auth_domain: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyRunOutcome {
    Applied,
    ReturnedToCaller,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyPostSavePolicy {
    ManageDefaultSuggestion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingTargetAction {
    Register,
    Reject,
}

fn missing_target_action(
    target: &IdentityTarget,
    private_test_continuation: bool,
) -> MissingTargetAction {
    match target.level() {
        IdentityLevel::SubIdentity => MissingTargetAction::Register,
        IdentityLevel::Identity if private_test_continuation => MissingTargetAction::Register,
        IdentityLevel::Identity => MissingTargetAction::Reject,
    }
}

fn private_test_root_registration(command: &Apply) -> bool {
    command.verify_code.is_some() && matches!(command.auth, Some(AuthMethod::Email))
}

fn missing_root_target_error(target: &IdentityTarget) -> Error {
    debug_assert_eq!(target.level(), IdentityLevel::Identity);
    Error::without_source(format!(
        "{} does not exist yet. Apply can register a missing sub-identity, but not a new root identity.",
        target.short_name()
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApplyVerifyCodeAction {
    ResendVerificationCode,
    ChangeEmail,
    Cancel,
}

impl ApplyVerifyCodeAction {
    fn label(&self) -> String {
        match self {
            Self::ResendVerificationCode => "Resend verification code".to_string(),
            Self::ChangeEmail => "Change email".to_string(),
            Self::Cancel => "Cancel".to_string(),
        }
    }
}

fn apply_verify_code_actions() -> Vec<ApplyVerifyCodeAction> {
    vec![
        ApplyVerifyCodeAction::ResendVerificationCode,
        ApplyVerifyCodeAction::ChangeEmail,
        ApplyVerifyCodeAction::Cancel,
    ]
}

#[derive(Debug, Clone)]
struct InteractiveApplyState {
    target: Option<dhttp::name::DhttpName<'static>>,
    kind: Option<IdentityKind>,
    kind_prompt_required: bool,
    approval_plan: Option<ApplyApprovalPlan>,
    email: Option<String>,
    email_prompt_required: bool,
    verify_code: Option<String>,
    verification_code_sent_to: Option<String>,
}

impl InteractiveApplyState {
    fn from_command(
        command: &Apply,
        target: Option<dhttp::name::DhttpName<'static>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            target,
            kind: command
                .kind
                .as_deref()
                .map(str::parse::<IdentityKind>)
                .transpose()?,
            kind_prompt_required: command.kind.is_none(),
            approval_plan: None,
            email: command.email.clone(),
            email_prompt_required: command.email.is_none(),
            verify_code: command.verify_code.clone(),
            verification_code_sent_to: None,
        })
    }

    fn revisit_email(&mut self) {
        self.email_prompt_required = true;
        self.verify_code = None;
        self.verification_code_sent_to = None;
    }

    fn fall_back_to_email(&mut self) {
        self.approval_plan = Some(ApplyApprovalPlan::Email);
        self.email_prompt_required = true;
        self.verify_code = None;
        self.verification_code_sent_to = None;
    }
}

fn apply_verification_recovery(
    state: &mut InteractiveApplyState,
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
    state: &mut InteractiveApplyState,
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

fn is_domain_not_found(error: &crate::cert_server::Error) -> bool {
    error.is_api_code("domain_not_found")
}

fn classify_apply_email_issue_error(
    _target: &IdentityTarget,
    error: &crate::cert_server::Error,
) -> Option<crate::cli::flow::recovery::VerificationRecovery> {
    match error {
        crate::cert_server::Error::Api {
            status,
            code,
            message,
        } if *status == reqwest::StatusCode::FORBIDDEN && code == "domain_forbidden" => Some(
            crate::cli::flow::recovery::VerificationRecovery::BackToEmail {
                message: message.clone(),
            },
        ),
        _ => None,
    }
}

fn preserve_apply_email_issue_error(error: crate::cert_server::Error) -> Error {
    Error::from(error)
}

fn is_subdomain_quota_exceeded(error: &crate::cert_server::Error) -> bool {
    super::registration::is_subdomain_quota_exceeded(error)
}

fn preserve_apply_registration_error(error: Error) -> Error {
    error
}

fn resolve_non_interactive_approval_plan(
    target: &str,
    requested_auth: Option<AuthMethod>,
    identity_auth_domain: Option<&str>,
) -> Result<ApplyApprovalPlan, Error> {
    match requested_auth {
        Some(AuthMethod::Email) => Ok(ApplyApprovalPlan::Email),
        Some(AuthMethod::Identity) => {
            let Some(auth_domain) = identity_auth_domain else {
                whatever!(
                    "applying {} with --auth identity requires a ready local identity that can approve this apply flow",
                    target
                );
            };
            Ok(ApplyApprovalPlan::DirectIdentity {
                auth_domain: auth_domain.to_string(),
            })
        }
        None => {
            if let Some(auth_domain) = identity_auth_domain {
                return Ok(ApplyApprovalPlan::DirectIdentity {
                    auth_domain: auth_domain.to_string(),
                });
            }
            Ok(ApplyApprovalPlan::Email)
        }
    }
}

fn apply_identity_name_opening() -> &'static str {
    "Apply an identity here."
}

fn interactive_name_check_progress_message() -> &'static str {
    "Checking the validity of this name..."
}

fn interactive_name_unavailable_message() -> &'static str {
    "Sorry, this name is not available. Please try another one."
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InteractiveNameAvailability {
    Applicable,
    Retry,
}

fn classify_interactive_name_availability(
    target: &IdentityTarget,
    availability: &str,
) -> Result<InteractiveNameAvailability, Error> {
    match availability {
        "conflict" => Ok(InteractiveNameAvailability::Applicable),
        "available" if target.level() == IdentityLevel::SubIdentity => {
            Ok(InteractiveNameAvailability::Applicable)
        }
        "available" | "reserved" | "unavailable" => Ok(InteractiveNameAvailability::Retry),
        other => Err(Error::without_source(format!(
            "cert server returned unsupported domain availability: {other}"
        ))),
    }
}

fn explicit_target_from_command(
    command: &Apply,
) -> Result<Option<dhttp::name::DhttpName<'static>>, Error> {
    command
        .name
        .as_deref()
        .map(cli::parse_identity_name)
        .transpose()
}

async fn prompt_apply_target_with_opening(
    opening: &'static str,
) -> Result<dhttp::name::DhttpName<'static>, Error> {
    let identity = crate::cli::prompt::prompt_identity_name(opening)
        .await
        .require_interactive("IDENTITY")?;
    cli::parse_identity_name(&identity)
}

async fn prompt_apply_target() -> Result<dhttp::name::DhttpName<'static>, Error> {
    prompt_apply_target_with_opening(apply_identity_name_opening()).await
}

async fn prompt_apply_target_with_online_validation(
    cert_server: &CertServer,
) -> Result<dhttp::name::DhttpName<'static>, Error> {
    let mut opening = apply_identity_name_opening();
    loop {
        let name = prompt_apply_target_with_opening(opening).await?;
        opening = "";
        let target = IdentityTarget::parse(name.as_partial())?;
        let response = match super::progress::run_with_spinner(
            interactive_name_check_progress_message(),
            cert_server.inspect_domain_availability(name.as_full()),
        )
        .await
        {
            Ok(response) => response,
            Err(error) if error.is_api_code("domain_invalid") => {
                crate::cli::flow::transcript::print_err_block(
                    interactive_name_unavailable_message(),
                );
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        match classify_interactive_name_availability(&target, &response.availability)? {
            InteractiveNameAvailability::Applicable => return Ok(name),
            InteractiveNameAvailability::Retry => {
                crate::cli::flow::transcript::print_err_block(
                    interactive_name_unavailable_message(),
                );
            }
        }
    }
}

async fn resolve_target(
    command: &Apply,
    interactive_cert_server: Option<&CertServer>,
) -> Result<dhttp::name::DhttpName<'static>, Error> {
    match explicit_target_from_command(command)? {
        Some(name) => Ok(name),
        None => match interactive_cert_server {
            Some(cert_server) => prompt_apply_target_with_online_validation(cert_server).await,
            None => prompt_apply_target().await,
        },
    }
}

async fn resolve_kind(command: &Apply) -> Result<IdentityKind, Error> {
    match command.kind.as_deref() {
        Some(kind) => Ok(kind.parse::<IdentityKind>()?),
        None => Ok(crate::cli::prompt::prompt_kind()
            .await
            .require_interactive("--kind")?),
    }
}

async fn resolve_email(command: &Apply) -> Result<String, Error> {
    match command.email.clone() {
        Some(email) => Ok(email),
        None => Ok(crate::cli::prompt::prompt_email()
            .await
            .require_interactive("--email")?),
    }
}

async fn prompt_apply_verify_code_action() -> Result<ApplyVerifyCodeAction, Error> {
    let actions = apply_verify_code_actions();
    let labels = actions
        .iter()
        .map(ApplyVerifyCodeAction::label)
        .collect::<Vec<_>>();
    let selected = crate::cli::prompt::prompt_select_string("More options:", labels.clone())
        .await
        .require_interactive("interactive input")?;
    actions
        .into_iter()
        .zip(labels)
        .find_map(|(action, label)| (label == selected).then_some(action))
        .whatever_context::<_, Error>("selected apply action is unavailable")
}

async fn run_post_save_epilogue(
    post_save: ApplyPostSavePolicy,
    dhttp_home: &DhttpHome,
    domain: dhttp::name::DhttpName<'_>,
    default_identity_when_command_started: Option<dhttp::name::DhttpName<'static>>,
    interactive: bool,
    welcome: Option<&super::welcome::WelcomeServiceCreated>,
) -> Result<(), Error> {
    let ApplyPostSavePolicy::ManageDefaultSuggestion = post_save;
    crate::cli::flow::epilogue::run_lifecycle_epilogue(
        dhttp_home,
        domain,
        default_identity_when_command_started,
        interactive,
        super::output::SavedIdentityAction::Applied,
        welcome,
    )
    .await
}

fn new_identity_confirmation_message() -> &'static str {
    "This new name is yours now."
}

async fn ensure_identity_exists_after_apply_login(
    target: &IdentityTarget,
    cert_server: &CertServer,
    access_token: &str,
    interactive: bool,
) -> Result<(), Error> {
    match target.level() {
        IdentityLevel::Identity => {
            if interactive {
                super::registration::ensure_identity_exists_with_token_interactively(
                    cert_server,
                    target,
                    access_token,
                    super::registration::create_identity_progress_message(),
                )
                .await
            } else {
                super::registration::ensure_identity_exists_with_token(
                    cert_server,
                    target,
                    access_token,
                    super::registration::create_identity_progress_message(),
                )
                .await
            }
        }
        IdentityLevel::SubIdentity => {
            let parent = target.parent().whatever_context::<_, Error>(
                "sub-identity target is missing its parent identity",
            )?;
            let label = target.sub_identity_label().whatever_context::<_, Error>(
                "sub-identity target is missing its direct child label",
            )?;
            let created = if interactive {
                super::registration::create_sub_identity_with_token_interactively(
                    cert_server,
                    target,
                    access_token,
                    &parent,
                    label,
                )
                .await?
            } else {
                let created = super::registration::create_sub_identity_with_token(
                    cert_server,
                    target,
                    access_token,
                    &parent,
                    label,
                )
                .await?;
                super::registration::ensure_non_interactive_sub_identity_checkout_not_required(
                    target, &created,
                )?;
                created
            };
            let _ = created;
            Ok(())
        }
    }
}

async fn ensure_sub_identity_exists_with_identity(
    target: &IdentityTarget,
    cert_server: &CertServer,
    identity_domain: &str,
) -> Result<(), Error> {
    let parent = target
        .parent()
        .whatever_context::<_, Error>("sub-identity target is missing its parent identity")?;
    let label = target
        .sub_identity_label()
        .whatever_context::<_, Error>("sub-identity target is missing its direct child label")?;

    match super::progress::run_with_spinner(
        super::registration::create_identity_progress_message(),
        cert_server.create_subdomain_with_identity(identity_domain, parent.as_full(), label, None),
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(crate::cert_server::Error::Api { code, .. }) if code == "subdomain_conflict" => Ok(()),
        Err(error) => Err(Error::from(error)),
    }
}

async fn run_interactive_with_policy(
    command: &Apply,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
    post_save: ApplyPostSavePolicy,
) -> Result<ApplyRunOutcome, Error> {
    let default_identity_when_command_started = cli::load_current_settings(dhttp_home)
        .await?
        .and_then(|config| config.settings().default_identity_name().cloned());
    let initial_target = explicit_target_from_command(command)?;
    let mut state = InteractiveApplyState::from_command(command, initial_target)?;

    loop {
        if state.target.is_none() {
            state.target = Some(prompt_apply_target_with_online_validation(cert_server).await?);
            continue;
        }

        if state.kind.is_none() || state.kind_prompt_required {
            state.kind = Some(
                crate::cli::prompt::prompt_kind_with_cursor(state.kind)
                    .await
                    .require_interactive("--kind")?,
            );
            state.kind_prompt_required = false;
            continue;
        }

        let domain = state
            .target
            .clone()
            .whatever_context::<_, Error>("interactive apply target is unavailable")?;
        let target = IdentityTarget::parse(domain.as_partial())?;
        if state.approval_plan.is_none() {
            let auth_plan = super::auth_plan::load_apply_auth_plan(dhttp_home, &target).await?;
            for warning in &auth_plan.warnings {
                crate::cli::flow::transcript::print_err_block(warning);
            }
            state.approval_plan = Some(resolve_non_interactive_approval_plan(
                target.short_name(),
                command.auth,
                auth_plan.first_identity_full_name(),
            )?);
            continue;
        }

        let approval_plan = state
            .approval_plan
            .clone()
            .whatever_context::<_, Error>("interactive apply approval plan is unavailable")?;
        if matches!(approval_plan, ApplyApprovalPlan::Email)
            && (state.email.is_none() || state.email_prompt_required)
        {
            let email = crate::cli::prompt::prompt_email_with_default(state.email.as_deref())
                .await
                .require_interactive("--email")?;
            state.email = Some(email);
            state.email_prompt_required = false;
            continue;
        }

        if matches!(approval_plan, ApplyApprovalPlan::Email) && state.verify_code.is_none() {
            let email = state
                .email
                .clone()
                .whatever_context::<_, Error>("interactive apply email is unavailable")?;
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
                    match prompt_apply_verify_code_action().await? {
                        ApplyVerifyCodeAction::ResendVerificationCode => {
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
                        ApplyVerifyCodeAction::ChangeEmail => state.revisit_email(),
                        ApplyVerifyCodeAction::Cancel => {
                            return Ok(ApplyRunOutcome::ReturnedToCaller);
                        }
                    }
                }
            }
            continue;
        }

        let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&domain)?;
        let kind = state
            .kind
            .whatever_context::<_, Error>("interactive apply kind is unavailable")?;
        let device_name =
            super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
        let detail = match approval_plan {
            ApplyApprovalPlan::Email => {
                let email = state
                    .email
                    .clone()
                    .whatever_context::<_, Error>("interactive apply email is unavailable")?;
                let verify_code = state.verify_code.as_deref().whatever_context::<_, Error>(
                    "interactive apply verification code is unavailable",
                )?;
                let token = match super::progress::run_with_spinner(
                    "Verifying with email...",
                    cert_server.login(&email, verify_code),
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
                match super::progress::run_with_spinner(
                    "Applying identity...",
                    cert_server.issue_cert(
                        &token,
                        domain.as_full(),
                        kind.as_str(),
                        None,
                        &device_name,
                        &csr_pem,
                    ),
                )
                .await
                {
                    Ok(detail) => detail,
                    Err(error) if is_domain_not_found(&error) => {
                        if missing_target_action(&target, private_test_root_registration(command))
                            == MissingTargetAction::Reject
                        {
                            return Err(missing_root_target_error(&target));
                        }
                        if let Err(error) = ensure_identity_exists_after_apply_login(
                            &target,
                            cert_server,
                            &token,
                            true,
                        )
                        .await
                        {
                            return Err(preserve_apply_registration_error(error));
                        }
                        crate::cli::flow::transcript::print_line(
                            new_identity_confirmation_message(),
                        );
                        let detail = super::progress::run_with_spinner(
                            "Applying identity...",
                            cert_server.issue_cert(
                                &token,
                                domain.as_full(),
                                kind.as_str(),
                                None,
                                &device_name,
                                &csr_pem,
                            ),
                        )
                        .await?;
                        let local_identity_save = cli::ensure_replace_local_allowed(
                            dhttp_home,
                            domain.borrow(),
                            command.replace_local,
                        )
                        .await?;
                        cli::save_identity(
                            dhttp_home,
                            &domain,
                            key_pem.as_bytes(),
                            detail.cert_pem.as_bytes(),
                        )
                        .await?;
                        let welcome = super::welcome::maybe_create_welcome_service(
                            dhttp_home,
                            domain.borrow(),
                            local_identity_save.created_new_identity(),
                        )
                        .await?;
                        run_post_save_epilogue(
                            post_save,
                            dhttp_home,
                            domain.borrow(),
                            default_identity_when_command_started.clone(),
                            std::io::stdin().is_terminal(),
                            welcome.as_ref(),
                        )
                        .await?;
                        return Ok(ApplyRunOutcome::Applied);
                    }
                    Err(error) => {
                        if let Some(recovery) = classify_apply_email_issue_error(&target, &error) {
                            state.verify_code = None;
                            if apply_verification_recovery(&mut state, &recovery) {
                                continue;
                            }
                        }
                        return Err(Error::from(error));
                    }
                }
            }
            ApplyApprovalPlan::DirectIdentity { auth_domain } => {
                match super::progress::run_with_spinner(
                    "Applying identity...",
                    cert_server.issue_cert_with_identity(
                        &auth_domain,
                        domain.as_full(),
                        kind.as_str(),
                        None,
                        &device_name,
                        &csr_pem,
                    ),
                )
                .await
                {
                    Ok(detail) => detail,
                    Err(error) if is_domain_not_found(&error) => {
                        if missing_target_action(&target, private_test_root_registration(command))
                            == MissingTargetAction::Reject
                        {
                            return Err(missing_root_target_error(&target));
                        }
                        if target.level() != IdentityLevel::SubIdentity {
                            crate::cli::flow::transcript::print_block(&format!(
                                "Registering {} requires email verification.\nFalling back to email verification.",
                                target.short_name()
                            ));
                            state.fall_back_to_email();
                            continue;
                        }
                        match ensure_sub_identity_exists_with_identity(
                            &target,
                            cert_server,
                            &auth_domain,
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(Error::CertServer { source })
                                if is_subdomain_quota_exceeded(&source) =>
                            {
                                crate::cli::flow::transcript::print_block(&format!(
                                    "Creating {} exceeded the sub-identity quota under {}.\nFalling back to email verification.",
                                    target.short_name(),
                                    target
                                        .parent()
                                        .map(|parent| parent.as_partial().to_string())
                                        .unwrap_or_else(|| "<parent>".to_string()),
                                ));
                                state.fall_back_to_email();
                                continue;
                            }
                            Err(error) => return Err(error),
                        }
                        crate::cli::flow::transcript::print_line(
                            new_identity_confirmation_message(),
                        );
                        super::progress::run_with_spinner(
                            "Applying identity...",
                            cert_server.issue_cert_with_identity(
                                &auth_domain,
                                domain.as_full(),
                                kind.as_str(),
                                None,
                                &device_name,
                                &csr_pem,
                            ),
                        )
                        .await?
                    }
                    Err(error) => return Err(Error::from(error)),
                }
            }
        };

        let local_identity_save =
            cli::ensure_replace_local_allowed(dhttp_home, domain.borrow(), command.replace_local)
                .await?;
        cli::save_identity(
            dhttp_home,
            &domain,
            key_pem.as_bytes(),
            detail.cert_pem.as_bytes(),
        )
        .await?;
        let welcome = super::welcome::maybe_create_welcome_service(
            dhttp_home,
            domain.borrow(),
            local_identity_save.created_new_identity(),
        )
        .await?;
        run_post_save_epilogue(
            post_save,
            dhttp_home,
            domain.borrow(),
            default_identity_when_command_started.clone(),
            std::io::stdin().is_terminal(),
            welcome.as_ref(),
        )
        .await?;
        return Ok(ApplyRunOutcome::Applied);
    }
}

pub(crate) async fn run_with_policy(
    command: &Apply,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
    post_save: ApplyPostSavePolicy,
) -> Result<(), Error> {
    let is_interactive = std::io::stdin().is_terminal();
    if is_interactive && !command.send_code {
        return match run_interactive_with_policy(
            command,
            dhttp_home,
            home_scope,
            cert_server,
            post_save,
        )
        .await?
        {
            ApplyRunOutcome::Applied => Ok(()),
            ApplyRunOutcome::ReturnedToCaller => whatever!("apply was cancelled"),
        };
    }
    let default_identity_when_command_started = cli::load_current_settings(dhttp_home)
        .await?
        .and_then(|config| config.settings().default_identity_name().cloned());
    let domain = resolve_target(command, is_interactive.then_some(cert_server)).await?;
    let target = IdentityTarget::parse(domain.as_partial())?;
    let kind = resolve_kind(command).await?;
    let device_name =
        super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
    let auth_plan = super::auth_plan::load_apply_auth_plan(dhttp_home, &target).await?;
    for warning in &auth_plan.warnings {
        crate::cli::flow::transcript::print_err_block(warning);
    }
    let approval_plan = resolve_non_interactive_approval_plan(
        target.short_name(),
        command.auth,
        auth_plan.first_identity_full_name(),
    )?;

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

    let local_identity_save =
        cli::ensure_replace_local_allowed(dhttp_home, domain.borrow(), command.replace_local)
            .await?;
    let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&domain)?;
    let detail = match approval_plan {
        ApplyApprovalPlan::Email => {
            let email = resolve_email(command).await?;
            let verify_code = match command.verify_code.clone() {
                Some(code) => code,
                None => {
                    super::progress::run_with_spinner(
                        "Sending verification code...",
                        cert_server.send_email_verification(&email),
                    )
                    .await?;
                    crate::cli::prompt::prompt_verify_code()
                        .await
                        .require_interactive("--verify-code")?
                }
            };
            let token = super::progress::run_with_spinner(
                "Verifying with email...",
                cert_server.login(&email, &verify_code),
            )
            .await?
            .access_token;
            match super::progress::run_with_spinner(
                "Applying identity...",
                cert_server.issue_cert(
                    &token,
                    domain.as_full(),
                    kind.as_str(),
                    None,
                    &device_name,
                    &csr_pem,
                ),
            )
            .await
            {
                Ok(detail) => detail,
                Err(error) if is_domain_not_found(&error) => {
                    if missing_target_action(&target, private_test_root_registration(command))
                        == MissingTargetAction::Reject
                    {
                        return Err(missing_root_target_error(&target));
                    }
                    ensure_identity_exists_after_apply_login(
                        &target,
                        cert_server,
                        &token,
                        is_interactive,
                    )
                    .await
                    .map_err(preserve_apply_registration_error)?;
                    crate::cli::flow::transcript::print_line(new_identity_confirmation_message());
                    super::progress::run_with_spinner(
                        "Applying identity...",
                        cert_server.issue_cert(
                            &token,
                            domain.as_full(),
                            kind.as_str(),
                            None,
                            &device_name,
                            &csr_pem,
                        ),
                    )
                    .await
                    .map_err(preserve_apply_email_issue_error)?
                }
                Err(error) => return Err(preserve_apply_email_issue_error(error)),
            }
        }
        ApplyApprovalPlan::DirectIdentity { auth_domain } => {
            match super::progress::run_with_spinner(
                "Applying identity...",
                cert_server.issue_cert_with_identity(
                    &auth_domain,
                    domain.as_full(),
                    kind.as_str(),
                    None,
                    &device_name,
                    &csr_pem,
                ),
            )
            .await
            {
                Ok(detail) => detail,
                Err(error) if is_domain_not_found(&error) => {
                    if missing_target_action(&target, private_test_root_registration(command))
                        == MissingTargetAction::Reject
                    {
                        return Err(missing_root_target_error(&target));
                    }
                    if target.level() != IdentityLevel::SubIdentity {
                        whatever!(
                            "registering {} requires email verification; rerun with --auth email",
                            target.short_name()
                        );
                    }
                    ensure_sub_identity_exists_with_identity(&target, cert_server, &auth_domain)
                        .await?;
                    crate::cli::flow::transcript::print_line(new_identity_confirmation_message());
                    super::progress::run_with_spinner(
                        "Applying identity...",
                        cert_server.issue_cert_with_identity(
                            &auth_domain,
                            domain.as_full(),
                            kind.as_str(),
                            None,
                            &device_name,
                            &csr_pem,
                        ),
                    )
                    .await?
                }
                Err(error) => return Err(Error::from(error)),
            }
        }
    };

    cli::save_identity(
        dhttp_home,
        &domain,
        key_pem.as_bytes(),
        detail.cert_pem.as_bytes(),
    )
    .await?;
    let welcome = super::welcome::maybe_create_welcome_service(
        dhttp_home,
        domain.borrow(),
        local_identity_save.created_new_identity(),
    )
    .await?;
    run_post_save_epilogue(
        post_save,
        dhttp_home,
        domain.borrow(),
        default_identity_when_command_started,
        is_interactive,
        welcome.as_ref(),
    )
    .await
}

pub(crate) async fn run(
    command: &Apply,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
) -> Result<(), Error> {
    run_with_policy(
        command,
        dhttp_home,
        home_scope,
        cert_server,
        ApplyPostSavePolicy::ManageDefaultSuggestion,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        ApplyApprovalPlan, ApplyVerifyCodeAction, InteractiveApplyState,
        InteractiveNameAvailability, MissingTargetAction, apply_identity_name_opening,
        apply_verify_code_actions, classify_apply_email_issue_error,
        classify_interactive_name_availability, explicit_target_from_command,
        interactive_name_check_progress_message, interactive_name_unavailable_message,
        missing_root_target_error, missing_target_action, new_identity_confirmation_message,
        preserve_apply_email_issue_error, preserve_apply_registration_error,
        resolve_non_interactive_approval_plan,
    };
    use crate::{
        auth::AuthMethod,
        cli::{Apply, flow::target::IdentityTarget},
    };

    #[test]
    fn stay_recovery_keeps_apply_verify_state() {
        let mut state = InteractiveApplyState::from_command(
            &Apply {
                name: Some("alice.smith".to_string()),
                kind: Some("primary".to_string()),
                replace_local: false,
                device_name: None,
                email: Some("alice@example.test".to_string()),
                send_code: false,
                verify_code: None,
                auth: None,
            },
            None,
        )
        .unwrap();
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
    fn back_to_email_recovery_reopens_apply_email_prompt() {
        let mut state = InteractiveApplyState::from_command(
            &Apply {
                name: Some("alice.smith".to_string()),
                kind: Some("primary".to_string()),
                replace_local: false,
                device_name: None,
                email: Some("alice@example.test".to_string()),
                send_code: false,
                verify_code: None,
                auth: None,
            },
            None,
        )
        .unwrap();
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
    fn apply_email_issue_domain_forbidden_reopens_owner_email_prompt() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::FORBIDDEN,
            code: "domain_forbidden".to_string(),
            message: "domain access is forbidden".to_string(),
        };
        let target = IdentityTarget::parse("alice.smith").unwrap();

        assert_eq!(
            classify_apply_email_issue_error(&target, &error),
            Some(
                crate::cli::flow::recovery::VerificationRecovery::BackToEmail {
                    message: "domain access is forbidden".to_string(),
                }
            ),
        );
    }

    #[test]
    fn non_interactive_apply_email_issue_keeps_the_certserver_problem_message() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::FORBIDDEN,
            code: "domain_forbidden".to_string(),
            message: "domain access is forbidden".to_string(),
        };
        let rendered = preserve_apply_email_issue_error(error).to_string();

        assert_eq!(rendered, "domain access is forbidden");
    }

    #[test]
    fn explicit_target_from_command_returns_none_without_name() {
        let target = explicit_target_from_command(&Apply {
            name: None,
            kind: None,
            replace_local: false,
            device_name: None,
            email: None,
            send_code: false,
            verify_code: None,
            auth: None,
        })
        .unwrap();

        assert!(target.is_none());
    }

    #[test]
    fn root_apply_without_local_auth_defaults_to_email_non_interactively() {
        assert_eq!(
            resolve_non_interactive_approval_plan("alice.smith", None, None).unwrap(),
            ApplyApprovalPlan::Email,
        );
    }

    #[test]
    fn root_apply_prefers_ready_local_auth_non_interactively() {
        assert_eq!(
            resolve_non_interactive_approval_plan("alice.smith", None, Some("alice.smith"))
                .unwrap(),
            ApplyApprovalPlan::DirectIdentity {
                auth_domain: "alice.smith".to_string(),
            },
        );
    }

    #[test]
    fn apply_identity_auth_requires_ready_local_identity_or_parent() {
        let error = resolve_non_interactive_approval_plan(
            "phone.alice.smith",
            Some(AuthMethod::Identity),
            None,
        )
        .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("ready local identity"), "{rendered}");
        assert!(rendered.contains("phone.alice.smith"), "{rendered}");
    }

    #[test]
    fn sub_identity_apply_can_use_ready_parent_identity() {
        assert_eq!(
            resolve_non_interactive_approval_plan(
                "phone.alice.smith",
                Some(AuthMethod::Identity),
                Some("alice.smith"),
            )
            .unwrap(),
            ApplyApprovalPlan::DirectIdentity {
                auth_domain: "alice.smith".to_string(),
            },
        );
    }

    #[test]
    fn sub_identity_apply_automatically_uses_ready_parent() {
        assert_eq!(
            resolve_non_interactive_approval_plan("phone.alice.smith", None, Some("alice.smith"),)
                .unwrap(),
            ApplyApprovalPlan::DirectIdentity {
                auth_domain: "alice.smith".to_string(),
            },
        );
    }

    #[test]
    fn apply_identity_name_opening_matches_spec_copy() {
        assert_eq!(apply_identity_name_opening(), "Apply an identity here.");
    }

    #[test]
    fn interactive_name_availability_respects_target_level() {
        let root = IdentityTarget::parse("alice.smith").unwrap();
        let child = IdentityTarget::parse("phone.alice.smith").unwrap();

        assert_eq!(
            classify_interactive_name_availability(&root, "conflict").unwrap(),
            InteractiveNameAvailability::Applicable
        );
        assert_eq!(
            classify_interactive_name_availability(&child, "available").unwrap(),
            InteractiveNameAvailability::Applicable
        );
        assert_eq!(
            classify_interactive_name_availability(&root, "available").unwrap(),
            InteractiveNameAvailability::Retry
        );
        assert_eq!(
            classify_interactive_name_availability(&child, "reserved").unwrap(),
            InteractiveNameAvailability::Retry
        );
        assert_eq!(
            classify_interactive_name_availability(&child, "unavailable").unwrap(),
            InteractiveNameAvailability::Retry
        );
        assert!(classify_interactive_name_availability(&child, "future-status").is_err());
    }

    #[test]
    fn interactive_name_check_copy_matches_spec() {
        assert_eq!(
            interactive_name_check_progress_message(),
            "Checking the validity of this name..."
        );
        assert_eq!(
            interactive_name_unavailable_message(),
            "Sorry, this name is not available. Please try another one."
        );
    }

    #[test]
    fn newly_registered_identity_uses_the_approved_confirmation() {
        assert_eq!(
            new_identity_confirmation_message(),
            "This new name is yours now."
        );
    }

    #[test]
    fn missing_sub_identity_registration_is_implicit() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        assert_eq!(
            missing_target_action(&target, false),
            MissingTargetAction::Register
        );
    }

    #[test]
    fn root_registration_requires_the_private_test_continuation() {
        let target = IdentityTarget::parse("alice.smith").unwrap();

        assert_eq!(
            missing_target_action(&target, false),
            MissingTargetAction::Reject
        );
        assert_eq!(
            missing_target_action(&target, true),
            MissingTargetAction::Register
        );
    }

    #[test]
    fn missing_root_error_does_not_advertise_private_root_registration() {
        let target = IdentityTarget::parse("alice.smith").unwrap();

        assert_eq!(
            missing_root_target_error(&target).to_string(),
            "alice.smith does not exist yet. Apply can register a missing sub-identity, but not a new root identity."
        );
    }

    #[test]
    fn starter_domain_limit_registration_error_keeps_the_certserver_problem_message() {
        let error = preserve_apply_registration_error(crate::cli::Error::CertServer {
            source: crate::cert_server::Error::Api {
                status: reqwest::StatusCode::CONFLICT,
                code: "starter_domain_limit_reached".to_string(),
                message: "starter plan is limited to 3 free domains per account".to_string(),
            },
        });
        let rendered = error.to_string();
        assert_eq!(
            rendered,
            "starter plan is limited to 3 free domains per account"
        );
        assert!(matches!(
            error,
            crate::cli::Error::CertServer { source }
                if source.is_api_code("starter_domain_limit_reached")
        ));
    }

    #[test]
    fn subdomain_quota_helper_matches_api_code_only() {
        assert!(super::is_subdomain_quota_exceeded(
            &crate::cert_server::Error::Api {
                status: reqwest::StatusCode::UNPROCESSABLE_ENTITY,
                code: "subdomain_quota_exceeded".to_string(),
                message: "subdomain quota exceeded".to_string(),
            }
        ));
        assert!(!super::is_subdomain_quota_exceeded(
            &crate::cert_server::Error::Api {
                status: reqwest::StatusCode::UNPROCESSABLE_ENTITY,
                code: "domain_not_found".to_string(),
                message: "domain not found".to_string(),
            }
        ));
    }

    #[test]
    fn apply_verify_code_actions_are_limited_to_the_code_recovery_boundary() {
        assert_eq!(
            apply_verify_code_actions()
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
            apply_verify_code_actions(),
            vec![
                ApplyVerifyCodeAction::ResendVerificationCode,
                ApplyVerifyCodeAction::ChangeEmail,
                ApplyVerifyCodeAction::Cancel,
            ]
        );
    }
}
