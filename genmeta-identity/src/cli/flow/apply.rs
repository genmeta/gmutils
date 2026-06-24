use std::io::IsTerminal;

use dhttp::home::{DhttpHome, HomeScope};
use snafu::{OptionExt, whatever};
use tracing::{Instrument, info_span};

use super::{
    approval,
    kind::IdentityKind,
    local::{self, LocalIdentityStatus, LocalIdentitySummary},
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
    DirectIdentity {
        auth_domain: String,
    },
    HelperIdentity {
        auth_domain: String,
        action: approval::ApprovalHelperAction,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApplyEmailAction {
    SwitchVerificationMethod,
    ChangeCertificateKind,
    ChangeIdentitySelection,
    ReturnToCaller { label: String },
}

impl ApplyEmailAction {
    fn label(&self) -> String {
        match self {
            Self::SwitchVerificationMethod => {
                "Switch verification method (go back to verification method selection)".to_string()
            }
            Self::ChangeCertificateKind => {
                "Change certificate kind (go back to identity kind)".to_string()
            }
            Self::ChangeIdentitySelection => {
                "Change identity (go back to identity selection)".to_string()
            }
            Self::ReturnToCaller { label } => format!("Return to {label}"),
        }
    }
}

fn apply_email_actions(return_to: Option<&str>) -> Vec<ApplyEmailAction> {
    let mut actions = vec![
        ApplyEmailAction::SwitchVerificationMethod,
        ApplyEmailAction::ChangeCertificateKind,
        ApplyEmailAction::ChangeIdentitySelection,
    ];
    if let Some(label) = return_to {
        actions.push(ApplyEmailAction::ReturnToCaller {
            label: label.to_string(),
        });
    }
    actions
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApplyApprovalMenuAction {
    ChangeCertificateKind,
    ChangeIdentitySelection,
    ReturnToCaller { label: String },
}

impl ApplyApprovalMenuAction {
    fn label(&self) -> String {
        match self {
            Self::ChangeCertificateKind => {
                "Change certificate kind (go back to identity kind)".to_string()
            }
            Self::ChangeIdentitySelection => {
                "Change identity (go back to identity selection)".to_string()
            }
            Self::ReturnToCaller { label } => format!("Return to {label}"),
        }
    }
}

fn apply_approval_menu_actions(return_to: Option<&str>) -> Vec<ApplyApprovalMenuAction> {
    let mut actions = vec![
        ApplyApprovalMenuAction::ChangeCertificateKind,
        ApplyApprovalMenuAction::ChangeIdentitySelection,
    ];
    if let Some(label) = return_to {
        actions.push(ApplyApprovalMenuAction::ReturnToCaller {
            label: label.to_string(),
        });
    }
    actions
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyRunOutcome {
    Applied,
    ReturnedToCaller,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyPostSavePolicy {
    ManageDefaultSuggestion,
    SkipDefaultSuggestion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApplyVerifyCodeAction {
    ResendVerificationCode,
    ChangeEmail,
    SwitchVerificationMethod,
    ChangeCertificateKind,
    ChangeIdentitySelection,
    ReturnToCaller { label: String },
}

impl ApplyVerifyCodeAction {
    fn label(&self) -> String {
        match self {
            Self::ResendVerificationCode => "Resend verification code".to_string(),
            Self::ChangeEmail => "Send code to another email (go back to email)".to_string(),
            Self::SwitchVerificationMethod => {
                "Switch verification method (go back to verification method selection)".to_string()
            }
            Self::ChangeCertificateKind => {
                "Change certificate kind (go back to identity kind)".to_string()
            }
            Self::ChangeIdentitySelection => {
                "Change identity (go back to identity selection)".to_string()
            }
            Self::ReturnToCaller { label } => format!("Return to {label}"),
        }
    }
}

fn apply_verify_code_actions(return_to: Option<&str>) -> Vec<ApplyVerifyCodeAction> {
    let mut actions = vec![
        ApplyVerifyCodeAction::ResendVerificationCode,
        ApplyVerifyCodeAction::ChangeEmail,
        ApplyVerifyCodeAction::SwitchVerificationMethod,
        ApplyVerifyCodeAction::ChangeCertificateKind,
        ApplyVerifyCodeAction::ChangeIdentitySelection,
    ];
    if let Some(label) = return_to {
        actions.push(ApplyVerifyCodeAction::ReturnToCaller {
            label: label.to_string(),
        });
    }
    actions
}

fn build_apply_approval_options(
    candidate: Option<approval::LocalApprovalCandidate>,
) -> Vec<approval::ApprovalMenuOption> {
    approval::build_options_for_candidate("Verify with email", candidate)
}

fn apply_verification_options(auth_domain: &str) -> Vec<(String, ApplyApprovalPlan)> {
    let short_name = IdentityTarget::parse(auth_domain)
        .map(|target| target.short_name().to_string())
        .unwrap_or_else(|_| auth_domain.to_string());
    build_apply_approval_options(Some(approval::LocalApprovalCandidate::ready(
        short_name,
        auth_domain,
    )))
    .into_iter()
    .filter_map(|option| match option {
        approval::ApprovalMenuOption::Email { label } => Some((label, ApplyApprovalPlan::Email)),
        approval::ApprovalMenuOption::DirectLocal(local) => Some((
            format!("Verify with {} on local device", local.short_name),
            ApplyApprovalPlan::DirectIdentity {
                auth_domain: local.auth_domain,
            },
        )),
        approval::ApprovalMenuOption::Helper(_) => None,
    })
    .collect()
}

fn apply_candidate_from_summary(
    summary: &LocalIdentitySummary,
) -> approval::LocalApprovalCandidate {
    let short_name = summary.target.short_name().to_string();
    let auth_domain = summary.target.full_name();
    match &summary.status {
        LocalIdentityStatus::Ready { .. } => {
            approval::LocalApprovalCandidate::ready(short_name, auth_domain)
        }
        LocalIdentityStatus::Expired { .. } => {
            approval::LocalApprovalCandidate::expired(short_name, auth_domain, true, true)
        }
        LocalIdentityStatus::Incomplete { detail } => {
            approval::LocalApprovalCandidate::incomplete(short_name, auth_domain, detail.clone())
        }
        LocalIdentityStatus::Invalid { detail } => {
            approval::LocalApprovalCandidate::invalid(short_name, auth_domain, detail.clone())
        }
    }
}

fn apply_plan_from_option(option: &approval::ApprovalMenuOption) -> ApplyApprovalPlan {
    match option {
        approval::ApprovalMenuOption::Email { .. } => ApplyApprovalPlan::Email,
        approval::ApprovalMenuOption::DirectLocal(local) => ApplyApprovalPlan::DirectIdentity {
            auth_domain: local.auth_domain.clone(),
        },
        approval::ApprovalMenuOption::Helper(helper) => ApplyApprovalPlan::HelperIdentity {
            auth_domain: helper.auth_domain.clone(),
            action: helper.action.clone(),
        },
    }
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

    fn revisit_target_selection(&mut self) {
        self.target = None;
        self.kind = None;
        self.kind_prompt_required = true;
        self.approval_plan = None;
        self.email = None;
        self.email_prompt_required = true;
        self.verify_code = None;
        self.verification_code_sent_to = None;
    }

    fn revisit_kind(&mut self) {
        self.kind_prompt_required = true;
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
    state: &mut InteractiveApplyState,
    recovery: &crate::cli::flow::recovery::VerificationRecovery,
) -> bool {
    match recovery {
        crate::cli::flow::recovery::VerificationRecovery::StayCurrentStep { message } => {
            crate::cli::flow::transcript::print_line(*message);
            true
        }
        crate::cli::flow::recovery::VerificationRecovery::BackToEmail { message } => {
            crate::cli::flow::transcript::print_line(*message);
            state.revisit_email();
            true
        }
        crate::cli::flow::recovery::VerificationRecovery::Abort => false,
    }
}

fn approval_plan_from_selection(
    options: &[(String, ApplyApprovalPlan)],
    selected: &str,
) -> Result<ApplyApprovalPlan, Error> {
    options
        .iter()
        .find_map(|(label, plan)| (label == selected).then_some(plan.clone()))
        .whatever_context::<_, Error>("selected approval path is unavailable")
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
            if identity_auth_domain.is_some() {
                whatever!(
                    "applying {} non-interactively requires choosing an approval path; rerun with --auth email or --auth identity",
                    target
                );
            }
            Ok(ApplyApprovalPlan::Email)
        }
    }
}

async fn resolve_approval_plan(
    target: &str,
    requested_auth: Option<AuthMethod>,
    identity_auth_domain: Option<&str>,
    is_interactive: bool,
) -> Result<ApplyApprovalPlan, Error> {
    if !is_interactive {
        return resolve_non_interactive_approval_plan(target, requested_auth, identity_auth_domain);
    }

    match requested_auth {
        Some(auth) => {
            resolve_non_interactive_approval_plan(target, Some(auth), identity_auth_domain)
        }
        None => {
            if let Some(auth_domain) = identity_auth_domain {
                let options = apply_verification_options(auth_domain);
                let labels = options
                    .iter()
                    .map(|(label, _)| label.clone())
                    .collect::<Vec<_>>();
                let message = format!("Choose how to verify applying {target}:");
                let selected = crate::cli::prompt::prompt_select_string(&message, labels)
                    .await
                    .require_interactive("--auth")?;
                return approval_plan_from_selection(&options, &selected);
            }
            Ok(ApplyApprovalPlan::Email)
        }
    }
}

fn apply_identity_name_opening() -> &'static str {
    "Apply an existing identity here.\n\nThis will create a new certificate chain for an existing identity\nand save it here.\n\nUse a dotted name:\n  <given_name>.<surname>\n\nFor example:\n  alice.smith\n\nTo apply a sub-identity, add one more name before it:\n  phone.alice.smith"
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

async fn prompt_apply_target() -> Result<dhttp::name::DhttpName<'static>, Error> {
    let identity = crate::cli::prompt::prompt_identity_name(apply_identity_name_opening())
        .await
        .require_interactive("IDENTITY")?;
    cli::parse_identity_name(&identity)
}

async fn resolve_target(command: &Apply) -> Result<dhttp::name::DhttpName<'static>, Error> {
    match explicit_target_from_command(command)? {
        Some(name) => Ok(name),
        None => prompt_apply_target().await,
    }
}

async fn resolve_kind(command: &Apply) -> Result<IdentityKind, Error> {
    match command.kind.as_deref() {
        Some(kind) => Ok(kind.parse::<IdentityKind>()?),
        None => Ok(crate::cli::prompt::prompt_kind()
            .await
            .require_interactive("--kind")?
            .parse::<IdentityKind>()?),
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

async fn resolve_identity_auth_domain(
    dhttp_home: &DhttpHome,
    target: &IdentityTarget,
) -> Result<Option<dhttp::name::DhttpName<'static>>, Error> {
    if dhttp_home
        .identity_profile_exists_exactly(target.dhttp_name())
        .await
    {
        let summary = local::load_summary(dhttp_home, target.dhttp_name(), None).await?;
        if matches!(summary.status, LocalIdentityStatus::Ready { .. }) {
            return Ok(Some(target.dhttp_name().into_owned()));
        }
    }

    if target.level() == IdentityLevel::SubIdentity
        && let Some(parent) = target.parent()
        && dhttp_home
            .identity_profile_exists_exactly(parent.clone())
            .await
    {
        let summary = local::load_summary(dhttp_home, parent.clone(), None).await?;
        if matches!(summary.status, LocalIdentityStatus::Ready { .. }) {
            return Ok(Some(parent.into_owned()));
        }
    }

    Ok(None)
}

async fn resolve_apply_candidate(
    dhttp_home: &DhttpHome,
    target: &IdentityTarget,
) -> Result<Option<approval::LocalApprovalCandidate>, Error> {
    let target_candidate = if dhttp_home
        .identity_profile_exists_exactly(target.dhttp_name())
        .await
    {
        let summary = local::load_summary(dhttp_home, target.dhttp_name(), None).await?;
        Some(apply_candidate_from_summary(&summary))
    } else {
        None
    };

    let parent_candidate = if target.level() == IdentityLevel::SubIdentity {
        if let Some(parent) = target.parent() {
            if dhttp_home
                .identity_profile_exists_exactly(parent.clone())
                .await
            {
                let summary = local::load_summary(dhttp_home, parent.clone(), None).await?;
                Some(apply_candidate_from_summary(&summary))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    if matches!(
        target_candidate,
        Some(approval::LocalApprovalCandidate::Ready { .. })
    ) {
        return Ok(target_candidate);
    }
    if matches!(
        parent_candidate,
        Some(approval::LocalApprovalCandidate::Ready { .. })
    ) {
        return Ok(parent_candidate);
    }

    Ok(target_candidate.or(parent_candidate))
}

async fn run_helper_apply_action(
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
    auth_domain: &str,
    action: approval::ApprovalHelperAction,
    return_to: Option<&str>,
) -> Result<bool, Error> {
    match action {
        approval::ApprovalHelperAction::Apply | approval::ApprovalHelperAction::Reapply => {
            let command = Apply {
                name: Some(auth_domain.to_string()),
                kind: None,
                replace_local: matches!(action, approval::ApprovalHelperAction::Reapply),
                device_name: None,
                email: None,
                send_code: false,
                verify_code: None,
                auth: None,
            };
            match Box::pin(run_interactive(
                &command,
                dhttp_home,
                home_scope,
                cert_server,
                return_to,
            ))
            .await?
            {
                ApplyRunOutcome::Applied => Ok(true),
                ApplyRunOutcome::ReturnedToCaller => Ok(false),
            }
        }
        approval::ApprovalHelperAction::Renew => {
            super::renew::run_helper_for_verification(
                dhttp_home,
                cert_server,
                auth_domain,
                return_to.unwrap_or("apply"),
            )
            .await
        }
    }
}

async fn prompt_apply_verify_code_action(
    return_to: Option<&str>,
) -> Result<ApplyVerifyCodeAction, Error> {
    let actions = apply_verify_code_actions(return_to);
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

async fn prompt_apply_email_action(return_to: Option<&str>) -> Result<ApplyEmailAction, Error> {
    let actions = apply_email_actions(return_to);
    let labels = actions
        .iter()
        .map(ApplyEmailAction::label)
        .collect::<Vec<_>>();
    let selected = crate::cli::prompt::prompt_select_string("More options:", labels.clone())
        .await
        .require_interactive("interactive input")?;
    actions
        .into_iter()
        .zip(labels)
        .find_map(|(action, label)| (label == selected).then_some(action))
        .whatever_context::<_, Error>("selected apply email action is unavailable")
}

async fn prompt_apply_approval_menu_action(
    return_to: Option<&str>,
) -> Result<ApplyApprovalMenuAction, Error> {
    let actions = apply_approval_menu_actions(return_to);
    let labels = actions
        .iter()
        .map(ApplyApprovalMenuAction::label)
        .collect::<Vec<_>>();
    let selected = crate::cli::prompt::prompt_select_string("More options:", labels.clone())
        .await
        .require_interactive("interactive input")?;
    actions
        .into_iter()
        .zip(labels)
        .find_map(|(action, label)| (label == selected).then_some(action))
        .whatever_context::<_, Error>("selected apply approval action is unavailable")
}

async fn run_post_save_epilogue(
    post_save: ApplyPostSavePolicy,
    dhttp_home: &DhttpHome,
    domain: dhttp::name::DhttpName<'_>,
    default_identity_when_command_started: Option<dhttp::name::DhttpName<'static>>,
    interactive: bool,
    welcome: Option<&super::welcome::WelcomeServiceCreated>,
) -> Result<(), Error> {
    match post_save {
        ApplyPostSavePolicy::ManageDefaultSuggestion => {
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
        ApplyPostSavePolicy::SkipDefaultSuggestion => {
            crate::cli::flow::epilogue::run_local_epilogue(
                dhttp_home,
                domain,
                super::output::SavedIdentityAction::Applied,
                welcome,
            )
            .await
        }
    }
}

async fn run_interactive_with_policy(
    command: &Apply,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
    return_to: Option<&str>,
    post_save: ApplyPostSavePolicy,
) -> Result<ApplyRunOutcome, Error> {
    let default_identity_when_command_started = cli::load_current_settings(dhttp_home)
        .await?
        .and_then(|config| config.settings().default_identity_name().cloned());
    let initial_target = explicit_target_from_command(command)?;
    let mut state = InteractiveApplyState::from_command(command, initial_target)?;

    loop {
        if state.target.is_none() {
            state.target = Some(prompt_apply_target().await?);
            continue;
        }

        if state.kind.is_none() || state.kind_prompt_required {
            state.kind = Some(
                crate::cli::prompt::prompt_kind_with_cursor(state.kind)
                    .await
                    .require_interactive("--kind")?
                    .parse::<IdentityKind>()?,
            );
            state.kind_prompt_required = false;
            continue;
        }

        let domain = state
            .target
            .clone()
            .whatever_context::<_, Error>("interactive apply target is unavailable")?;
        let target = IdentityTarget::parse(domain.as_partial())?;
        let identity_auth_domain = resolve_identity_auth_domain(dhttp_home, &target).await?;
        let approval_candidate = resolve_apply_candidate(dhttp_home, &target).await?;

        if state.approval_plan.is_none() {
            if let Some(auth) = command.auth {
                state.approval_plan = Some(resolve_non_interactive_approval_plan(
                    target.short_name(),
                    Some(auth),
                    identity_auth_domain.as_ref().map(|name| name.as_full()),
                )?);
                continue;
            }

            if let Some(candidate) = approval_candidate.clone() {
                let options = build_apply_approval_options(Some(candidate));
                let mut labels = options
                    .iter()
                    .map(approval::ApprovalMenuOption::label)
                    .collect::<Vec<_>>();
                labels.push(crate::cli::prompt::MORE_OPTIONS_LABEL.to_string());
                let message = format!("Choose how to verify applying {}:", target.short_name());
                let selected = crate::cli::prompt::prompt_select_string(&message, labels)
                    .await
                    .require_interactive("--auth")?;
                if selected == crate::cli::prompt::MORE_OPTIONS_LABEL {
                    match prompt_apply_approval_menu_action(return_to).await? {
                        ApplyApprovalMenuAction::ChangeCertificateKind => state.revisit_kind(),
                        ApplyApprovalMenuAction::ChangeIdentitySelection => {
                            state.revisit_target_selection();
                        }
                        ApplyApprovalMenuAction::ReturnToCaller { .. } => {
                            return Ok(ApplyRunOutcome::ReturnedToCaller);
                        }
                    }
                } else {
                    let option = options
                        .iter()
                        .find(|option| option.label() == selected)
                        .whatever_context::<_, Error>("selected approval path is unavailable")?;
                    state.approval_plan = Some(apply_plan_from_option(option));
                }
            } else {
                state.approval_plan = Some(ApplyApprovalPlan::Email);
            }
            continue;
        }

        let approval_plan = state
            .approval_plan
            .clone()
            .whatever_context::<_, Error>("interactive apply approval plan is unavailable")?;
        if let ApplyApprovalPlan::HelperIdentity {
            auth_domain,
            action,
        } = approval_plan.clone()
        {
            if !run_helper_apply_action(
                dhttp_home,
                home_scope,
                cert_server,
                &auth_domain,
                action,
                return_to,
            )
            .await?
            {
                state.approval_plan = None;
                state.revisit_verification_method();
                continue;
            }
            state.approval_plan = Some(ApplyApprovalPlan::DirectIdentity { auth_domain });
            continue;
        }

        if matches!(approval_plan, ApplyApprovalPlan::Email)
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
                    match prompt_apply_email_action(return_to).await? {
                        ApplyEmailAction::SwitchVerificationMethod => {
                            state.revisit_verification_method();
                        }
                        ApplyEmailAction::ChangeCertificateKind => state.revisit_kind(),
                        ApplyEmailAction::ChangeIdentitySelection => {
                            state.revisit_target_selection();
                        }
                        ApplyEmailAction::ReturnToCaller { .. } => {
                            return Ok(ApplyRunOutcome::ReturnedToCaller);
                        }
                    }
                }
            }
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
                    match prompt_apply_verify_code_action(return_to).await? {
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
                        ApplyVerifyCodeAction::SwitchVerificationMethod => {
                            state.revisit_verification_method();
                        }
                        ApplyVerifyCodeAction::ChangeCertificateKind => state.revisit_kind(),
                        ApplyVerifyCodeAction::ChangeIdentitySelection => {
                            state.revisit_target_selection();
                        }
                        ApplyVerifyCodeAction::ReturnToCaller { .. } => {
                            return Ok(ApplyRunOutcome::ReturnedToCaller);
                        }
                    }
                }
            }
            continue;
        }

        cli::ensure_replace_local_allowed(dhttp_home, domain.borrow(), command.replace_local)
            .await?;
        let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&domain)?;
        let kind = state
            .kind
            .whatever_context::<_, Error>("interactive apply kind is unavailable")?;
        let device_name = super::device::resolve_device_name(command.device_name.as_deref());
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
                    cert_server.domain_login(domain.as_full(), &email, verify_code),
                )
                .await
                {
                    Ok(login) => login.access_token,
                    Err(error) => {
                        let recovery =
                            crate::cli::flow::recovery::classify_verify_submit_error(&error);
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
                .await?
            }
            ApplyApprovalPlan::DirectIdentity { auth_domain } => {
                super::progress::run_with_spinner(
                    "Verifying with local identity...",
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
            ApplyApprovalPlan::HelperIdentity { .. } => {
                unreachable!("helper approval plan should be resolved before issuing certificate")
            }
        };

        cli::save_identity(
            dhttp_home,
            &domain,
            key_pem.as_bytes(),
            detail.cert_pem.as_bytes(),
        )
        .instrument(info_span!("save_identity"))
        .await?;
        let welcome =
            super::welcome::maybe_create_welcome_service(dhttp_home, domain.borrow(), home_scope)
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

pub(crate) async fn run_interactive(
    command: &Apply,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
    return_to: Option<&str>,
) -> Result<ApplyRunOutcome, Error> {
    run_interactive_with_policy(
        command,
        dhttp_home,
        home_scope,
        cert_server,
        return_to,
        ApplyPostSavePolicy::ManageDefaultSuggestion,
    )
    .await
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
            None,
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
    let domain = resolve_target(command).await?;
    let target = IdentityTarget::parse(domain.as_partial())?;
    let kind = resolve_kind(command).await?;
    let device_name = super::device::resolve_device_name(command.device_name.as_deref());
    let identity_auth_domain = resolve_identity_auth_domain(dhttp_home, &target).await?;
    let approval_plan = resolve_approval_plan(
        target.short_name(),
        command.auth,
        identity_auth_domain.as_ref().map(|name| name.as_full()),
        is_interactive,
    )
    .await?;

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

    cli::ensure_replace_local_allowed(dhttp_home, domain.borrow(), command.replace_local).await?;
    let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&domain)?;
    let detail = match approval_plan {
        ApplyApprovalPlan::Email => {
            let email = resolve_email(command).await?;
            let token = cli::login_with_email(
                cert_server,
                Some(&domain),
                Some(email),
                command.verify_code.clone(),
            )
            .await?;
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
            .await?
        }
        ApplyApprovalPlan::DirectIdentity { auth_domain } => {
            super::progress::run_with_spinner(
                "Verifying with local identity...",
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
        ApplyApprovalPlan::HelperIdentity { .. } => {
            unreachable!("helper approval plan should be resolved before issuing certificate")
        }
    };

    cli::save_identity(
        dhttp_home,
        &domain,
        key_pem.as_bytes(),
        detail.cert_pem.as_bytes(),
    )
    .instrument(info_span!("save_identity"))
    .await?;
    let welcome =
        super::welcome::maybe_create_welcome_service(dhttp_home, domain.borrow(), home_scope)
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
        ApplyApprovalMenuAction, ApplyApprovalPlan, ApplyEmailAction, ApplyVerifyCodeAction,
        InteractiveApplyState, apply_approval_menu_actions, apply_email_actions,
        apply_identity_name_opening, apply_verification_options, apply_verify_code_actions,
        approval_plan_from_selection, build_apply_approval_options, explicit_target_from_command,
        resolve_non_interactive_approval_plan,
    };
    use crate::{
        auth::AuthMethod,
        cli::{
            Apply,
            flow::approval::{ApprovalMenuOption, LocalApprovalCandidate},
        },
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
                message: "retry later",
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
                message: "start over",
            },
        );

        assert!(state.email_prompt_required);
        assert!(state.verify_code.is_none());
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
    fn root_apply_with_local_auth_requires_explicit_auth_non_interactively() {
        let error = resolve_non_interactive_approval_plan("alice.smith", None, Some("alice.smith"))
            .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("--auth email"), "{rendered}");
        assert!(rendered.contains("--auth identity"), "{rendered}");
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
    fn sub_identity_apply_with_parent_local_auth_still_requires_explicit_auth_when_missing() {
        let error =
            resolve_non_interactive_approval_plan("phone.alice.smith", None, Some("alice.smith"))
                .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("--auth email"), "{rendered}");
        assert!(rendered.contains("--auth identity"), "{rendered}");
    }

    #[test]
    fn apply_identity_name_opening_matches_spec_copy() {
        let opening = apply_identity_name_opening();
        assert!(opening.contains("Apply an existing identity here."));
        assert!(opening.contains("<given_name>.<surname>"));
        assert!(opening.contains("alice.smith"));
        assert!(opening.contains("phone.alice.smith"));
    }

    #[test]
    fn apply_with_invalid_local_identity_uses_reapply_copy() {
        let options = build_apply_approval_options(Some(LocalApprovalCandidate::invalid(
            "alice.smith",
            "alice.smith.dhttp.net",
            "certificate is unreadable",
        )));

        assert_eq!(
            options
                .iter()
                .map(ApprovalMenuOption::label)
                .collect::<Vec<_>>(),
            vec![
                "Verify with email".to_string(),
                "Re-apply alice.smith here, then verify with alice.smith".to_string(),
            ]
        );
    }

    #[test]
    fn apply_with_expired_local_identity_shows_renew_before_reapply() {
        let options = build_apply_approval_options(Some(LocalApprovalCandidate::expired(
            "alice.smith",
            "alice.smith.dhttp.net",
            true,
            true,
        )));

        assert_eq!(
            options
                .iter()
                .map(ApprovalMenuOption::label)
                .collect::<Vec<_>>(),
            vec![
                "Verify with email".to_string(),
                "Renew alice.smith here, then verify with alice.smith".to_string(),
                "Re-apply alice.smith here, then verify with alice.smith".to_string(),
            ]
        );
    }

    #[test]
    fn interactive_apply_selection_can_choose_email() {
        let options = apply_verification_options("alice.smith.dhttp.net");

        assert_eq!(
            approval_plan_from_selection(&options, "Verify with email").unwrap(),
            ApplyApprovalPlan::Email,
        );
    }

    #[test]
    fn interactive_apply_selection_can_choose_local_identity() {
        let options = apply_verification_options("alice.smith.dhttp.net");

        assert_eq!(
            approval_plan_from_selection(&options, "Verify with alice.smith on local device",)
                .unwrap(),
            ApplyApprovalPlan::DirectIdentity {
                auth_domain: "alice.smith.dhttp.net".to_string(),
            },
        );
    }

    #[test]
    fn apply_verify_code_actions_include_return_to_parent_flow() {
        assert_eq!(
            apply_verify_code_actions(Some("create phone.alice.smith"))
                .into_iter()
                .map(|action| action.label())
                .collect::<Vec<_>>(),
            vec![
                "Resend verification code".to_string(),
                "Send code to another email (go back to email)".to_string(),
                "Switch verification method (go back to verification method selection)".to_string(),
                "Change certificate kind (go back to identity kind)".to_string(),
                "Change identity (go back to identity selection)".to_string(),
                "Return to create phone.alice.smith".to_string(),
            ]
        );
        assert_eq!(
            apply_verify_code_actions(Some("create phone.alice.smith")),
            vec![
                ApplyVerifyCodeAction::ResendVerificationCode,
                ApplyVerifyCodeAction::ChangeEmail,
                ApplyVerifyCodeAction::SwitchVerificationMethod,
                ApplyVerifyCodeAction::ChangeCertificateKind,
                ApplyVerifyCodeAction::ChangeIdentitySelection,
                ApplyVerifyCodeAction::ReturnToCaller {
                    label: "create phone.alice.smith".to_string(),
                },
            ]
        );
    }

    #[test]
    fn apply_email_actions_include_explicit_return_points() {
        assert_eq!(
            apply_email_actions(Some("create phone.alice.smith"))
                .into_iter()
                .map(|action| action.label())
                .collect::<Vec<_>>(),
            vec![
                "Switch verification method (go back to verification method selection)".to_string(),
                "Change certificate kind (go back to identity kind)".to_string(),
                "Change identity (go back to identity selection)".to_string(),
                "Return to create phone.alice.smith".to_string(),
            ]
        );
        assert_eq!(
            apply_email_actions(Some("create phone.alice.smith")),
            vec![
                ApplyEmailAction::SwitchVerificationMethod,
                ApplyEmailAction::ChangeCertificateKind,
                ApplyEmailAction::ChangeIdentitySelection,
                ApplyEmailAction::ReturnToCaller {
                    label: "create phone.alice.smith".to_string(),
                },
            ]
        );
    }

    #[test]
    fn apply_approval_menu_actions_include_explicit_return_points() {
        assert_eq!(
            apply_approval_menu_actions(Some("create phone.alice.smith"))
                .into_iter()
                .map(|action| action.label())
                .collect::<Vec<_>>(),
            vec![
                "Change certificate kind (go back to identity kind)".to_string(),
                "Change identity (go back to identity selection)".to_string(),
                "Return to create phone.alice.smith".to_string(),
            ]
        );
        assert_eq!(
            apply_approval_menu_actions(Some("create phone.alice.smith")),
            vec![
                ApplyApprovalMenuAction::ChangeCertificateKind,
                ApplyApprovalMenuAction::ChangeIdentitySelection,
                ApplyApprovalMenuAction::ReturnToCaller {
                    label: "create phone.alice.smith".to_string(),
                },
            ]
        );
    }
}
