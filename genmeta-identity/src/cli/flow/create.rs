use std::io::IsTerminal;

use dhttp::home::DhttpHome;
use snafu::{FromString, OptionExt, whatever};
use tracing::{Instrument, info_span};

use super::{
    approval,
    kind::IdentityKind,
    local::{self, LocalIdentityStatus, LocalIdentitySummary},
    target::{IdentityLevel, IdentityTarget},
};
use crate::{
    auth::AuthMethod,
    cert_server::{
        CertServer, CreateDomainResponse, CreateSubdomainAttempt, CreateSubdomainResponse,
        InvoiceDetail, SubdomainQuotaQuote,
    },
    cli::{
        self, Create, Error,
        prompt::{self, InquireResultExt},
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreateApprovalPlan {
    parent_identity: Option<String>,
    auth: AuthMethod,
    helper_action: Option<approval::ApprovalHelperAction>,
}

#[derive(Debug)]
enum CompleteRootIdentityCreateInteractivelyError {
    Verification { source: crate::cert_server::Error },
    Flow { source: Error },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CreateEmailAction {
    SwitchVerificationMethod,
    ChangeCertificateKind,
    ChangeIdentityName,
}

impl CreateEmailAction {
    fn label(&self) -> String {
        match self {
            Self::SwitchVerificationMethod => {
                "Switch verification method (go back to verification method selection)".to_string()
            }
            Self::ChangeCertificateKind => {
                "Change certificate kind (go back to identity kind)".to_string()
            }
            Self::ChangeIdentityName => {
                "Change identity name (go back to identity name)".to_string()
            }
        }
    }
}

fn create_email_actions(can_switch_verification_method: bool) -> Vec<CreateEmailAction> {
    let mut actions = Vec::new();
    if can_switch_verification_method {
        actions.push(CreateEmailAction::SwitchVerificationMethod);
    }
    actions.push(CreateEmailAction::ChangeCertificateKind);
    actions.push(CreateEmailAction::ChangeIdentityName);
    actions
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CreateVerifyCodeAction {
    ResendVerificationCode,
    ChangeEmail,
    SwitchVerificationMethod,
    ChangeCertificateKind,
    ChangeIdentityName,
    ReturnToCreate { target_name: String },
}

impl CreateVerifyCodeAction {
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
            Self::ChangeIdentityName => {
                "Change identity name (go back to identity name)".to_string()
            }
            Self::ReturnToCreate { target_name } => {
                format!("Return to create {target_name}")
            }
        }
    }
}

fn create_verify_code_actions(return_target_name: Option<&str>) -> Vec<CreateVerifyCodeAction> {
    let mut actions = vec![
        CreateVerifyCodeAction::ResendVerificationCode,
        CreateVerifyCodeAction::ChangeEmail,
        CreateVerifyCodeAction::SwitchVerificationMethod,
        CreateVerifyCodeAction::ChangeCertificateKind,
        CreateVerifyCodeAction::ChangeIdentityName,
    ];
    if let Some(target_name) = return_target_name {
        actions.push(CreateVerifyCodeAction::ReturnToCreate {
            target_name: target_name.to_string(),
        });
    }
    actions
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreateApprovalMenuAction {
    ChangeCertificateKind,
    ChangeIdentityName,
}

impl CreateApprovalMenuAction {
    fn label(self) -> String {
        match self {
            Self::ChangeCertificateKind => {
                "Change certificate kind (go back to identity kind)".to_string()
            }
            Self::ChangeIdentityName => {
                "Change identity name (go back to identity name)".to_string()
            }
        }
    }
}

#[derive(Debug, Clone)]
struct InteractiveCreateState {
    target: Option<IdentityTarget>,
    target_opening_required: bool,
    kind: Option<IdentityKind>,
    kind_prompt_required: bool,
    approval_plan: Option<CreateApprovalPlan>,
    email: Option<String>,
    email_prompt_required: bool,
    verify_code: Option<String>,
    verification_code_sent_to: Option<String>,
}

impl InteractiveCreateState {
    fn from_command(command: &Create) -> Result<Self, Error> {
        Ok(Self {
            target: command
                .name
                .as_deref()
                .map(IdentityTarget::parse)
                .transpose()?,
            target_opening_required: command.name.is_none(),
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

    fn reset_after_target_change(&mut self) {
        self.kind = None;
        self.kind_prompt_required = true;
        self.reset_after_kind_change();
        self.target_opening_required = true;
    }

    fn reset_after_kind_change(&mut self) {
        self.kind_prompt_required = false;
        self.approval_plan = None;
        self.reset_after_approval_change();
    }

    fn reset_after_approval_change(&mut self) {
        self.email = None;
        self.email_prompt_required = true;
        self.reset_after_email_change();
    }

    fn reset_after_email_change(&mut self) {
        self.verify_code = None;
        self.verification_code_sent_to = None;
    }

    fn revisit_target_prompt(&mut self) {
        self.kind = None;
        self.kind_prompt_required = true;
        self.approval_plan = None;
        self.reset_after_approval_change();
        self.target_opening_required = true;
    }

    fn revisit_kind_prompt(&mut self) {
        self.approval_plan = None;
        self.reset_after_approval_change();
        self.kind_prompt_required = true;
    }

    fn revisit_email_prompt(&mut self) {
        self.reset_after_email_change();
        self.email_prompt_required = true;
    }
}

fn apply_verification_recovery(
    state: &mut InteractiveCreateState,
    recovery: &crate::cli::flow::recovery::VerificationRecovery,
) -> bool {
    match recovery {
        crate::cli::flow::recovery::VerificationRecovery::StayCurrentStep { message } => {
            crate::cli::flow::transcript::print_line(*message);
            true
        }
        crate::cli::flow::recovery::VerificationRecovery::BackToEmail { message } => {
            crate::cli::flow::transcript::print_line(*message);
            state.revisit_email_prompt();
            true
        }
        crate::cli::flow::recovery::VerificationRecovery::Abort => false,
    }
}

fn build_create_approval_options(
    candidate: Option<approval::LocalApprovalCandidate>,
) -> Vec<approval::ApprovalMenuOption> {
    approval::build_options_for_candidate("Verify with email", candidate)
}

fn create_plan_from_selection(
    options: &[approval::ApprovalMenuOption],
    selected: &str,
    parent_identity: Option<&str>,
) -> Result<CreateApprovalPlan, Error> {
    let option = options
        .iter()
        .find(|option| option.label() == selected)
        .whatever_context::<_, Error>("selected approval path is unavailable")?;

    match option {
        approval::ApprovalMenuOption::Email { .. } => Ok(CreateApprovalPlan {
            parent_identity: parent_identity.map(str::to_string),
            auth: AuthMethod::Email,
            helper_action: None,
        }),
        approval::ApprovalMenuOption::DirectLocal(local) => Ok(CreateApprovalPlan {
            parent_identity: Some(local.auth_domain.clone()),
            auth: AuthMethod::Identity,
            helper_action: None,
        }),
        approval::ApprovalMenuOption::Helper(helper) => Ok(CreateApprovalPlan {
            parent_identity: Some(helper.auth_domain.clone()),
            auth: AuthMethod::Identity,
            helper_action: Some(helper.action.clone()),
        }),
    }
}

fn create_candidate_from_summary(
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

fn resolve_non_interactive_approval_plan(
    target: &IdentityTarget,
    requested_auth: Option<AuthMethod>,
    ready_parent_identity: Option<&str>,
) -> Result<CreateApprovalPlan, Error> {
    match target.level() {
        IdentityLevel::Identity => match requested_auth {
            Some(AuthMethod::Identity) => whatever!(
                "creating {} requires email verification; rerun without --auth or use --auth email instead of --auth identity",
                target.short_name()
            ),
            Some(AuthMethod::Email) | None => Ok(CreateApprovalPlan {
                parent_identity: None,
                auth: AuthMethod::Email,
                helper_action: None,
            }),
        },
        IdentityLevel::SubIdentity => {
            let parent_identity = target
                .parent()
                .expect("BUG: sub-identity should always expose its parent")
                .as_partial()
                .to_string();
            match requested_auth {
                Some(AuthMethod::Identity) => {
                    let Some(ready_parent_identity) = ready_parent_identity else {
                        whatever!(
                            "creating {} with --auth identity requires a ready local parent identity on this device",
                            target.short_name()
                        );
                    };
                    Ok(CreateApprovalPlan {
                        parent_identity: Some(ready_parent_identity.to_string()),
                        auth: AuthMethod::Identity,
                        helper_action: None,
                    })
                }
                Some(AuthMethod::Email) => Ok(CreateApprovalPlan {
                    parent_identity: Some(parent_identity),
                    auth: AuthMethod::Email,
                    helper_action: None,
                }),
                None => {
                    if ready_parent_identity.is_some() {
                        whatever!(
                            "creating {} non-interactively requires choosing an approval path; rerun with --auth email or --auth identity",
                            target.short_name()
                        );
                    }
                    Ok(CreateApprovalPlan {
                        parent_identity: Some(parent_identity),
                        auth: AuthMethod::Email,
                        helper_action: None,
                    })
                }
            }
        }
    }
}

async fn resolve_approval_plan(
    target: &IdentityTarget,
    requested_auth: Option<AuthMethod>,
    ready_parent_identity: Option<&str>,
    is_interactive: bool,
) -> Result<CreateApprovalPlan, Error> {
    if !is_interactive {
        return resolve_non_interactive_approval_plan(
            target,
            requested_auth,
            ready_parent_identity,
        );
    }

    match requested_auth {
        Some(auth) => {
            resolve_non_interactive_approval_plan(target, Some(auth), ready_parent_identity)
        }
        None => match target.level() {
            IdentityLevel::Identity => Ok(CreateApprovalPlan {
                parent_identity: None,
                auth: AuthMethod::Email,
                helper_action: None,
            }),
            IdentityLevel::SubIdentity => {
                let parent = target
                    .parent()
                    .whatever_context::<_, Error>(
                        "sub-identity target is missing its parent identity",
                    )?
                    .into_owned();
                let candidate = if let Some(parent_identity) = ready_parent_identity {
                    Some(approval::LocalApprovalCandidate::ready(
                        parent.as_partial(),
                        parent_identity,
                    ))
                } else {
                    Some(approval::LocalApprovalCandidate::missing(
                        parent.as_partial(),
                        parent.as_full(),
                    ))
                };
                let options = build_create_approval_options(candidate);
                let labels = options
                    .iter()
                    .map(approval::ApprovalMenuOption::label)
                    .collect::<Vec<_>>();
                let message = format!("Choose how to verify creating {}:", target.short_name());
                let selected = prompt::prompt_select_string(&message, labels)
                    .await
                    .require_interactive("--auth")?;
                create_plan_from_selection(&options, &selected, Some(parent.as_full()))
            }
        },
    }
}

fn ensure_non_interactive_root_checkout_not_required(
    target: &IdentityTarget,
    response: &CreateDomainResponse,
) -> Result<(), Error> {
    match crate::checkout::classify_checkout(response) {
        crate::checkout::CheckoutState::Completed => Ok(()),
        crate::checkout::CheckoutState::Pending
        | crate::checkout::CheckoutState::Expired
        | crate::checkout::CheckoutState::Cancelled => whatever!(
            "creating {} requires interactive checkout; rerun this command in an interactive terminal to complete payment",
            target.short_name()
        ),
    }
}

fn ensure_non_interactive_sub_identity_checkout_not_required(
    target: &IdentityTarget,
    response: &CreateSubdomainResponse,
) -> Result<(), Error> {
    if response.invoice.is_some() {
        whatever!(
            "creating {} requires interactive checkout; rerun this command in an interactive terminal to expand the parent identity quota",
            target.short_name()
        );
    }
    Ok(())
}

fn create_identity_name_opening() -> &'static str {
    "Create a new identity for this device.\n\nThis will create a new identity or sub-identity, complete the required verification,\nand save it on this device.\n\nUse a dotted name:\n  <given_name>.<surname>\n\nFor example:\n  alice.smith\n\nTo create a sub-identity, add one more name before it:\n  phone.alice.smith"
}

async fn prompt_create_email_action(
    can_switch_verification_method: bool,
) -> Result<CreateEmailAction, Error> {
    let actions = create_email_actions(can_switch_verification_method);
    let labels = actions
        .iter()
        .map(CreateEmailAction::label)
        .collect::<Vec<_>>();
    let selected = prompt::prompt_select_string("More options:", labels.clone())
        .await
        .require_interactive("interactive input")?;
    actions
        .into_iter()
        .zip(labels)
        .find_map(|(action, label)| (label == selected).then_some(action))
        .whatever_context::<_, Error>("selected create email action is unavailable")
}

async fn prompt_create_verify_code_action(
    return_target_name: Option<&str>,
) -> Result<CreateVerifyCodeAction, Error> {
    let actions = create_verify_code_actions(return_target_name);
    let labels = actions
        .iter()
        .map(CreateVerifyCodeAction::label)
        .collect::<Vec<_>>();
    let selected = prompt::prompt_select_string("More options:", labels.clone())
        .await
        .require_interactive("interactive input")?;
    actions
        .into_iter()
        .zip(labels)
        .find_map(|(action, label)| (label == selected).then_some(action))
        .whatever_context::<_, Error>("selected verification-code action is unavailable")
}

async fn prompt_create_approval_menu_action() -> Result<CreateApprovalMenuAction, Error> {
    let actions = [
        CreateApprovalMenuAction::ChangeCertificateKind,
        CreateApprovalMenuAction::ChangeIdentityName,
    ];
    let labels = actions
        .iter()
        .map(|action| action.label())
        .collect::<Vec<_>>();
    let selected = prompt::prompt_select_string("More options:", labels.clone())
        .await
        .require_interactive("interactive input")?;
    actions
        .into_iter()
        .zip(labels)
        .find_map(|(action, label)| (label == selected).then_some(action))
        .whatever_context::<_, Error>("selected create approval action is unavailable")
}

async fn prompt_restart_checkout(message: &str) -> Result<bool, Error> {
    let message = message.to_string();
    Ok(
        prompt::sync(move || inquire::Confirm::new(&message).with_default(true).prompt())
            .await
            .require_interactive("interactive input")?,
    )
}

fn can_switch_verification_method(target: &IdentityTarget) -> bool {
    target.level() == IdentityLevel::SubIdentity
}

fn print_root_checkout_instructions(target: &IdentityTarget, response: &CreateDomainResponse) {
    if let Some(payment_entry) = response.payment_entry.as_ref() {
        crate::cli::flow::transcript::print_block(&format!(
            "Payment is required to create {}.\n\nOpen this checkout page to continue:\n  {}",
            target.short_name(),
            payment_entry.url
        ));
    }
}

fn print_subdomain_checkout_instructions(
    target: &IdentityTarget,
    invoice: &InvoiceDetail,
    quote: &SubdomainQuotaQuote,
) {
    crate::cli::flow::transcript::print_block(&format!(
        "Adding one more sub-identity slot is required to create {}.\n\nAmount due now: {} {}\nOpen this checkout page to continue:\n  {}",
        target.short_name(),
        quote.currency,
        format_minor_amount(quote.due),
        invoice.url
    ));
}

fn format_minor_amount(amount: i64) -> String {
    let major = amount / 100;
    let cents = amount.abs() % 100;
    format!("{major}.{cents:02}")
}

async fn resolve_target(command: &Create) -> Result<IdentityTarget, Error> {
    match command.name.as_deref() {
        Some(identity) => Ok(IdentityTarget::parse(identity)?),
        None => {
            let identity = prompt::prompt_identity_name(create_identity_name_opening())
                .await
                .require_interactive("IDENTITY")?;
            Ok(IdentityTarget::parse(&identity)?)
        }
    }
}

async fn resolve_kind(command: &Create) -> Result<IdentityKind, Error> {
    match command.kind.as_deref() {
        Some(kind) => Ok(kind.parse::<IdentityKind>()?),
        None => Ok(prompt::prompt_kind()
            .await
            .require_interactive("--kind")?
            .parse::<IdentityKind>()?),
    }
}

async fn resolve_email(command: &Create) -> Result<String, Error> {
    match command.email.clone() {
        Some(email) => Ok(email),
        None => Ok(prompt::prompt_email()
            .await
            .require_interactive("--email")?),
    }
}

async fn resolve_verify_code(
    cert_server: &CertServer,
    email: &str,
    provided_verify_code: Option<String>,
) -> Result<String, Error> {
    match provided_verify_code {
        Some(code) => Ok(code),
        None => {
            super::progress::run_with_spinner(
                "Sending verification code...",
                cert_server.send_email_verification(email),
            )
            .await?;
            Ok(prompt::prompt_verify_code()
                .await
                .require_interactive("--verify-code")?)
        }
    }
}

async fn ensure_parent_identity_ready(
    dhttp_home: &DhttpHome,
    target: &IdentityTarget,
) -> Result<dhttp::name::DhttpName<'static>, Error> {
    let parent = target
        .parent()
        .whatever_context::<_, Error>("sub-identity target is missing its parent identity")?
        .into_owned();
    let summary = local::load_summary(dhttp_home, parent.borrow(), None).await?;
    match summary.status {
        LocalIdentityStatus::Ready { .. } => Ok(parent),
        _ => whatever!(
            "creating {} with --auth identity requires a ready local parent identity at {}",
            target.short_name(),
            summary.saved_at.display()
        ),
    }
}

async fn resolve_ready_parent_identity(
    dhttp_home: &DhttpHome,
    target: &IdentityTarget,
) -> Result<Option<dhttp::name::DhttpName<'static>>, Error> {
    if target.level() != IdentityLevel::SubIdentity {
        return Ok(None);
    }

    let Some(parent) = target.parent() else {
        whatever!("sub-identity target is missing its parent identity");
    };
    if !dhttp_home
        .identity_profile_exists_exactly(parent.clone())
        .await
    {
        return Ok(None);
    }

    let summary = local::load_summary(dhttp_home, parent.clone(), None).await?;
    if summary.status.is_ready() {
        return Ok(Some(parent.into_owned()));
    }

    Ok(None)
}

async fn resolve_parent_candidate(
    dhttp_home: &DhttpHome,
    target: &IdentityTarget,
) -> Result<Option<approval::LocalApprovalCandidate>, Error> {
    if target.level() != IdentityLevel::SubIdentity {
        return Ok(None);
    }

    let parent = target
        .parent()
        .whatever_context::<_, Error>("sub-identity target is missing its parent identity")?
        .into_owned();
    if !dhttp_home
        .identity_profile_exists_exactly(parent.clone())
        .await
    {
        return Ok(Some(approval::LocalApprovalCandidate::missing(
            parent.as_partial(),
            parent.as_full(),
        )));
    }

    let summary = local::load_summary(dhttp_home, parent.borrow(), None).await?;
    Ok(Some(create_candidate_from_summary(&summary)))
}

async fn run_helper_apply_parent(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    target: &IdentityTarget,
    parent_identity: &str,
    replace_local: bool,
) -> Result<bool, Error> {
    let short_parent_identity = IdentityTarget::parse(parent_identity)
        .map(|target| target.short_name().to_string())
        .unwrap_or_else(|_| parent_identity.to_string());
    let verb = if replace_local { "re-apply" } else { "apply" };
    crate::cli::flow::transcript::print_block(&format!(
        "This command needs {short_parent_identity} available on this device first.

To continue creating {}, it will {verb} {short_parent_identity} on this device, then return here and continue verification.",
        target.short_name()
    ));
    let command = crate::cli::Apply {
        name: Some(parent_identity.to_string()),
        kind: None,
        replace_local,
        device_name: None,
        email: None,
        send_code: false,
        verify_code: None,
        auth: None,
    };
    match super::apply::run_interactive(
        &command,
        dhttp_home,
        cert_server,
        Some(&format!("create {}", target.short_name())),
    )
    .await?
    {
        super::apply::ApplyRunOutcome::Applied => Ok(true),
        super::apply::ApplyRunOutcome::ReturnedToCaller => Ok(false),
    }
}

async fn run_helper_parent_action(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    target: &IdentityTarget,
    parent_identity: &str,
    action: approval::ApprovalHelperAction,
) -> Result<bool, Error> {
    match action {
        approval::ApprovalHelperAction::Apply => {
            run_helper_apply_parent(dhttp_home, cert_server, target, parent_identity, false).await
        }
        approval::ApprovalHelperAction::Reapply => {
            run_helper_apply_parent(dhttp_home, cert_server, target, parent_identity, true).await
        }
        approval::ApprovalHelperAction::Renew => {
            super::renew::run_helper_for_verification(
                dhttp_home,
                cert_server,
                parent_identity,
                &format!("create {}", target.short_name()),
            )
            .await
        }
    }
}

async fn complete_root_identity_create_interactively(
    cert_server: &CertServer,
    target: &IdentityTarget,
    email: &str,
    verify_code: &str,
) -> Result<CreateDomainResponse, CompleteRootIdentityCreateInteractivelyError> {
    loop {
        let created = match super::progress::run_with_spinner(
            "Creating identity...",
            cert_server.create_domain_with_email(target.full_name(), email, verify_code),
        )
        .await
        {
            Ok(created) => created,
            Err(source) => {
                return Err(CompleteRootIdentityCreateInteractivelyError::Verification { source });
            }
        };
        if created.payment_entry.is_none() {
            return Ok(created);
        }

        print_root_checkout_instructions(target, &created);
        let completed = match crate::checkout::wait_for_checkout_completion(
            cert_server,
            &created
                .payment_entry
                .as_ref()
                .expect("payment entry just checked")
                .checkout_token,
        )
        .await
        {
            Ok(completed) => completed,
            Err(source) => {
                return Err(CompleteRootIdentityCreateInteractivelyError::Flow {
                    source: Error::from(source),
                });
            }
        };
        match crate::checkout::classify_checkout(&completed) {
            crate::checkout::CheckoutState::Completed => return Ok(created),
            crate::checkout::CheckoutState::Expired => {
                let restart = match prompt_restart_checkout(
                    "This checkout expired. Start a new checkout for this identity?",
                )
                .await
                {
                    Ok(restart) => restart,
                    Err(source) => {
                        return Err(CompleteRootIdentityCreateInteractivelyError::Flow { source });
                    }
                };
                if !restart {
                    return Err(CompleteRootIdentityCreateInteractivelyError::Flow {
                        source: Error::without_source("checkout was not completed".to_string()),
                    });
                }
            }
            crate::checkout::CheckoutState::Cancelled => {
                let restart = match prompt_restart_checkout(
                    "This checkout was cancelled. Start a new checkout for this identity?",
                )
                .await
                {
                    Ok(restart) => restart,
                    Err(source) => {
                        return Err(CompleteRootIdentityCreateInteractivelyError::Flow { source });
                    }
                };
                if !restart {
                    return Err(CompleteRootIdentityCreateInteractivelyError::Flow {
                        source: Error::without_source("checkout was not completed".to_string()),
                    });
                }
            }
            crate::checkout::CheckoutState::Pending => {
                return Err(CompleteRootIdentityCreateInteractivelyError::Flow {
                    source: Error::without_source(
                        "checkout did not reach a terminal state".to_string(),
                    ),
                });
            }
        }
    }
}

async fn wait_for_invoice_terminal(
    cert_server: &CertServer,
    access_token: &str,
    invoice_no: &str,
) -> Result<InvoiceDetail, Error> {
    super::progress::run_with_spinner("Waiting for payment confirmation...", async {
        loop {
            let invoice = cert_server.get_invoice(access_token, invoice_no).await?;
            match invoice.status.as_str() {
                "paid" | "expired" | "cancelled" | "canceled" => return Ok(invoice),
                _ => tokio::time::sleep(std::time::Duration::from_secs(3)).await,
            }
        }
    })
    .await
}

async fn create_sub_identity_with_email_interactively(
    cert_server: &CertServer,
    target: &IdentityTarget,
    access_token: &str,
    parent: &dhttp::name::DhttpName<'_>,
    label: &str,
) -> Result<CreateSubdomainResponse, Error> {
    loop {
        match super::progress::run_with_spinner(
            "Creating sub-identity...",
            cert_server.create_subdomain_attempt(access_token, parent.as_full(), label, None),
        )
        .await?
        {
            CreateSubdomainAttempt::Created(response) => return Ok(response),
            CreateSubdomainAttempt::QuotaExceeded(quote) => {
                let continue_checkout = prompt_restart_checkout(&format!(
                    "Creating {} needs one more sub-identity slot under {}. Start checkout now?",
                    target.short_name(),
                    parent.as_partial()
                ))
                .await?;
                if !continue_checkout {
                    whatever!("checkout was not completed");
                }

                loop {
                    let invoice_response = match super::progress::run_with_spinner(
                        "Creating sub-identity...",
                        cert_server.create_subdomain_attempt(
                            access_token,
                            parent.as_full(),
                            label,
                            Some(quote.due),
                        ),
                    )
                    .await?
                    {
                        CreateSubdomainAttempt::Created(response) => response,
                        CreateSubdomainAttempt::QuotaExceeded(_) => {
                            whatever!("subdomain quota expansion quote changed during checkout")
                        }
                    };
                    let invoice_no = invoice_response
                        .invoice
                        .as_ref()
                        .map(|invoice| invoice.number.as_str())
                        .whatever_context::<_, Error>(
                            "quota expansion checkout did not return an invoice number",
                        )?;
                    let invoice = super::progress::run_with_spinner(
                        "Loading payment details...",
                        cert_server.get_invoice(access_token, invoice_no),
                    )
                    .await?;
                    print_subdomain_checkout_instructions(target, &invoice, &quote);
                    let invoice =
                        wait_for_invoice_terminal(cert_server, access_token, invoice_no).await?;
                    match invoice.status.as_str() {
                        "paid" => break,
                        "expired" => {
                            if !prompt_restart_checkout(
                                "This checkout expired. Start a new checkout for this sub-identity slot?",
                            )
                            .await?
                            {
                                whatever!("checkout was not completed");
                            }
                        }
                        "cancelled" | "canceled" => {
                            if !prompt_restart_checkout(
                                "This checkout was cancelled. Start a new checkout for this sub-identity slot?",
                            )
                            .await?
                            {
                                whatever!("checkout was not completed");
                            }
                        }
                        _ => whatever!("invoice did not reach a terminal state"),
                    }
                }
            }
        }
    }
}

async fn run_interactive(
    command: &Create,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    let default_identity_when_command_started = cli::load_current_settings(dhttp_home)
        .await?
        .and_then(|config| config.settings().default_identity_name().cloned());
    let mut state = InteractiveCreateState::from_command(command)?;

    loop {
        if state.target.is_none() {
            let identity = prompt::prompt_identity_name(create_identity_name_opening())
                .await
                .require_interactive("IDENTITY")?;
            state.target = Some(IdentityTarget::parse(&identity)?);
            state.target_opening_required = false;
            continue;
        }

        let target = state
            .target
            .clone()
            .whatever_context::<_, Error>("interactive create target is unavailable")?;

        if state.target_opening_required {
            let identity = prompt::prompt_identity_name_with_default(
                create_identity_name_opening(),
                Some(target.short_name()),
            )
            .await
            .require_interactive("IDENTITY")?;
            let parsed = IdentityTarget::parse(&identity)?;
            if parsed != target {
                state.target = Some(parsed);
                state.reset_after_target_change();
            }
            state.target_opening_required = false;
            continue;
        }

        if state.kind.is_none() || state.kind_prompt_required {
            state.kind = Some(
                prompt::prompt_kind_with_cursor(state.kind)
                    .await
                    .require_interactive("--kind")?
                    .parse::<IdentityKind>()?,
            );
            state.kind_prompt_required = false;
            continue;
        }

        let ready_parent_identity = resolve_ready_parent_identity(dhttp_home, &target).await?;
        let parent_candidate = resolve_parent_candidate(dhttp_home, &target).await?;
        if state.approval_plan.is_none() {
            if let Some(auth) = command.auth {
                state.approval_plan = Some(resolve_non_interactive_approval_plan(
                    &target,
                    Some(auth),
                    ready_parent_identity.as_ref().map(|name| name.as_full()),
                )?);
                continue;
            }

            match target.level() {
                IdentityLevel::Identity => {
                    state.approval_plan = Some(CreateApprovalPlan {
                        parent_identity: None,
                        auth: AuthMethod::Email,
                        helper_action: None,
                    });
                }
                IdentityLevel::SubIdentity => {
                    let parent_identity = target
                        .parent()
                        .whatever_context::<_, Error>(
                            "sub-identity target is missing its parent identity",
                        )?
                        .into_owned();
                    let options = build_create_approval_options(parent_candidate.clone());
                    let mut labels = options
                        .iter()
                        .map(approval::ApprovalMenuOption::label)
                        .collect::<Vec<_>>();
                    labels.push(prompt::MORE_OPTIONS_LABEL.to_string());
                    let message = format!("Choose how to verify creating {}:", target.short_name());
                    let selected = prompt::prompt_select_string(&message, labels)
                        .await
                        .require_interactive("--auth")?;
                    if selected == prompt::MORE_OPTIONS_LABEL {
                        match prompt_create_approval_menu_action().await? {
                            CreateApprovalMenuAction::ChangeCertificateKind => {
                                state.revisit_kind_prompt();
                            }
                            CreateApprovalMenuAction::ChangeIdentityName => {
                                state.revisit_target_prompt();
                            }
                        }
                    } else {
                        state.approval_plan = Some(create_plan_from_selection(
                            &options,
                            &selected,
                            Some(parent_identity.as_full()),
                        )?);
                    }
                }
            }
            continue;
        }

        let approval_plan = state
            .approval_plan
            .clone()
            .whatever_context::<_, Error>("interactive create approval plan is unavailable")?;
        if let Some(action) = approval_plan.helper_action.clone() {
            let parent_identity = approval_plan
                .parent_identity
                .as_deref()
                .whatever_context::<_, Error>("helper apply path is missing its parent identity")?;
            if !run_helper_parent_action(dhttp_home, cert_server, &target, parent_identity, action)
                .await?
            {
                state.approval_plan = None;
                state.reset_after_approval_change();
                continue;
            }
            state.approval_plan = Some(CreateApprovalPlan {
                parent_identity: Some(parent_identity.to_string()),
                auth: AuthMethod::Identity,
                helper_action: None,
            });
            continue;
        }

        if matches!(approval_plan.auth, AuthMethod::Email)
            && (state.email.is_none() || state.email_prompt_required)
        {
            match prompt::prompt_email_with_more_options(state.email.as_deref())
                .await
                .require_interactive("--email")?
            {
                prompt::TextPromptResult::Submitted(email) => {
                    state.email = Some(email);
                    state.email_prompt_required = false;
                }
                prompt::TextPromptResult::MoreOptions => {
                    match prompt_create_email_action(can_switch_verification_method(&target))
                        .await?
                    {
                        CreateEmailAction::SwitchVerificationMethod => {
                            state.approval_plan = None;
                            state.reset_after_approval_change();
                        }
                        CreateEmailAction::ChangeCertificateKind => {
                            state.revisit_kind_prompt();
                        }
                        CreateEmailAction::ChangeIdentityName => {
                            state.revisit_target_prompt();
                        }
                    }
                }
            }
            continue;
        }

        if matches!(approval_plan.auth, AuthMethod::Email) && state.verify_code.is_none() {
            let email = state
                .email
                .clone()
                .whatever_context::<_, Error>("interactive create email is unavailable")?;
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
            match prompt::prompt_verify_code_with_more_options(None)
                .await
                .require_interactive("--verify-code")?
            {
                prompt::TextPromptResult::Submitted(code) => {
                    state.verify_code = Some(code);
                }
                prompt::TextPromptResult::MoreOptions => {
                    match prompt_create_verify_code_action(None).await? {
                        CreateVerifyCodeAction::ResendVerificationCode => {
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
                        CreateVerifyCodeAction::ChangeEmail => {
                            state.revisit_email_prompt();
                        }
                        CreateVerifyCodeAction::SwitchVerificationMethod => {
                            state.approval_plan = None;
                            state.reset_after_approval_change();
                        }
                        CreateVerifyCodeAction::ChangeCertificateKind => {
                            state.revisit_kind_prompt();
                        }
                        CreateVerifyCodeAction::ChangeIdentityName => {
                            state.revisit_target_prompt();
                        }
                        CreateVerifyCodeAction::ReturnToCreate { .. } => {
                            state.approval_plan = None;
                            state.reset_after_approval_change();
                        }
                    }
                }
            }
            continue;
        }

        cli::ensure_replace_local_allowed(dhttp_home, target.dhttp_name(), command.replace_local)
            .await?;
        let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&target.dhttp_name())?;
        let kind = state
            .kind
            .whatever_context::<_, Error>("interactive create kind is unavailable")?;

        match target.level() {
            IdentityLevel::Identity => {
                let email = state
                    .email
                    .clone()
                    .whatever_context::<_, Error>("interactive create email is unavailable")?;
                let verify_code = state.verify_code.clone().whatever_context::<_, Error>(
                    "interactive create verification code is unavailable",
                )?;
                let created = match complete_root_identity_create_interactively(
                    cert_server,
                    &target,
                    &email,
                    &verify_code,
                )
                .await
                {
                    Ok(created) => created,
                    Err(CompleteRootIdentityCreateInteractivelyError::Verification { source }) => {
                        let recovery =
                            crate::cli::flow::recovery::classify_verify_submit_error(&source);
                        if matches!(
                            recovery,
                            crate::cli::flow::recovery::VerificationRecovery::StayCurrentStep { .. }
                        ) {
                            state.verify_code = None;
                        }
                        if apply_verification_recovery(&mut state, &recovery) {
                            continue;
                        }
                        return Err(Error::from(source));
                    }
                    Err(CompleteRootIdentityCreateInteractivelyError::Flow { source }) => {
                        return Err(source);
                    }
                };
                let access_token = if let Some(auth) = created.auth {
                    auth.access_token
                } else {
                    match super::progress::run_with_spinner(
                        "Verifying with email...",
                        cert_server.login(&email, &verify_code),
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
                    }
                };
                let cert = super::progress::run_with_spinner(
                    "Applying identity...",
                    cert_server.issue_cert(
                        &access_token,
                        target.full_name(),
                        kind.as_str(),
                        None,
                        &super::device::resolve_device_name(command.device_name.as_deref()),
                        &csr_pem,
                    ),
                )
                .await?;
                cli::save_identity(
                    dhttp_home,
                    &target.dhttp_name(),
                    key_pem.as_bytes(),
                    cert.cert_pem.as_bytes(),
                )
                .instrument(info_span!("save_identity"))
                .await?;
            }
            IdentityLevel::SubIdentity => {
                let parent = target
                    .parent()
                    .whatever_context::<_, Error>(
                        "sub-identity target is missing its parent identity",
                    )?
                    .into_owned();
                let label = target.sub_identity_label().whatever_context::<_, Error>(
                    "sub-identity target is missing its direct child label",
                )?;
                match approval_plan.auth {
                    AuthMethod::Email => {
                        let email = state.email.clone().whatever_context::<_, Error>(
                            "interactive create email is unavailable",
                        )?;
                        let verify_code = state.verify_code.clone().whatever_context::<_, Error>(
                            "interactive create verification code is unavailable",
                        )?;
                        let access_token = match super::progress::run_with_spinner(
                            "Verifying with email...",
                            cert_server.login(&email, &verify_code),
                        )
                        .await
                        {
                            Ok(login) => login.access_token,
                            Err(error) => {
                                let recovery =
                                    crate::cli::flow::recovery::classify_verify_submit_error(
                                        &error,
                                    );
                                if matches!(
                                    recovery,
                                    crate::cli::flow::recovery::VerificationRecovery::StayCurrentStep {
                                        ..
                                    }
                                ) {
                                    state.verify_code = None;
                                }
                                if apply_verification_recovery(&mut state, &recovery) {
                                    continue;
                                }
                                return Err(Error::from(error));
                            }
                        };
                        create_sub_identity_with_email_interactively(
                            cert_server,
                            &target,
                            &access_token,
                            &parent,
                            label,
                        )
                        .await?;
                        let cert = super::progress::run_with_spinner(
                            "Applying identity...",
                            cert_server.issue_cert(
                                &access_token,
                                target.full_name(),
                                kind.as_str(),
                                None,
                                &super::device::resolve_device_name(command.device_name.as_deref()),
                                &csr_pem,
                            ),
                        )
                        .await?;
                        cli::save_identity(
                            dhttp_home,
                            &target.dhttp_name(),
                            key_pem.as_bytes(),
                            cert.cert_pem.as_bytes(),
                        )
                        .instrument(info_span!("save_identity"))
                        .await?;
                    }
                    AuthMethod::Identity => {
                        let ready_parent =
                            match ensure_parent_identity_ready(dhttp_home, &target).await {
                                Ok(parent) => parent,
                                Err(error) => {
                                    let rendered = error.to_string();
                                    if rendered.contains("ready local parent identity") {
                                        state.approval_plan = None;
                                        state.reset_after_approval_change();
                                        continue;
                                    }
                                    return Err(error);
                                }
                            };
                        match super::progress::run_with_spinner(
                            "Creating sub-identity...",
                            cert_server.create_subdomain_with_identity(
                                ready_parent.as_full(),
                                parent.as_full(),
                                label,
                                None,
                            ),
                        )
                        .await
                        {
                            Ok(_) => {}
                            Err(error) => {
                                let rendered = error.to_string();
                                if rendered.contains("subdomain quota exceeded") {
                                    crate::cli::flow::transcript::print_block(&format!(
                                        "Creating {} needs checkout to add one more sub-identity slot under {}.\nChoose email verification to continue with checkout.",
                                        target.short_name(),
                                        parent.as_partial(),
                                    ));
                                    state.approval_plan = None;
                                    state.reset_after_approval_change();
                                    continue;
                                }
                                return Err(Error::from(error));
                            }
                        }
                        let cert = super::progress::run_with_spinner(
                            "Verifying with local identity...",
                            cert_server.issue_cert_with_identity(
                                ready_parent.as_full(),
                                target.full_name(),
                                kind.as_str(),
                                None,
                                &super::device::resolve_device_name(command.device_name.as_deref()),
                                &csr_pem,
                            ),
                        )
                        .await?;
                        cli::save_identity(
                            dhttp_home,
                            &target.dhttp_name(),
                            key_pem.as_bytes(),
                            cert.cert_pem.as_bytes(),
                        )
                        .instrument(info_span!("save_identity"))
                        .await?;
                    }
                }
            }
        }

        crate::cli::flow::epilogue::run_lifecycle_epilogue(
            dhttp_home,
            target.dhttp_name(),
            default_identity_when_command_started.clone(),
            std::io::stdin().is_terminal(),
        )
        .await?;
        return Ok(());
    }
}

pub(crate) async fn run(
    command: &Create,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    let is_interactive = std::io::stdin().is_terminal();
    if is_interactive && !command.send_code {
        return run_interactive(command, dhttp_home, cert_server).await;
    }
    let default_identity_when_command_started = cli::load_current_settings(dhttp_home)
        .await?
        .and_then(|config| config.settings().default_identity_name().cloned());
    let target = resolve_target(command).await?;
    let kind = resolve_kind(command).await?;
    let ready_parent_identity = resolve_ready_parent_identity(dhttp_home, &target).await?;
    let approval_plan = resolve_approval_plan(
        &target,
        command.auth,
        ready_parent_identity.as_ref().map(|name| name.as_full()),
        is_interactive,
    )
    .await?;
    let device_name = super::device::resolve_device_name(command.device_name.as_deref());

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

    if let Some(action) = approval_plan.helper_action.clone() {
        let parent_identity = approval_plan
            .parent_identity
            .as_deref()
            .whatever_context::<_, Error>("helper apply path is missing its parent identity")?;
        if !run_helper_parent_action(dhttp_home, cert_server, &target, parent_identity, action)
            .await?
        {
            whatever!("create was cancelled");
        }
    }

    cli::ensure_replace_local_allowed(dhttp_home, target.dhttp_name(), command.replace_local)
        .await?;
    let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&target.dhttp_name())?;

    match target.level() {
        IdentityLevel::Identity => {
            let email = resolve_email(command).await?;
            let verify_code =
                resolve_verify_code(cert_server, &email, command.verify_code.clone()).await?;
            let created = super::progress::run_with_spinner(
                "Creating identity...",
                cert_server.create_domain_with_email(target.full_name(), &email, &verify_code),
            )
            .await?;

            if let Some(payment_entry) = created.payment_entry.as_ref() {
                if !is_interactive {
                    ensure_non_interactive_root_checkout_not_required(&target, &created)?;
                }
                crate::checkout::print_payment_instructions(&created);
                let completed = crate::checkout::wait_for_checkout_completion(
                    cert_server,
                    &payment_entry.checkout_token,
                )
                .await?;
                match crate::checkout::classify_checkout(&completed) {
                    crate::checkout::CheckoutState::Completed => {}
                    crate::checkout::CheckoutState::Expired => {
                        whatever!("checkout expired before payment completed")
                    }
                    crate::checkout::CheckoutState::Cancelled => {
                        whatever!("checkout was cancelled")
                    }
                    crate::checkout::CheckoutState::Pending => {
                        whatever!("checkout did not reach a terminal state")
                    }
                }
            }

            let access_token = if let Some(auth) = created.auth {
                auth.access_token
            } else {
                super::progress::run_with_spinner(
                    "Verifying with email...",
                    cert_server.login(&email, &verify_code),
                )
                .await?
                .access_token
            };
            let cert = super::progress::run_with_spinner(
                "Applying identity...",
                cert_server.issue_cert(
                    &access_token,
                    target.full_name(),
                    kind.as_str(),
                    None,
                    &device_name,
                    &csr_pem,
                ),
            )
            .await?;
            cli::save_identity(
                dhttp_home,
                &target.dhttp_name(),
                key_pem.as_bytes(),
                cert.cert_pem.as_bytes(),
            )
            .instrument(info_span!("save_identity"))
            .await?;
        }
        IdentityLevel::SubIdentity => {
            let parent = target
                .parent()
                .whatever_context::<_, Error>("sub-identity target is missing its parent identity")?
                .into_owned();
            let label = target.sub_identity_label().whatever_context::<_, Error>(
                "sub-identity target is missing its direct child label",
            )?;
            match approval_plan.auth {
                AuthMethod::Email => {
                    let email = resolve_email(command).await?;
                    let verify_code =
                        resolve_verify_code(cert_server, &email, command.verify_code.clone())
                            .await?;
                    let access_token = super::progress::run_with_spinner(
                        "Verifying with email...",
                        cert_server.login(&email, &verify_code),
                    )
                    .await?
                    .access_token;
                    let created = super::progress::run_with_spinner(
                        "Creating sub-identity...",
                        cert_server.create_subdomain(&access_token, parent.as_full(), label, None),
                    )
                    .await?;
                    ensure_non_interactive_sub_identity_checkout_not_required(&target, &created)?;
                    let cert = super::progress::run_with_spinner(
                        "Applying identity...",
                        cert_server.issue_cert(
                            &access_token,
                            target.full_name(),
                            kind.as_str(),
                            None,
                            &device_name,
                            &csr_pem,
                        ),
                    )
                    .await?;
                    cli::save_identity(
                        dhttp_home,
                        &target.dhttp_name(),
                        key_pem.as_bytes(),
                        cert.cert_pem.as_bytes(),
                    )
                    .instrument(info_span!("save_identity"))
                    .await?;
                }
                AuthMethod::Identity => {
                    let ready_parent = ensure_parent_identity_ready(dhttp_home, &target).await?;
                    let created = super::progress::run_with_spinner(
                        "Creating sub-identity...",
                        cert_server.create_subdomain_with_identity(
                            ready_parent.as_full(),
                            parent.as_full(),
                            label,
                            None,
                        ),
                    )
                    .await?;
                    ensure_non_interactive_sub_identity_checkout_not_required(&target, &created)?;
                    let cert = super::progress::run_with_spinner(
                        "Verifying with local identity...",
                        cert_server.issue_cert_with_identity(
                            ready_parent.as_full(),
                            target.full_name(),
                            kind.as_str(),
                            None,
                            &device_name,
                            &csr_pem,
                        ),
                    )
                    .await?;
                    cli::save_identity(
                        dhttp_home,
                        &target.dhttp_name(),
                        key_pem.as_bytes(),
                        cert.cert_pem.as_bytes(),
                    )
                    .instrument(info_span!("save_identity"))
                    .await?;
                }
            }
        }
    }

    crate::cli::flow::epilogue::run_lifecycle_epilogue(
        dhttp_home,
        target.dhttp_name(),
        default_identity_when_command_started,
        is_interactive,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        CreateApprovalPlan, CreateEmailAction, CreateVerifyCodeAction, InteractiveCreateState,
        build_create_approval_options, create_email_actions, create_verify_code_actions,
        ensure_non_interactive_root_checkout_not_required,
        ensure_non_interactive_sub_identity_checkout_not_required,
        resolve_non_interactive_approval_plan,
    };
    use crate::{
        auth::AuthMethod,
        cert_server::{CreateDomainResponse, CreateSubdomainResponse},
        cli::{
            Create,
            flow::{
                approval::{ApprovalMenuOption, LocalApprovalCandidate},
                target::IdentityTarget,
            },
        },
    };

    #[test]
    fn stay_recovery_keeps_create_verify_state() {
        let mut state = InteractiveCreateState::from_command(&Create {
            name: Some("alice.smith".to_string()),
            kind: Some("primary".to_string()),
            replace_local: false,
            device_name: None,
            email: Some("alice@example.test".to_string()),
            send_code: false,
            verify_code: None,
            auth: None,
        })
        .unwrap();
        state.verify_code = Some("123456".to_string());
        state.verification_code_sent_to = Some("alice@example.test".to_string());

        super::apply_verification_recovery(
            &mut state,
            &crate::cli::flow::recovery::VerificationRecovery::StayCurrentStep {
                message: "retry later",
            },
        );

        assert_eq!(state.verify_code.as_deref(), Some("123456"));
        assert_eq!(
            state.verification_code_sent_to.as_deref(),
            Some("alice@example.test")
        );
    }

    #[test]
    fn back_to_email_recovery_reopens_email_prompt() {
        let mut state = InteractiveCreateState::from_command(&Create {
            name: Some("alice.smith".to_string()),
            kind: Some("primary".to_string()),
            replace_local: false,
            device_name: None,
            email: Some("alice@example.test".to_string()),
            send_code: false,
            verify_code: None,
            auth: None,
        })
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
    fn root_identity_defaults_to_email_auth_non_interactively() {
        let target = IdentityTarget::parse("alice.smith").unwrap();
        assert_eq!(
            resolve_non_interactive_approval_plan(&target, None, None).unwrap(),
            CreateApprovalPlan {
                parent_identity: None,
                auth: AuthMethod::Email,
                helper_action: None,
            }
        );
    }

    #[test]
    fn root_identity_rejects_identity_auth() {
        let target = IdentityTarget::parse("alice.smith").unwrap();
        let error =
            resolve_non_interactive_approval_plan(&target, Some(AuthMethod::Identity), None)
                .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("email verification"), "{rendered}");
        assert!(rendered.contains("--auth identity"), "{rendered}");
    }

    #[test]
    fn sub_identity_with_ready_parent_requires_explicit_auth_non_interactively() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        let error =
            resolve_non_interactive_approval_plan(&target, None, Some("alice.smith")).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("--auth email"), "{rendered}");
        assert!(rendered.contains("--auth identity"), "{rendered}");
    }

    #[test]
    fn sub_identity_identity_auth_targets_parent_identity() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        assert_eq!(
            resolve_non_interactive_approval_plan(
                &target,
                Some(AuthMethod::Identity),
                Some("alice.smith"),
            )
            .unwrap(),
            CreateApprovalPlan {
                parent_identity: Some("alice.smith".to_string()),
                auth: AuthMethod::Identity,
                helper_action: None,
            }
        );
    }

    #[test]
    fn sub_identity_email_auth_is_allowed() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        assert_eq!(
            resolve_non_interactive_approval_plan(&target, Some(AuthMethod::Email), None).unwrap(),
            CreateApprovalPlan {
                parent_identity: Some("alice.smith".to_string()),
                auth: AuthMethod::Email,
                helper_action: None,
            }
        );
    }

    #[test]
    fn sub_identity_without_ready_parent_defaults_to_email_non_interactively() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        assert_eq!(
            resolve_non_interactive_approval_plan(&target, None, None).unwrap(),
            CreateApprovalPlan {
                parent_identity: Some("alice.smith".to_string()),
                auth: AuthMethod::Email,
                helper_action: None,
            }
        );
    }

    #[test]
    fn sub_identity_identity_auth_requires_ready_local_parent() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        let error =
            resolve_non_interactive_approval_plan(&target, Some(AuthMethod::Identity), None)
                .unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered.contains("ready local parent identity"),
            "{rendered}"
        );
        assert!(rendered.contains("phone.alice.smith"), "{rendered}");
    }

    #[test]
    fn completed_root_identity_create_does_not_require_interactive_checkout() {
        let target = IdentityTarget::parse("alice.smith").unwrap();
        let response: CreateDomainResponse = serde_json::from_str(
            r#"{"domain":"alice.smith.dhttp.net","quotes":{"currency":"USD","monthly":0,"yearly":0,"default_billing_cycle":"yearly"},"next_action":"completed"}"#,
        )
        .unwrap();

        ensure_non_interactive_root_checkout_not_required(&target, &response).unwrap();
    }

    #[test]
    fn payment_required_root_identity_create_requires_interactive_checkout() {
        let target = IdentityTarget::parse("alice.smith").unwrap();
        let response: CreateDomainResponse = serde_json::from_str(
            r#"{"domain":"alice.smith.dhttp.net","quotes":{"currency":"USD","monthly":9900,"yearly":99000,"default_billing_cycle":"yearly"},"next_action":"payment","payment_entry":{"url":"https://pay.example.com","checkout_token":"tok_123","expires_at":123456}}"#,
        )
        .unwrap();

        let error =
            ensure_non_interactive_root_checkout_not_required(&target, &response).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("interactive checkout"), "{rendered}");
        assert!(rendered.contains("alice.smith"), "{rendered}");
    }

    #[test]
    fn direct_sub_identity_create_does_not_require_interactive_checkout() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        let response: CreateSubdomainResponse = serde_json::from_str(
            r#"{"domain":"phone.alice.smith.dhttp.net","parent":"alice.smith.dhttp.net","status":"active","expires_at":1794305532,"cert":{"limit":1,"used":0},"url":"/v2/subdomain?parent=alice.smith.dhttp.net&domain=phone.alice.smith.dhttp.net","certs_url":"/v2/cert?domain=phone.alice.smith.dhttp.net","created_at":1794305532}"#,
        )
        .unwrap();

        ensure_non_interactive_sub_identity_checkout_not_required(&target, &response).unwrap();
    }

    #[test]
    fn quota_expansion_sub_identity_create_requires_interactive_checkout() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        let response: CreateSubdomainResponse = serde_json::from_str(
            r#"{"domain":"phone.alice.smith.dhttp.net","parent":"alice.smith.dhttp.net","status":"pending","expires_at":1794305532,"cert":{"limit":1,"used":0},"url":"/v2/subdomain?parent=alice.smith.dhttp.net&domain=phone.alice.smith.dhttp.net","certs_url":"/v2/cert?domain=phone.alice.smith.dhttp.net","created_at":1794305532,"invoice":{"number":"INV-123","amount":500,"currency":"USD"}}"#,
        )
        .unwrap();

        let error = ensure_non_interactive_sub_identity_checkout_not_required(&target, &response)
            .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("interactive checkout"), "{rendered}");
        assert!(rendered.contains("phone.alice.smith"), "{rendered}");
    }

    #[test]
    fn create_identity_name_opening_matches_spec_copy() {
        let opening = super::create_identity_name_opening();
        assert!(opening.contains("Create a new identity for this device."));
        assert!(opening.contains("<given_name>.<surname>"));
        assert!(opening.contains("alice.smith"));
        assert!(opening.contains("phone.alice.smith"));
    }

    #[test]
    fn create_subidentity_with_ready_parent_shows_local_before_email() {
        let options = build_create_approval_options(Some(LocalApprovalCandidate::ready(
            "alice.smith",
            "alice.smith.dhttp.net",
        )));

        assert_eq!(
            options
                .iter()
                .map(ApprovalMenuOption::label)
                .collect::<Vec<_>>(),
            vec![
                "Verify with alice.smith on local device".to_string(),
                "Verify with email".to_string(),
            ]
        );
    }

    #[test]
    fn create_subidentity_with_missing_parent_uses_apply_copy() {
        let options = build_create_approval_options(Some(LocalApprovalCandidate::missing(
            "alice.smith",
            "alice.smith.dhttp.net",
        )));

        assert_eq!(
            options
                .iter()
                .map(ApprovalMenuOption::label)
                .collect::<Vec<_>>(),
            vec![
                "Verify with email".to_string(),
                "Apply alice.smith to this device, then verify with alice.smith".to_string(),
            ]
        );
    }

    #[test]
    fn create_email_actions_use_explicit_return_point_copy() {
        assert_eq!(
            create_email_actions(true),
            vec![
                CreateEmailAction::SwitchVerificationMethod,
                CreateEmailAction::ChangeCertificateKind,
                CreateEmailAction::ChangeIdentityName,
            ]
        );
        assert_eq!(
            create_email_actions(true)
                .into_iter()
                .map(|action| action.label())
                .collect::<Vec<_>>(),
            vec![
                "Switch verification method (go back to verification method selection)".to_string(),
                "Change certificate kind (go back to identity kind)".to_string(),
                "Change identity name (go back to identity name)".to_string(),
            ]
        );
    }

    #[test]
    fn create_verify_code_actions_include_resend_and_explicit_return_points() {
        assert_eq!(
            create_verify_code_actions(Some("phone.alice.smith")),
            vec![
                CreateVerifyCodeAction::ResendVerificationCode,
                CreateVerifyCodeAction::ChangeEmail,
                CreateVerifyCodeAction::SwitchVerificationMethod,
                CreateVerifyCodeAction::ChangeCertificateKind,
                CreateVerifyCodeAction::ChangeIdentityName,
                CreateVerifyCodeAction::ReturnToCreate {
                    target_name: "phone.alice.smith".to_string(),
                },
            ]
        );
        assert_eq!(
            create_verify_code_actions(Some("phone.alice.smith"))
                .into_iter()
                .map(|action| action.label())
                .collect::<Vec<_>>(),
            vec![
                "Resend verification code".to_string(),
                "Send code to another email (go back to email)".to_string(),
                "Switch verification method (go back to verification method selection)".to_string(),
                "Change certificate kind (go back to identity kind)".to_string(),
                "Change identity name (go back to identity name)".to_string(),
                "Return to create phone.alice.smith".to_string(),
            ]
        );
    }
}
