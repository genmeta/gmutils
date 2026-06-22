use std::io::IsTerminal;

use dhttp::home::DhttpHome;
use snafu::{OptionExt, whatever};
use tracing::{Instrument, info_span};

use super::{
    approval,
    local::{self, InteractiveInventoryChoice},
};
use crate::{
    auth::AuthMethod,
    cert_server::CertServer,
    cli::{self, Error, Renew, prompt::InquireResultExt},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum RenewApprovalPlan {
    Email,
    Identity,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum RenewApprovalMenuAction {
    ChangeIdentitySelection,
}

impl RenewApprovalMenuAction {
    fn label(&self) -> String {
        match self {
            Self::ChangeIdentitySelection => {
                "Change identity (go back to identity selection)".to_string()
            }
        }
    }
}

fn renew_approval_menu_actions() -> Vec<RenewApprovalMenuAction> {
    vec![RenewApprovalMenuAction::ChangeIdentitySelection]
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

fn build_renew_approval_options(target: &str) -> Vec<approval::ApprovalMenuOption> {
    approval::build_approval_options(approval::ApprovalMenuSpec {
        email_label: "Verify with email".to_string(),
        direct_local: vec![approval::ApprovalDirectLocal::new(target, target)],
        helpers: Vec::new(),
    })
}

fn renew_verification_options(target: &str) -> Vec<(String, RenewApprovalPlan)> {
    build_renew_approval_options(target)
        .into_iter()
        .filter_map(|option| match option {
            approval::ApprovalMenuOption::Email { label } => {
                Some((label, RenewApprovalPlan::Email))
            }
            approval::ApprovalMenuOption::DirectLocal(local) => Some((
                format!("Verify with {} on local device", local.short_name),
                RenewApprovalPlan::Identity,
            )),
            approval::ApprovalMenuOption::Helper(_) => None,
        })
        .collect()
}

fn approval_plan_from_selection(
    options: &[(String, RenewApprovalPlan)],
    selected: &str,
) -> Result<RenewApprovalPlan, Error> {
    options
        .iter()
        .find_map(|(label, plan)| (label == selected).then_some(plan.clone()))
        .whatever_context::<_, Error>("selected approval path is unavailable")
}

fn resolve_non_interactive_approval_plan(
    target: &str,
    requested_auth: Option<AuthMethod>,
) -> Result<RenewApprovalPlan, Error> {
    match requested_auth {
        Some(AuthMethod::Email) => Ok(RenewApprovalPlan::Email),
        Some(AuthMethod::Identity) => Ok(RenewApprovalPlan::Identity),
        None => whatever!(
            "renewing {} non-interactively requires choosing an approval path; rerun with --auth email or --auth identity",
            target
        ),
    }
}

async fn resolve_approval_plan(
    target: &str,
    requested_auth: Option<AuthMethod>,
    is_interactive: bool,
) -> Result<RenewApprovalPlan, Error> {
    if !is_interactive {
        return resolve_non_interactive_approval_plan(target, requested_auth);
    }

    match requested_auth {
        Some(auth) => resolve_non_interactive_approval_plan(target, Some(auth)),
        None => {
            let options = renew_verification_options(target);
            let labels = options
                .iter()
                .map(|(label, _)| label.clone())
                .collect::<Vec<_>>();
            let message = format!("Choose how to verify renewing {target}:");
            let selected = crate::cli::prompt::prompt_select_string(&message, labels)
                .await
                .require_interactive("--auth")?;
            approval_plan_from_selection(&options, &selected)
        }
    }
}

async fn resolve_target(
    command: &Renew,
    dhttp_home: &DhttpHome,
) -> Result<dhttp::name::DhttpName<'static>, Error> {
    if command.use_default {
        return cli::resolve_default_target_name(dhttp_home).await;
    }

    match command.name.as_deref() {
        Some(name) => cli::parse_identity_name(name),
        None => {
            let default_name = cli::load_current_settings(dhttp_home)
                .await?
                .and_then(|config| config.settings().default_identity_name().cloned());
            let inventory =
                local::load_inventory(dhttp_home, default_name.as_ref().map(|name| name.borrow()))
                    .await?;
            let choices = local::build_renew_inventory_choices(&inventory);
            if choices.is_empty() {
                whatever!("No identities found here. Renew requires an identity saved here.");
            }
            let labels: Vec<String> = choices
                .iter()
                .map(|choice| {
                    super::output::render_choice_label(choice, std::io::stdout().is_terminal())
                })
                .collect();
            let selected = crate::cli::prompt::prompt_select_string(
                "Select an identity to renew here:",
                labels.clone(),
            )
            .await
            .require_interactive("IDENTITY")?;
            let choice = choices
                .into_iter()
                .zip(labels)
                .find_map(|(choice, label)| (label == selected).then_some(choice))
                .whatever_context::<_, Error>("selected identity choice is unavailable")?;
            match choice {
                InteractiveInventoryChoice::Saved(summary) => Ok(summary.target.into_dhttp_name()),
                InteractiveInventoryChoice::Organization { .. } => {
                    whatever!("renew requires an identity already saved here")
                }
            }
        }
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

async fn prompt_renew_approval_menu_action() -> Result<RenewApprovalMenuAction, Error> {
    let actions = renew_approval_menu_actions();
    let labels = actions
        .iter()
        .map(RenewApprovalMenuAction::label)
        .collect::<Vec<_>>();
    let selected = crate::cli::prompt::prompt_select_string("More options:", labels.clone())
        .await
        .require_interactive("interactive input")?;
    actions
        .into_iter()
        .zip(labels)
        .find_map(|(action, label)| (label == selected).then_some(action))
        .whatever_context::<_, Error>("selected renew approval action is unavailable")
}

async fn run_interactive(
    command: &Renew,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    let initial_target = if command.use_default {
        Some(cli::resolve_default_target_name(dhttp_home).await?)
    } else {
        command
            .name
            .as_deref()
            .map(cli::parse_identity_name)
            .transpose()?
    };
    let mut state = InteractiveRenewState::from_command(command, initial_target);

    loop {
        if state.target.is_none() {
            let default_name = cli::load_current_settings(dhttp_home)
                .await?
                .and_then(|config| config.settings().default_identity_name().cloned());
            let inventory =
                local::load_inventory(dhttp_home, default_name.as_ref().map(|name| name.borrow()))
                    .await?;
            let choices = local::build_renew_inventory_choices(&inventory);
            if choices.is_empty() {
                whatever!("No identities found here. Renew requires an identity saved here.");
            }
            let labels: Vec<String> = choices
                .iter()
                .map(|choice| {
                    super::output::render_choice_label(choice, std::io::stdout().is_terminal())
                })
                .collect();
            let selected = crate::cli::prompt::prompt_select_string(
                "Select an identity to renew here:",
                labels.clone(),
            )
            .await
            .require_interactive("IDENTITY")?;
            let choice = choices
                .into_iter()
                .zip(labels)
                .find_map(|(choice, label)| (label == selected).then_some(choice))
                .whatever_context::<_, Error>("selected identity choice is unavailable")?;
            match choice {
                InteractiveInventoryChoice::Saved(summary) => {
                    state.target = Some(summary.target.into_dhttp_name());
                }
                InteractiveInventoryChoice::Organization { target } => {
                    crate::cli::flow::transcript::print_block(&renew_not_saved_root_message(
                        target.short_name(),
                    ));
                    state.revisit_target_selection();
                }
            }
            continue;
        }

        let domain = state
            .target
            .clone()
            .whatever_context::<_, Error>("interactive renew target is unavailable")?;
        ensure_saved_renew_target(dhttp_home, domain.borrow()).await?;

        if state.approval_plan.is_none() {
            if let Some(auth) = command.auth {
                state.approval_plan = Some(resolve_non_interactive_approval_plan(
                    domain.as_partial(),
                    Some(auth),
                )?);
                continue;
            }

            let options = renew_verification_options(domain.as_partial());
            let mut labels = options
                .iter()
                .map(|(label, _)| label.clone())
                .collect::<Vec<_>>();
            labels.push(crate::cli::prompt::MORE_OPTIONS_LABEL.to_string());
            let message = format!("Choose how to verify renewing {}:", domain.as_partial());
            let selected = crate::cli::prompt::prompt_select_string(&message, labels)
                .await
                .require_interactive("--auth")?;
            if selected == crate::cli::prompt::MORE_OPTIONS_LABEL {
                match prompt_renew_approval_menu_action().await? {
                    RenewApprovalMenuAction::ChangeIdentitySelection => {
                        state.revisit_target_selection();
                    }
                }
            } else {
                state.approval_plan = Some(approval_plan_from_selection(&options, &selected)?);
            }
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
        let device_name = super::device::resolve_device_name(command.device_name.as_deref());
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
            RenewApprovalPlan::Identity => {
                super::progress::run_with_spinner(
                    "Renewing identity...",
                    cert_server.renew_cert_with_identity(
                        domain.as_full(),
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
        .instrument(info_span!("save_identity"))
        .await?;
        return crate::cli::flow::epilogue::run_local_epilogue(dhttp_home, domain.borrow()).await;
    }
}

pub(crate) async fn run_helper_for_verification(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    short_name: &str,
    _return_to: &str,
) -> Result<bool, Error> {
    let command = Renew {
        name: Some(short_name.to_string()),
        use_default: false,
        device_name: None,
        email: None,
        send_code: false,
        verify_code: None,
        auth: None,
    };
    run(&command, dhttp_home, cert_server).await?;
    Ok(true)
}

pub(crate) async fn run(
    command: &Renew,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    let is_interactive = std::io::stdin().is_terminal();
    if is_interactive && !command.send_code {
        return run_interactive(command, dhttp_home, cert_server).await;
    }
    let domain = resolve_target(command, dhttp_home).await?;
    ensure_saved_renew_target(dhttp_home, domain.borrow()).await?;
    let approval_plan =
        resolve_approval_plan(domain.as_partial(), command.auth, is_interactive).await?;
    let identity_profile = dhttp_home.resolve_identity_profile(domain.borrow()).await?;
    let local_identity = identity_profile.load_identity().await?;
    let chain_key = cli::certificate_chain_key_from_identity(&local_identity)?
        .whatever_context::<_, Error>("local identity does not expose a certificate chain")?;
    let kind = chain_key.kind().as_str();
    let sequence = chain_key.sequence().get();
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
        RenewApprovalPlan::Identity => {
            super::progress::run_with_spinner(
                "Renewing identity...",
                cert_server.renew_cert_with_identity(
                    domain.as_full(),
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
    crate::cli::flow::epilogue::run_local_epilogue(dhttp_home, domain.borrow()).await
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use dhttp::home::DhttpHome;

    use super::{
        InteractiveRenewState, RenewApprovalMenuAction, RenewApprovalPlan, RenewEmailAction,
        RenewVerifyCodeAction, approval_plan_from_selection, build_renew_approval_options,
        renew_approval_menu_actions, renew_email_actions, renew_not_saved_root_message,
        renew_verification_options, renew_verify_code_actions,
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
                use_default: false,
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
                message: "retry later",
            },
        );

        assert_eq!(state.verify_code.as_deref(), Some("123456"));
    }

    #[test]
    fn back_to_email_recovery_reopens_renew_email_prompt() {
        let mut state = InteractiveRenewState::from_command(
            &Renew {
                name: Some("alice.smith".to_string()),
                use_default: false,
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
                message: "start over",
            },
        );

        assert!(state.email_prompt_required);
        assert!(state.verify_code.is_none());
    }

    #[test]
    fn renew_requires_explicit_auth_non_interactively() {
        let error = resolve_non_interactive_approval_plan("alice.smith", None).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("--auth email"), "{rendered}");
        assert!(rendered.contains("--auth identity"), "{rendered}");
    }

    #[test]
    fn renew_identity_auth_is_allowed() {
        assert_eq!(
            resolve_non_interactive_approval_plan("alice.smith", Some(AuthMethod::Identity))
                .unwrap(),
            RenewApprovalPlan::Identity,
        );
    }

    #[test]
    fn renew_email_auth_is_allowed() {
        assert_eq!(
            resolve_non_interactive_approval_plan("alice.smith", Some(AuthMethod::Email)).unwrap(),
            RenewApprovalPlan::Email,
        );
    }

    #[test]
    fn interactive_renew_selection_can_choose_email() {
        let options = renew_verification_options("alice.smith");

        assert_eq!(
            approval_plan_from_selection(&options, "Verify with email").unwrap(),
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
            use_default: false,
            device_name: None,
            email: None,
            send_code: false,
            verify_code: None,
            auth: None,
        };

        let error = super::run(&command, &dhttp_home, &dummy_cert_server())
            .await
            .unwrap_err();
        let rendered = error.to_string();

        assert!(
            rendered.contains("Apply alice.smith here first"),
            "{rendered}"
        );
    }

    #[test]
    fn renew_verification_options_place_local_before_email() {
        let options = build_renew_approval_options("alice.ma");

        assert_eq!(
            options
                .iter()
                .map(crate::cli::flow::approval::ApprovalMenuOption::label)
                .collect::<Vec<_>>(),
            vec![
                "Verify with alice.ma on local device".to_string(),
                "Verify with email".to_string(),
            ]
        );
    }

    #[test]
    fn interactive_renew_selection_can_choose_local_identity() {
        let options = renew_verification_options("alice.smith");

        assert_eq!(
            approval_plan_from_selection(&options, "Verify with alice.smith on local device",)
                .unwrap(),
            RenewApprovalPlan::Identity,
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

    #[test]
    fn renew_approval_menu_actions_include_explicit_return_points() {
        assert_eq!(
            renew_approval_menu_actions()
                .into_iter()
                .map(|action| action.label())
                .collect::<Vec<_>>(),
            vec!["Change identity (go back to identity selection)".to_string(),]
        );
        assert_eq!(
            renew_approval_menu_actions(),
            vec![RenewApprovalMenuAction::ChangeIdentitySelection,]
        );
    }
}
