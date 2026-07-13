use std::io::IsTerminal;

use dhttp::home::{DhttpHome, HomeScope};
use snafu::{FromString, OptionExt, whatever};

use super::{
    auth_plan::CandidateEvent,
    kind::IdentityKind,
    target::{
        IdentityLevel, IdentityTarget, RemoteTargetState, ReplacementRequirement,
        ResolvedApplyTarget, remote_state_from_availability, replacement_requirement,
    },
};
use crate::{
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
    command.verify_code.is_some()
}

fn missing_root_target_error(target: &IdentityTarget) -> Error {
    debug_assert_eq!(target.level(), IdentityLevel::Identity);
    Error::without_source(format!(
        "{} does not exist yet. Apply can register a missing sub-identity, but not a new root identity.",
        target.short_name()
    ))
}

#[derive(Debug, Clone)]
struct InteractiveApplyState {
    target: Option<dhttp::name::DhttpName<'static>>,
    kind: Option<IdentityKind>,
    kind_prompt_required: bool,
    approval_plan: Option<ApplyApprovalPlan>,
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
        })
    }

    fn fall_back_to_email(&mut self) {
        self.approval_plan = Some(ApplyApprovalPlan::Email);
    }
}

fn is_domain_not_found(error: &crate::cert_server::Error) -> bool {
    matches!(
        crate::auth::classify_identity_attempt(error),
        crate::auth::AuthAttemptDisposition::ReplanMissingTarget
    )
}

fn is_subdomain_quota_exceeded(error: &crate::cert_server::Error) -> bool {
    super::registration::is_subdomain_quota_exceeded(error)
}

fn preserve_apply_registration_error(error: Error) -> Error {
    error
}

fn approval_plan_from_candidate(candidate: CandidateEvent) -> Result<ApplyApprovalPlan, Error> {
    match candidate {
        CandidateEvent::Identity { full_name, .. } => Ok(ApplyApprovalPlan::DirectIdentity {
            auth_domain: full_name,
        }),
        CandidateEvent::Email => Ok(ApplyApprovalPlan::Email),
        CandidateEvent::Warning(_) => {
            unreachable!("first_auth_candidate consumes warnings")
        }
        CandidateEvent::Exhausted => {
            whatever!("no authentication candidate is available")
        }
    }
}

fn apply_identity_name_opening() -> &'static str {
    "Applying identity, generating ECC key pair locally, then requesting and deploying certificate."
}

fn interactive_name_unavailable_message() -> &'static str {
    "Sorry, this name is not available. Please try another one."
}

fn explicit_target_from_command(command: &Apply) -> Result<Option<IdentityTarget>, Error> {
    command
        .name
        .as_deref()
        .map(IdentityTarget::parse)
        .transpose()
        .map_err(Error::from)
}

async fn prompt_apply_target() -> Result<IdentityTarget, Error> {
    let identity = crate::cli::prompt::prompt_identity_name("")
        .await
        .require_interactive("IDENTITY")?;
    Ok(IdentityTarget::parse(&identity)?)
}

async fn prompt_apply_target_with_online_validation(
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<ResolvedApplyTarget, Error> {
    loop {
        let target = prompt_apply_target().await?;
        let inspected = super::progress::run(super::progress::CHECK_NAME, async {
            let local =
                super::local::try_load_summary_exact(dhttp_home, target.dhttp_name(), None).await?;
            let remote = cert_server
                .inspect_domain_availability(target.full_name())
                .await?;
            Ok::<_, Error>((local, remote))
        })
        .await;
        let (local, response) = match inspected {
            Ok(inspected) => inspected,
            Err(Error::CertServer { source }) if source.is_api_code("domain_invalid") => {
                crate::cli::flow::transcript::print_err_block(
                    interactive_name_unavailable_message(),
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        let remote = remote_state_from_availability(&response.availability)
            .map_err(|error| Error::without_source(error.to_string()))?;
        match remote {
            RemoteTargetState::Exists | RemoteTargetState::Missing => {
                return Ok(ResolvedApplyTarget {
                    target,
                    remote,
                    local,
                });
            }
            RemoteTargetState::Unavailable => {
                crate::cli::flow::transcript::print_err_block(
                    interactive_name_unavailable_message(),
                );
            }
            RemoteTargetState::Unknown => unreachable!("pricing inspection returns known state"),
        }
    }
}

async fn resolve_apply_target(
    command: &Apply,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    interactive: bool,
) -> Result<ResolvedApplyTarget, Error> {
    match explicit_target_from_command(command)? {
        Some(target) => {
            let local = super::progress::run(
                super::progress::CHECK_NAME,
                super::local::try_load_summary_exact(dhttp_home, target.dhttp_name(), None),
            )
            .await?;
            Ok(ResolvedApplyTarget {
                target,
                remote: RemoteTargetState::Unknown,
                local,
            })
        }
        None if interactive => {
            prompt_apply_target_with_online_validation(dhttp_home, cert_server).await
        }
        None => Err(crate::cli::prompt::Error::NotInteractive {
            hint: "IDENTITY".into(),
        }
        .into()),
    }
}

async fn authorize_local_replacement(
    resolved: &ResolvedApplyTarget,
    force: bool,
    interactive: bool,
) -> Result<cli::LocalIdentitySave, Error> {
    let save = if resolved.local.is_some() {
        cli::LocalIdentitySave::Replace
    } else {
        cli::LocalIdentitySave::New
    };
    if replacement_requirement(resolved.local.as_ref()) == ReplacementRequirement::None || force {
        return Ok(save);
    }
    if !interactive {
        return Err(crate::cli::prompt::Error::NotInteractive {
            hint: "--force".into(),
        }
        .into());
    }
    if !crate::cli::prompt::prompt_local_replacement()
        .await
        .require_interactive("--force")?
    {
        whatever!("apply was cancelled");
    }
    Ok(save)
}

async fn resolve_kind(command: &Apply) -> Result<IdentityKind, Error> {
    match command.kind.as_deref() {
        Some(kind) => Ok(kind.parse::<IdentityKind>()?),
        None => Ok(crate::cli::prompt::prompt_kind()
            .await
            .require_interactive("--kind")?),
    }
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
    let resolved = resolve_apply_target(command, dhttp_home, cert_server, true).await?;
    let local_identity_save = authorize_local_replacement(&resolved, command.force, true).await?;
    let remote_target_state = resolved.remote;
    let mut state = InteractiveApplyState::from_command(
        command,
        Some(resolved.target.clone().into_dhttp_name()),
    )?;

    loop {
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
            let candidate =
                super::auth_plan::first_auth_candidate(dhttp_home, &target, remote_target_state)
                    .await?;
            state.approval_plan = Some(approval_plan_from_candidate(candidate)?);
            continue;
        }

        let approval_plan = state
            .approval_plan
            .clone()
            .whatever_context::<_, Error>("interactive apply approval plan is unavailable")?;

        let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&domain)?;
        let kind = state
            .kind
            .whatever_context::<_, Error>("interactive apply kind is unavailable")?;
        let device_name =
            super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
        let detail = match approval_plan {
            ApplyApprovalPlan::Email => {
                let token = super::email::run_cert_server_email_session(
                    cert_server,
                    super::email::EmailLogin::Account,
                    command.email.as_deref(),
                    command.verify_code.as_deref(),
                    true,
                )
                .await?;
                match super::progress::run(
                    super::progress::REQUEST_CERT,
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
                        let detail = super::progress::run(
                            super::progress::REQUEST_CERT,
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
                    Err(error) => return Err(Error::from(error)),
                }
            }
            ApplyApprovalPlan::DirectIdentity { auth_domain } => {
                match super::progress::run(
                    super::progress::REQUEST_CERT,
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
                        super::progress::run(
                            super::progress::REQUEST_CERT,
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
    crate::cli::flow::transcript::print_block(apply_identity_name_opening());
    let is_interactive = std::io::stdin().is_terminal();
    if is_interactive {
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
        };
    }
    let default_identity_when_command_started = cli::load_current_settings(dhttp_home)
        .await?
        .and_then(|config| config.settings().default_identity_name().cloned());
    let resolved = resolve_apply_target(command, dhttp_home, cert_server, false).await?;
    let local_identity_save = authorize_local_replacement(&resolved, command.force, false).await?;
    let remote_target_state = resolved.remote;
    let target = resolved.target;
    let domain = target.dhttp_name().into_owned();
    let kind = resolve_kind(command).await?;
    let device_name =
        super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
    let approval_plan = approval_plan_from_candidate(
        super::auth_plan::first_auth_candidate(dhttp_home, &target, remote_target_state).await?,
    )?;

    let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&domain)?;
    let detail = match approval_plan {
        ApplyApprovalPlan::Email => {
            let token = super::email::run_cert_server_email_session(
                cert_server,
                super::email::EmailLogin::Account,
                command.email.as_deref(),
                command.verify_code.as_deref(),
                false,
            )
            .await?;
            match super::progress::run(
                super::progress::REQUEST_CERT,
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
                    super::progress::run(
                        super::progress::REQUEST_CERT,
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
                Err(error) => return Err(Error::from(error)),
            }
        }
        ApplyApprovalPlan::DirectIdentity { auth_domain } => {
            match super::progress::run(
                super::progress::REQUEST_CERT,
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
                            "registering {} requires interactive email verification",
                            target.short_name()
                        );
                    }
                    ensure_sub_identity_exists_with_identity(&target, cert_server, &auth_domain)
                        .await?;
                    crate::cli::flow::transcript::print_line(new_identity_confirmation_message());
                    super::progress::run(
                        super::progress::REQUEST_CERT,
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
        ApplyApprovalPlan, CandidateEvent, MissingTargetAction, apply_identity_name_opening,
        approval_plan_from_candidate, authorize_local_replacement, explicit_target_from_command,
        interactive_name_unavailable_message, missing_root_target_error, missing_target_action,
        new_identity_confirmation_message, preserve_apply_registration_error, resolve_apply_target,
    };
    use crate::cli::{
        Apply, LocalIdentitySave,
        flow::{
            local::{IdentityUsage, LocalIdentityStatus, LocalIdentitySummary},
            target::{IdentityTarget, RemoteTargetState, ResolvedApplyTarget},
        },
    };

    fn command(name: &str) -> Apply {
        Apply {
            name: Some(name.to_string()),
            kind: Some("primary".to_string()),
            force: false,
            device_name: None,
            email: None,
            verify_code: None,
        }
    }

    fn resolved_with(status: Option<LocalIdentityStatus>) -> ResolvedApplyTarget {
        ResolvedApplyTarget {
            target: IdentityTarget::parse("alice.smith").unwrap(),
            remote: RemoteTargetState::Unknown,
            local: status.map(|status| LocalIdentitySummary {
                target: IdentityTarget::parse("alice.smith").unwrap(),
                usage: Some(IdentityUsage::BothClientAndServer),
                sequence: Some(0),
                valid_from: Some(1_700_000_000),
                expires_at: Some(1_900_000_000),
                status,
                dir: std::path::PathBuf::from("/tmp/alice.smith"),
                is_default: false,
            }),
        }
    }

    #[tokio::test]
    async fn replacement_authorization_prevents_noninteractive_side_effects_without_force() {
        let error = authorize_local_replacement(
            &resolved_with(Some(LocalIdentityStatus::Ready {
                expires_at: 1_900_000_000,
            })),
            false,
            false,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("--force"), "{error}");

        assert_eq!(
            authorize_local_replacement(
                &resolved_with(Some(LocalIdentityStatus::Invalid {
                    detail: "certificate is unreadable".to_string(),
                })),
                false,
                false,
            )
            .await
            .unwrap(),
            LocalIdentitySave::Replace
        );
        assert_eq!(
            authorize_local_replacement(&resolved_with(None), false, false)
                .await
                .unwrap(),
            LocalIdentitySave::New
        );
    }

    #[tokio::test]
    async fn explicit_target_skips_advisory_remote_inspection() {
        _ = rustls::crypto::ring::default_provider().install_default();
        let home = dhttp::home::DhttpHome::new(std::env::temp_dir().join(format!(
            "genmeta-identity-explicit-target-{}",
            std::process::id()
        )));
        let server = crate::cert_server::CertServer::new("http://127.0.0.1:1").unwrap();

        let resolved = resolve_apply_target(&command("alice.smith"), &home, &server, false)
            .await
            .unwrap();

        assert_eq!(resolved.remote, RemoteTargetState::Unknown);
        assert!(resolved.local.is_none());
    }

    #[test]
    fn explicit_target_from_command_returns_none_without_name() {
        let target = explicit_target_from_command(&Apply {
            name: None,
            kind: None,
            force: false,
            device_name: None,
            email: None,
            verify_code: None,
        })
        .unwrap();

        assert!(target.is_none());
    }

    #[test]
    fn root_apply_without_local_auth_defaults_to_email_non_interactively() {
        assert_eq!(
            approval_plan_from_candidate(CandidateEvent::Email).unwrap(),
            ApplyApprovalPlan::Email,
        );
    }

    #[test]
    fn root_apply_prefers_ready_local_auth_non_interactively() {
        assert_eq!(
            approval_plan_from_candidate(CandidateEvent::Identity {
                short_name: "alice.smith".to_string(),
                full_name: "alice.smith.dhttp.net".to_string(),
            })
            .unwrap(),
            ApplyApprovalPlan::DirectIdentity {
                auth_domain: "alice.smith.dhttp.net".to_string(),
            },
        );
    }

    #[test]
    fn sub_identity_apply_automatically_uses_ready_parent() {
        assert_eq!(
            approval_plan_from_candidate(CandidateEvent::Identity {
                short_name: "alice.smith".to_string(),
                full_name: "alice.smith.dhttp.net".to_string(),
            })
            .unwrap(),
            ApplyApprovalPlan::DirectIdentity {
                auth_domain: "alice.smith.dhttp.net".to_string(),
            },
        );
    }

    #[test]
    fn apply_identity_name_opening_matches_spec_copy() {
        assert_eq!(
            apply_identity_name_opening(),
            "Applying identity, generating ECC key pair locally, then requesting and deploying certificate."
        );
    }

    #[test]
    fn interactive_name_check_copy_matches_spec() {
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
}
