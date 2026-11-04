use std::{io::IsTerminal, path::Path};

use dhttp_home::{DhttpHome, HomeScope};
use snafu::{FromString, whatever};

use super::{
    auth_plan::CandidateEvent,
    kind::IdentityKind,
    registration::{RegistrationError, RegistrationOutcome, RegistrationProof},
    target::{
        IdentityLevel, IdentityTarget, RemoteTargetState, ReplacementRequirement,
        ResolvedApplyTarget, remote_state_from_availability, replacement_requirement,
    },
};
use crate::{
    cert_server::{CertServer, CertificateDetail},
    cli::{Apply, Error, prompt::InquireResultExt},
};

const APPLY_OPENING: &str = "Applying identity, generating ECC key pair locally, then requesting and deploying certificate.";
const INSTALLED: &str = "✔ Identity successfully installed on this device.";
const NEW_NAME_FREE: &str = "This new name is yours now.";
const APPLY_CERTIFICATE_KIND: IdentityKind = IdentityKind::Primary;

#[cfg(any(unix, test))]
fn auto_renew_enabled_message(identity: &str) -> String {
    format!("✔ Automatic certificate renewal enabled for {identity}.")
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
            Err(Error::CertServer { source })
                if source.is_api(reqwest::StatusCode::BAD_REQUEST, "domain_invalid") =>
            {
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
) -> Result<(), Error> {
    if replacement_requirement(resolved.local.as_ref()) == ReplacementRequirement::None || force {
        return Ok(());
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
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum CertificateProof<'a> {
    AccessToken(&'a str),
    IdentityProfile(&'a Path),
}

#[derive(Debug)]
enum RequestFailure {
    Local(Error),
    Remote(crate::cert_server::Error),
}

#[derive(Clone, Copy)]
struct CertificateRequest<'a> {
    target: &'a IdentityTarget,
    kind: IdentityKind,
    device_name: &'a str,
}

async fn request_certificate(
    cert_server: &CertServer,
    proof: CertificateProof<'_>,
    request: CertificateRequest<'_>,
    key_material: &mut super::key_material::LazyKeyMaterial,
) -> Result<CertificateDetail, RequestFailure> {
    let CertificateRequest {
        target,
        kind,
        device_name,
    } = request;
    key_material.ensure_key().map_err(RequestFailure::Local)?;
    super::progress::run(super::progress::REQUEST_CERT, async {
        let csr_pem = key_material
            .csr_pem()
            .map_err(RequestFailure::Local)?
            .to_string();
        let result = match proof {
            CertificateProof::AccessToken(token) => {
                cert_server
                    .issue_cert(
                        token,
                        target.full_name(),
                        kind.as_str(),
                        None,
                        device_name,
                        &csr_pem,
                    )
                    .await
            }
            CertificateProof::IdentityProfile(profile_dir) => {
                cert_server
                    .issue_cert_with_identity_profile(
                        profile_dir,
                        target.full_name(),
                        kind.as_str(),
                        None,
                        device_name,
                        &csr_pem,
                    )
                    .await
            }
        };
        result.map_err(RequestFailure::Remote)
    })
    .await
}

fn print_new_name(outcome: RegistrationOutcome) {
    if outcome == RegistrationOutcome::CreatedFree {
        super::transcript::print_line(NEW_NAME_FREE);
    }
}

async fn register_with_email(
    cert_server: &CertServer,
    target: &IdentityTarget,
    token: &str,
    interactive: bool,
) -> Result<RegistrationOutcome, RegistrationError> {
    let api = super::registration::CertServerRegistrationApi::new(cert_server);
    match target.level() {
        IdentityLevel::Identity if interactive => {
            super::registration::register_missing_root(
                &api,
                &super::registration::InquireRegistrationUi,
                target,
                token,
                true,
            )
            .await
        }
        IdentityLevel::Identity => {
            super::registration::register_missing_root(
                &api,
                &super::registration::NoRegistrationUi,
                target,
                token,
                false,
            )
            .await
        }
        IdentityLevel::SubIdentity => {
            super::registration::register_missing_child(
                &api,
                target,
                RegistrationProof::AccessToken(token),
            )
            .await
        }
    }
}

async fn register_with_parent(
    cert_server: &CertServer,
    target: &IdentityTarget,
    parent_profile_dir: &Path,
) -> Result<RegistrationOutcome, RegistrationError> {
    if target.level() != IdentityLevel::SubIdentity {
        return Err(RegistrationError::MissingParent {
            message: "a missing root identity cannot be registered by an identity proof"
                .to_string(),
        });
    }
    let api = super::registration::CertServerRegistrationApi::new(cert_server);
    super::registration::register_missing_child(
        &api,
        target,
        RegistrationProof::ParentIdentityProfile(parent_profile_dir),
    )
    .await
}

fn registration_auth_rejection(error: &RegistrationError) -> Option<&crate::cert_server::Error> {
    match error {
        RegistrationError::CertServer { source }
            if crate::auth::classify_identity_attempt(source)
                == crate::auth::AuthAttemptDisposition::TryNext =>
        {
            Some(source)
        }
        _ => None,
    }
}

fn print_auth_rejection(name: &str, error: &crate::cert_server::Error) {
    super::transcript::print_warning(&format!(
        "Cannot authenticate with {name}: {error}; trying the next authentication method"
    ));
}

fn should_register_with_parent(
    target: &IdentityTarget,
    remote: RemoteTargetState,
    candidate_full_name: &str,
) -> bool {
    target
        .parent()
        .is_some_and(|parent| parent.as_full() == candidate_full_name)
        && matches!(
            remote,
            RemoteTargetState::Missing | RemoteTargetState::Unknown
        )
}

#[derive(Debug)]
enum ApplyAttempt {
    Certificate(Box<CertificateDetail>),
    ReplanMissing,
}

struct ApplyAttemptContext<'a> {
    command: &'a Apply,
    cert_server: &'a CertServer,
    kind: IdentityKind,
    device_name: &'a str,
    interactive: bool,
    key_material: &'a mut super::key_material::LazyKeyMaterial,
}

async fn attempt_apply_with_candidates<L: super::auth_plan::ExactIdentityLoader>(
    resolved: &mut ResolvedApplyTarget,
    context: ApplyAttemptContext<'_>,
    loader: L,
) -> Result<ApplyAttempt, Error> {
    let ApplyAttemptContext {
        command,
        cert_server,
        kind,
        device_name,
        interactive,
        key_material,
    } = context;
    let specs = super::auth_plan::candidate_specs(&resolved.target, resolved.remote);
    let mut candidates = super::auth_plan::AuthCandidateRunner::new(loader, specs);
    let mut last_rejection = None;

    loop {
        match candidates.next().await? {
            CandidateEvent::Warning(warning) => {
                super::transcript::print_warning(&warning);
            }
            CandidateEvent::Identity {
                short_name,
                full_name,
                profile_dir,
            } => {
                if should_register_with_parent(&resolved.target, resolved.remote, &full_name) {
                    match register_with_parent(cert_server, &resolved.target, &profile_dir).await {
                        Ok(outcome) => {
                            print_new_name(outcome);
                            resolved.remote = RemoteTargetState::Exists;
                        }
                        Err(error) if registration_auth_rejection(&error).is_some() => {
                            let source = registration_auth_rejection(&error)
                                .expect("guard confirmed an authentication rejection");
                            print_auth_rejection(&short_name, source);
                            last_rejection = Some(error);
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }

                match request_certificate(
                    cert_server,
                    CertificateProof::IdentityProfile(&profile_dir),
                    CertificateRequest {
                        target: &resolved.target,
                        kind,
                        device_name,
                    },
                    key_material,
                )
                .await
                {
                    Ok(detail) => return Ok(ApplyAttempt::Certificate(Box::new(detail))),
                    Err(RequestFailure::Local(error)) => return Err(error),
                    Err(RequestFailure::Remote(error)) => {
                        match crate::auth::classify_identity_attempt(&error) {
                            crate::auth::AuthAttemptDisposition::TryNext => {
                                print_auth_rejection(&short_name, &error);
                                last_rejection =
                                    Some(RegistrationError::CertServer { source: error });
                            }
                            crate::auth::AuthAttemptDisposition::ReplanMissingTarget => {
                                return Ok(ApplyAttempt::ReplanMissing);
                            }
                            crate::auth::AuthAttemptDisposition::Terminal => {
                                return Err(error.into());
                            }
                        }
                    }
                }
            }
            CandidateEvent::Email => {
                let token = super::email::run_cert_server_email_session(
                    cert_server,
                    super::email::EmailLogin::Account,
                    command.email.as_deref(),
                    command.verify_code.as_deref(),
                    interactive,
                )
                .await?;

                if matches!(
                    resolved.remote,
                    RemoteTargetState::Missing | RemoteTargetState::Unknown
                ) {
                    let outcome =
                        register_with_email(cert_server, &resolved.target, &token, interactive)
                            .await?;
                    print_new_name(outcome);
                    resolved.remote = RemoteTargetState::Exists;
                }

                let first = request_certificate(
                    cert_server,
                    CertificateProof::AccessToken(&token),
                    CertificateRequest {
                        target: &resolved.target,
                        kind,
                        device_name,
                    },
                    key_material,
                )
                .await;
                let detail = match first {
                    Ok(detail) => detail,
                    Err(RequestFailure::Local(error)) => return Err(error),
                    Err(RequestFailure::Remote(error))
                        if crate::auth::classify_identity_attempt(&error)
                            == crate::auth::AuthAttemptDisposition::ReplanMissingTarget =>
                    {
                        let outcome =
                            register_with_email(cert_server, &resolved.target, &token, interactive)
                                .await?;
                        print_new_name(outcome);
                        resolved.remote = RemoteTargetState::Exists;
                        match request_certificate(
                            cert_server,
                            CertificateProof::AccessToken(&token),
                            CertificateRequest {
                                target: &resolved.target,
                                kind,
                                device_name,
                            },
                            key_material,
                        )
                        .await
                        {
                            Ok(detail) => detail,
                            Err(RequestFailure::Local(error)) => return Err(error),
                            Err(RequestFailure::Remote(error)) => return Err(error.into()),
                        }
                    }
                    Err(RequestFailure::Remote(error)) => return Err(error.into()),
                };
                return Ok(ApplyAttempt::Certificate(Box::new(detail)));
            }
            CandidateEvent::Exhausted => {
                if let Some(error) = last_rejection {
                    return Err(error.into());
                }
                whatever!("no authentication candidate is available");
            }
        }
    }
}

fn certificate_action(resolved: &ResolvedApplyTarget) -> dhttp::log::cert::CertificateAction {
    if resolved.local.is_some() {
        dhttp::log::cert::CertificateAction::Replace
    } else {
        dhttp::log::cert::CertificateAction::Apply
    }
}

async fn offer_server_activation(
    dhttp_home: &DhttpHome,
    target: &IdentityTarget,
    interactive: bool,
) -> Result<bool, Error> {
    let server_error = |source| Error::InstalledServerConfiguration { source };
    let profile = dhttp_home
        .resolve_identity_profile_exactly((target.dhttp_name()).as_full())
        .await
        .map_err(super::site::Error::from)
        .map_err(server_error)?;
    let server = super::site::ServerConfig::for_profile(&profile);

    let state = match server.state().await {
        Ok(state) => state,
        Err(error) => {
            super::transcript::print_warning(&format!(
                "The identity is installed, but its service could not be configured: {error}"
            ));
            print_server_disabled_hint(target.short_name());
            return Ok(false);
        }
    };
    match state {
        super::site::ServerConfigState::Enabled => Ok(true),
        super::site::ServerConfigState::Disabled | super::site::ServerConfigState::Missing
            if !interactive =>
        {
            print_server_disabled_hint(target.short_name());
            Ok(false)
        }
        super::site::ServerConfigState::Disabled | super::site::ServerConfigState::Missing => {
            let enabled = crate::cli::prompt::prompt_enable_server()
                .await
                .require_interactive("`genmeta listen --id IDENTITY all`")
                .map_err(|source| Error::ServerActivationPrompt { source })?;
            if enabled {
                if let Err(error) = server.enable().await {
                    super::transcript::print_warning(&format!(
                        "The identity is installed, but its service could not be enabled: {error}"
                    ));
                    print_server_disabled_hint(target.short_name());
                    return Ok(false);
                }
            } else {
                print_server_disabled_hint(target.short_name());
            }
            Ok(enabled)
        }
    }
}

fn print_server_disabled_hint(identity: &str) {
    super::transcript::print_line(format!(
        "Server is not enabled. Enable it with `genmeta listen --id {identity} all`."
    ));
}

struct InstallFinishContext<'a> {
    dhttp_home: &'a DhttpHome,
    home_scope: HomeScope,
    resolved: &'a ResolvedApplyTarget,
    interactive: bool,
}

async fn install_and_finish(
    context: InstallFinishContext<'_>,
    key_material: &super::key_material::LazyKeyMaterial,
    detail: &CertificateDetail,
) -> Result<(), Error> {
    let InstallFinishContext {
        dhttp_home,
        home_scope,
        resolved,
        interactive,
    } = context;
    let key_pem = key_material
        .key_pem()
        .expect("a certificate response requires the request key");
    super::install::validate_and_save(
        dhttp_home,
        detail,
        &super::install::InstallExpectation {
            target: resolved.target.dhttp_name(),
            kind: APPLY_CERTIFICATE_KIND,
            sequence: None,
        },
        key_pem,
        certificate_action(resolved),
    )
    .await?;
    if let Err(error) = super::key_material::PendingRenewal::remove_for_name(
        dhttp_home,
        resolved.target.dhttp_name(),
    )
    .await
    {
        tracing::warn!(
            identity = %resolved.target.full_name(),
            error = %snafu::Report::from_error(&error),
            "failed to remove installed renewal material"
        );
    }
    finish_installed(InstallFinishContext {
        dhttp_home,
        home_scope,
        resolved,
        interactive,
    })
    .await
}

async fn finish_installed(context: InstallFinishContext<'_>) -> Result<(), Error> {
    let InstallFinishContext {
        dhttp_home,
        home_scope,
        resolved,
        interactive,
    } = context;
    super::transcript::print_line(INSTALLED);

    let profile = dhttp_home
        .identity_profile(resolved.target.full_name())
        .expect("validated identity name");
    let developer = crate::cli::developer::installed_sequence(&profile)?.is_some();
    if developer {
        crate::cli::developer::require_manual_renewal(dhttp_home, resolved.target.full_name())
            .await;
    }
    #[cfg(unix)]
    if !developer {
        let identity_enabled = match super::auto_renew::enable_identity(
            dhttp_home,
            resolved.target.dhttp_name(),
        )
        .await
        {
            Ok(()) => true,
            Err(error) => {
                super::transcript::print_warning(&format!(
                    "The identity was installed, but automatic certificate renewal could not be enabled: {error}"
                ));
                false
            }
        };
        match super::auto_renew::ensure_schedule(home_scope).await {
            Ok(()) if identity_enabled => super::transcript::print_line(
                auto_renew_enabled_message(resolved.target.short_name()),
            ),
            Ok(()) => {}
            Err(error) => super::transcript::print_warning(&format!(
                "The identity was installed, but automatic certificate renewal could not be scheduled: {error}"
            )),
        }
    }

    let server_enabled = offer_server_activation(dhttp_home, &resolved.target, interactive).await?;

    super::epilogue::run_lifecycle_epilogue(dhttp_home, resolved.target.dhttp_name(), interactive)
        .await?;
    super::workspace::finish_setup(
        dhttp_home,
        home_scope,
        resolved.target.short_name(),
        server_enabled,
        interactive,
    )
    .await;
    Ok(())
}

pub(crate) async fn run(
    command: &Apply,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
) -> Result<(), Error> {
    super::transcript::print_line(APPLY_OPENING);
    let interactive = std::io::stdin().is_terminal();
    let mut resolved = resolve_apply_target(command, dhttp_home, cert_server, interactive).await?;
    let kind = APPLY_CERTIFICATE_KIND;
    let device_name =
        super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
    authorize_local_replacement(&resolved, command.force, interactive).await?;
    // Apply allocates a fresh sequence using the server's current entitlement policy.
    // Renew alone preserves a sequence and its certificate purpose.
    let mut key_material =
        super::key_material::LazyKeyMaterial::for_name(resolved.target.dhttp_name());

    loop {
        match attempt_apply_with_candidates(
            &mut resolved,
            ApplyAttemptContext {
                command,
                cert_server,
                kind,
                device_name: &device_name,
                interactive,
                key_material: &mut key_material,
            },
            super::auth_plan::HomeExactIdentityLoader::new(dhttp_home),
        )
        .await?
        {
            ApplyAttempt::Certificate(detail) => {
                return install_and_finish(
                    InstallFinishContext {
                        dhttp_home,
                        home_scope,
                        resolved: &resolved,
                        interactive,
                    },
                    &key_material,
                    &detail,
                )
                .await;
            }
            ApplyAttempt::ReplanMissing => {
                resolved.remote = RemoteTargetState::Missing;
            }
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/apply.rs"]
mod tests;
