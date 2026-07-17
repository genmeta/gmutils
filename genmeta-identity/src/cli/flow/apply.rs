use std::{io::IsTerminal, path::Path};

use dhttp::home::{DhttpHome, HomeScope};
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

async fn resolve_kind(command: &Apply) -> Result<IdentityKind, Error> {
    match command.kind.as_deref() {
        Some(kind) => Ok(kind.parse::<IdentityKind>()?),
        None => Ok(crate::cli::prompt::prompt_kind()
            .await
            .require_interactive("--kind")?),
    }
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

async fn request_certificate(
    cert_server: &CertServer,
    proof: CertificateProof<'_>,
    target: &IdentityTarget,
    kind: IdentityKind,
    device_name: &str,
    key_material: &mut super::key_material::LazyKeyMaterial,
) -> Result<CertificateDetail, RequestFailure> {
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

fn should_register_with_email(remote: RemoteTargetState) -> bool {
    matches!(
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
    dhttp_home: &'a DhttpHome,
    cert_server: &'a CertServer,
    kind: IdentityKind,
    device_name: &'a str,
    interactive: bool,
    key_material: &'a mut super::key_material::LazyKeyMaterial,
}

async fn attempt_apply_with_candidates(
    resolved: &mut ResolvedApplyTarget,
    context: ApplyAttemptContext<'_>,
) -> Result<ApplyAttempt, Error> {
    let ApplyAttemptContext {
        command,
        dhttp_home,
        cert_server,
        kind,
        device_name,
        interactive,
        key_material,
    } = context;
    let specs = super::auth_plan::candidate_specs(&resolved.target, resolved.remote);
    let loader = super::auth_plan::HomeExactIdentityLoader::new(dhttp_home);
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
                    &resolved.target,
                    kind,
                    device_name,
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

                if should_register_with_email(resolved.remote) {
                    let outcome =
                        register_with_email(cert_server, &resolved.target, &token, interactive)
                            .await?;
                    print_new_name(outcome);
                    resolved.remote = RemoteTargetState::Exists;
                }

                let first = request_certificate(
                    cert_server,
                    CertificateProof::AccessToken(&token),
                    &resolved.target,
                    kind,
                    device_name,
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
                            &resolved.target,
                            kind,
                            device_name,
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

async fn install_and_finish(
    dhttp_home: &DhttpHome,
    resolved: &ResolvedApplyTarget,
    kind: IdentityKind,
    interactive: bool,
    key_material: &super::key_material::LazyKeyMaterial,
    detail: &CertificateDetail,
) -> Result<(), Error> {
    let key_pem = key_material
        .key_pem()
        .expect("a certificate response requires the request key");
    super::install::validate_and_save(
        dhttp_home,
        detail,
        &super::install::InstallExpectation {
            target: resolved.target.dhttp_name(),
            kind: kind.into(),
            sequence: None,
        },
        key_pem,
        certificate_action(resolved),
    )
    .await?;
    super::transcript::print_line(INSTALLED);

    let usage = match kind {
        IdentityKind::Primary => super::local::IdentityUsage::BothClientAndServer,
        IdentityKind::Secondary => super::local::IdentityUsage::ClientOnly,
    };
    let welcome = super::welcome::maybe_create_welcome_service(
        dhttp_home,
        resolved.target.dhttp_name(),
        usage,
    )
    .await;

    super::epilogue::run_lifecycle_epilogue(dhttp_home, resolved.target.dhttp_name(), interactive)
        .await?;

    match welcome {
        Ok(Some(_)) => super::transcript::print_line(
            super::welcome::format_welcome_service_created(resolved.target.short_name()),
        ),
        Ok(None) => {}
        Err(error) => super::transcript::print_warning(&format!(
            "The identity was installed, but the sample welcome page could not be created: {error}"
        )),
    }
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
    authorize_local_replacement(&resolved, command.force, interactive).await?;
    let kind = resolve_kind(command).await?;
    let device_name =
        super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
    let mut key_material =
        super::key_material::LazyKeyMaterial::for_name(resolved.target.dhttp_name());

    loop {
        match attempt_apply_with_candidates(
            &mut resolved,
            ApplyAttemptContext {
                command,
                dhttp_home,
                cert_server,
                kind,
                device_name: &device_name,
                interactive,
                key_material: &mut key_material,
            },
        )
        .await?
        {
            ApplyAttempt::Certificate(detail) => {
                return install_and_finish(
                    dhttp_home,
                    &resolved,
                    kind,
                    interactive,
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
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::flow::local::{IdentityUsage, LocalIdentityStatus, LocalIdentitySummary};

    fn command(name: Option<&str>) -> Apply {
        Apply {
            name: name.map(ToOwned::to_owned),
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
                dir: PathBuf::from("/tmp/alice.smith"),
                is_default: false,
            }),
        }
    }

    #[test]
    fn certificate_action_tracks_exact_local_material_lifecycle() {
        assert_eq!(
            certificate_action(&resolved_with(None)),
            dhttp::log::cert::CertificateAction::Apply,
        );
        assert_eq!(
            certificate_action(&resolved_with(Some(LocalIdentityStatus::Invalid {
                detail: "certificate is unreadable".to_string(),
            }))),
            dhttp::log::cert::CertificateAction::Replace,
        );
        assert_eq!(
            certificate_action(&resolved_with(Some(LocalIdentityStatus::Ready {
                expires_at: 1_900_000_000,
            }))),
            dhttp::log::cert::CertificateAction::Replace,
        );
    }

    #[test]
    fn apply_copy_matches_the_approved_transcript() {
        assert_eq!(
            APPLY_OPENING,
            "Applying identity, generating ECC key pair locally, then requesting and deploying certificate."
        );
        assert_eq!(NEW_NAME_FREE, "This new name is yours now.");
        assert_eq!(
            INSTALLED,
            "✔ Identity successfully installed on this device."
        );
    }

    #[test]
    fn explicit_target_is_parsed_without_remote_preclassification() {
        assert_eq!(
            explicit_target_from_command(&command(Some("alice.smith")))
                .unwrap()
                .unwrap()
                .short_name(),
            "alice.smith"
        );
        assert!(
            explicit_target_from_command(&command(None))
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn replacement_authorization_prevents_noninteractive_side_effects_without_force() {
        let ready = resolved_with(Some(LocalIdentityStatus::Ready {
            expires_at: 1_900_000_000,
        }));
        assert!(
            authorize_local_replacement(&ready, false, false)
                .await
                .is_err()
        );
        authorize_local_replacement(&ready, true, false)
            .await
            .unwrap();

        let invalid = resolved_with(Some(LocalIdentityStatus::Invalid {
            detail: "certificate is unreadable".to_string(),
        }));
        authorize_local_replacement(&invalid, false, false)
            .await
            .unwrap();
    }

    #[test]
    fn missing_targets_are_replanned_to_the_safe_candidate_order() {
        let root = IdentityTarget::parse("alice.smith").unwrap();
        let child = IdentityTarget::parse("phone.alice.smith").unwrap();
        assert_eq!(
            super::super::auth_plan::candidate_specs(&root, RemoteTargetState::Missing),
            vec![super::super::auth_plan::AuthCandidateSpec::Email]
        );
        assert_eq!(
            super::super::auth_plan::candidate_specs(&child, RemoteTargetState::Missing),
            vec![
                super::super::auth_plan::AuthCandidateSpec::Identity(
                    dhttp::name::DhttpName::try_from("alice.smith")
                        .unwrap()
                        .into_owned()
                ),
                super::super::auth_plan::AuthCandidateSpec::Email,
            ]
        );
    }

    #[test]
    fn explicit_targets_register_only_with_the_direct_parent_proof() {
        let root = IdentityTarget::parse("alice.smith").unwrap();
        let child = IdentityTarget::parse("phone.alice.smith").unwrap();

        assert!(!should_register_with_parent(
            &root,
            RemoteTargetState::Unknown,
            "alice.smith.dhttp.net",
        ));
        assert!(!should_register_with_parent(
            &child,
            RemoteTargetState::Unknown,
            "phone.alice.smith.dhttp.net",
        ));
        assert!(should_register_with_parent(
            &child,
            RemoteTargetState::Unknown,
            "alice.smith.dhttp.net",
        ));
        assert!(!should_register_with_parent(
            &child,
            RemoteTargetState::Exists,
            "alice.smith.dhttp.net",
        ));
        assert!(should_register_with_email(RemoteTargetState::Unknown));
        assert!(should_register_with_email(RemoteTargetState::Missing));
        assert!(!should_register_with_email(RemoteTargetState::Exists));
    }
}
