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
    cert_server::{CertServer, CertificateDetail, CertificateRenewalRequest},
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
    sequence: Option<u32>,
    device_name: &'a str,
    renewal_operation_key: Option<&'a str>,
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
        sequence,
        device_name,
        renewal_operation_key,
    } = request;
    key_material.ensure_key().map_err(RequestFailure::Local)?;
    super::progress::run(super::progress::REQUEST_CERT, async {
        let csr_pem = key_material
            .csr_pem()
            .map_err(RequestFailure::Local)?
            .to_string();
        let result = match (proof, sequence) {
            (CertificateProof::AccessToken(token), Some(sequence)) => {
                let request = CertificateRenewalRequest::new(
                    target.full_name(),
                    kind.as_str(),
                    sequence,
                    Some(device_name),
                    &csr_pem,
                )
                .with_idempotency_key(
                    renewal_operation_key
                        .expect("an existing sequence requires a renewal operation key"),
                );
                cert_server.renew_cert_request(token, request).await
            }
            (CertificateProof::AccessToken(token), None) => {
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
            (CertificateProof::IdentityProfile(profile_dir), Some(sequence)) => {
                let request = CertificateRenewalRequest::new(
                    target.full_name(),
                    kind.as_str(),
                    sequence,
                    Some(device_name),
                    &csr_pem,
                )
                .with_idempotency_key(
                    renewal_operation_key
                        .expect("an existing sequence requires a renewal operation key"),
                );
                cert_server
                    .renew_cert_with_identity_profile_request(profile_dir, request)
                    .await
            }
            (CertificateProof::IdentityProfile(profile_dir), None) => {
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

fn replacement_sequence(
    resolved: &ResolvedApplyTarget,
    requested_kind: IdentityKind,
) -> Option<u32> {
    let local = resolved.local.as_ref()?;
    let local_kind = match local.usage? {
        super::local::IdentityUsage::BothClientAndServer => IdentityKind::Primary,
        super::local::IdentityUsage::ClientOnly => IdentityKind::Secondary,
    };

    (local_kind == requested_kind)
        .then_some(local.sequence)
        .flatten()
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
    renewal_operation_key: Option<&'a str>,
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
        renewal_operation_key,
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
                    CertificateRequest {
                        target: &resolved.target,
                        kind,
                        sequence: replacement_sequence(resolved, kind),
                        device_name,
                        renewal_operation_key,
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
                    CertificateRequest {
                        target: &resolved.target,
                        kind,
                        sequence: replacement_sequence(resolved, kind),
                        device_name,
                        renewal_operation_key,
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
                                sequence: replacement_sequence(resolved, kind),
                                device_name,
                                renewal_operation_key,
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
) -> Result<(), Error> {
    let server_error = |source| Error::InstalledServerConfiguration { source };
    let profile = dhttp_home
        .resolve_identity_profile_exactly(target.dhttp_name())
        .await
        .map_err(super::site::Error::from)
        .map_err(server_error)?;
    let server = super::site::ServerConfig::for_profile(&profile);

    match server.state().await.map_err(server_error)? {
        super::site::ServerConfigState::Enabled => {
            super::transcript::print_line("Server is already enabled for this name.");
        }
        super::site::ServerConfigState::Disabled if !interactive => {
            print_server_disabled_hint(target.short_name());
        }
        super::site::ServerConfigState::Disabled => {
            let enabled = crate::cli::prompt::prompt_enable_server()
                .await
                .require_interactive("`genmeta identity ensite --id IDENTITY`")
                .map_err(|source| Error::ServerActivationPrompt { source })?;
            if enabled {
                let change = server.enable().await.map_err(server_error)?;
                super::site::print_enable_result(target.short_name(), change);
                super::transcript::print_line(format!(
                    "After reloading pishoo, visit `genmeta curl https://{}~/welcome`.",
                    target.short_name()
                ));
            } else {
                print_server_disabled_hint(target.short_name());
            }
        }
        super::site::ServerConfigState::Missing => {
            super::transcript::print_warning(
                "The identity was installed, but no server configuration was found.",
            );
        }
    }
    Ok(())
}

fn print_server_disabled_hint(identity: &str) {
    super::transcript::print_line(format!(
        "Server configuration remains disabled. Enable it with `genmeta identity ensite --id {identity}`."
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
    #[cfg(not(unix))]
    let _ = home_scope;
    let key_pem = key_material
        .key_pem()
        .expect("a certificate response requires the request key");
    super::install::validate_and_save(
        dhttp_home,
        detail,
        &super::install::InstallExpectation {
            target: resolved.target.dhttp_name(),
            kind: APPLY_CERTIFICATE_KIND,
            sequence: replacement_sequence(resolved, APPLY_CERTIFICATE_KIND),
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
    super::transcript::print_line(INSTALLED);

    #[cfg(unix)]
    {
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

    let welcome =
        super::welcome::maybe_create_welcome_service(dhttp_home, resolved.target.dhttp_name())
            .await;
    match welcome {
        Ok(Some(_)) => super::transcript::print_block(
            &super::welcome::format_welcome_service_created(resolved.target.short_name()),
        ),
        Ok(None) => {}
        Err(error) => super::transcript::print_warning(&format!(
            "The identity was installed, but the sample welcome page could not be created: {error}"
        )),
    }
    offer_server_activation(dhttp_home, &resolved.target, interactive).await?;

    super::epilogue::run_lifecycle_epilogue(dhttp_home, resolved.target.dhttp_name(), interactive)
        .await?;
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
    let kind = APPLY_CERTIFICATE_KIND;
    let device_name =
        super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
    let replacement_sequence = replacement_sequence(&resolved, kind);
    let pending_renewal = match replacement_sequence {
        Some(sequence) => match super::key_material::PendingRenewal::load(
            dhttp_home,
            resolved.target.dhttp_name(),
            kind.as_str(),
            sequence,
        )
        .await?
        {
            Some(pending) => Some(pending),
            None => Some(
                super::key_material::PendingRenewal::create(
                    dhttp_home,
                    resolved.target.dhttp_name(),
                    kind.as_str(),
                    sequence,
                    &device_name,
                )
                .await?,
            ),
        },
        None => None,
    };
    let request_device_name = pending_renewal
        .as_ref()
        .map(|pending| pending.device_name())
        .unwrap_or(&device_name)
        .to_string();
    let mut key_material = match pending_renewal.as_ref() {
        Some(pending) => super::key_material::LazyKeyMaterial::from_existing(
            resolved.target.dhttp_name(),
            pending.key_pem().to_string(),
            pending.csr_pem().to_string(),
        ),
        None => super::key_material::LazyKeyMaterial::for_name(resolved.target.dhttp_name()),
    };
    let renewal_operation_key = pending_renewal
        .as_ref()
        .map(|pending| pending.operation_key());

    loop {
        match attempt_apply_with_candidates(
            &mut resolved,
            ApplyAttemptContext {
                command,
                dhttp_home,
                cert_server,
                kind,
                device_name: &request_device_name,
                interactive,
                key_material: &mut key_material,
                renewal_operation_key,
            },
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
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::cli::flow::local::{IdentityUsage, LocalIdentityStatus, LocalIdentitySummary};

    struct ServerFixture {
        root: PathBuf,
        home: DhttpHome,
        target: IdentityTarget,
    }

    impl ServerFixture {
        async fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "genmeta-identity-apply-server-{label}-{}-{nonce}",
                std::process::id()
            ));
            let home = DhttpHome::new(root.clone());
            let target = IdentityTarget::parse("alice.smith").unwrap();
            tokio::fs::create_dir_all(home.identity_profile(target.dhttp_name()).path())
                .await
                .unwrap();
            Self { root, home, target }
        }

        fn profile(&self) -> dhttp::home::identity::IdentityProfile {
            self.home.identity_profile(self.target.dhttp_name())
        }
    }

    impl Drop for ServerFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn command(name: Option<&str>) -> Apply {
        Apply {
            name: name.map(ToOwned::to_owned),
            force: false,
            device_name: None,
            email: None,
            verify_code: None,
        }
    }

    #[test]
    fn auto_renew_enabled_copy_includes_the_identity_name() {
        assert_eq!(
            auto_renew_enabled_message("alice.smith"),
            "✔ Automatic certificate renewal enabled for alice.smith."
        );
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
    fn replacement_reuses_sequence_only_for_the_same_certificate_kind() {
        assert_eq!(
            replacement_sequence(&resolved_with(None), IdentityKind::Primary),
            None
        );
        let resolved = resolved_with(Some(LocalIdentityStatus::Incomplete {
            detail: "private key is missing".to_string(),
        }));
        assert_eq!(
            replacement_sequence(&resolved, IdentityKind::Primary),
            Some(0),
        );
        assert_eq!(
            replacement_sequence(&resolved, IdentityKind::Secondary),
            None,
        );

        let mut secondary = resolved;
        secondary.local.as_mut().unwrap().usage = Some(IdentityUsage::ClientOnly);
        assert_eq!(
            replacement_sequence(&secondary, IdentityKind::Secondary),
            Some(0),
        );
        assert_eq!(
            replacement_sequence(&secondary, IdentityKind::Primary),
            None,
        );
    }

    #[test]
    fn replacement_without_local_usage_or_sequence_requests_a_new_chain() {
        let mut resolved = resolved_with(Some(LocalIdentityStatus::Invalid {
            detail: "certificate metadata is incomplete".to_string(),
        }));
        resolved.local.as_mut().unwrap().usage = None;
        assert_eq!(replacement_sequence(&resolved, IdentityKind::Primary), None,);

        resolved.local.as_mut().unwrap().usage = Some(IdentityUsage::BothClientAndServer);
        resolved.local.as_mut().unwrap().sequence = None;
        assert_eq!(replacement_sequence(&resolved, IdentityKind::Primary), None,);
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
    fn apply_always_requests_a_client_and_server_certificate() {
        assert_eq!(APPLY_CERTIFICATE_KIND, IdentityKind::Primary);
        assert_eq!(APPLY_CERTIFICATE_KIND.as_str(), "primary");
    }

    #[tokio::test]
    async fn noninteractive_apply_keeps_a_disabled_server_configuration() {
        let fixture = ServerFixture::new("disabled").await;
        let profile = fixture.profile();
        let backup = profile.join(super::super::site::SERVER_CONF_BACKUP_FILE);
        tokio::fs::write(&backup, "edited config").await.unwrap();

        offer_server_activation(&fixture.home, &fixture.target, false)
            .await
            .unwrap();

        assert!(!profile.server_conf_path().exists());
        assert_eq!(
            tokio::fs::read_to_string(&backup).await.unwrap(),
            "edited config"
        );
    }

    #[tokio::test]
    async fn apply_treats_active_configuration_as_enabled_when_backup_also_exists() {
        let fixture = ServerFixture::new("active-with-backup").await;
        let profile = fixture.profile();
        let active = profile.server_conf_path();
        let backup = profile.join(super::super::site::SERVER_CONF_BACKUP_FILE);
        tokio::fs::write(&active, "active config").await.unwrap();
        tokio::fs::write(&backup, "backup config").await.unwrap();

        offer_server_activation(&fixture.home, &fixture.target, true)
            .await
            .unwrap();

        assert_eq!(
            tokio::fs::read_to_string(&active).await.unwrap(),
            "active config"
        );
        assert_eq!(
            tokio::fs::read_to_string(&backup).await.unwrap(),
            "backup config"
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
