use std::io::IsTerminal;

use dhttp::home::{DhttpHome, HomeScope};
use snafu::{OptionExt, whatever};

use super::{auth_plan::CandidateEvent, local};
use crate::{
    cert_server::CertServer,
    cli::{self, Error, Renew},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum RenewApprovalPlan {
    Email,
    Identity { auth_domain: String },
}

#[derive(Debug, Clone)]
struct InteractiveRenewState {
    target: Option<dhttp::name::DhttpName<'static>>,
    approval_plan: Option<RenewApprovalPlan>,
}

impl InteractiveRenewState {
    fn from_command(_command: &Renew, target: Option<dhttp::name::DhttpName<'static>>) -> Self {
        Self {
            target,
            approval_plan: None,
        }
    }
}

fn renew_not_saved_root_message(short_name: &str) -> String {
    format!("Failed to renew: {short_name} not found!")
}

async fn ensure_saved_renew_target(
    dhttp_home: &DhttpHome,
    name: dhttp::name::DhttpName<'_>,
) -> Result<(), Error> {
    if local::try_load_summary_exact(dhttp_home, name.borrow(), None)
        .await?
        .is_some()
    {
        return Ok(());
    }

    whatever!("{}", renew_not_saved_root_message(name.as_partial()));
}

fn approval_plan_from_candidate(candidate: CandidateEvent) -> Result<RenewApprovalPlan, Error> {
    match candidate {
        CandidateEvent::Identity { full_name, .. } => Ok(RenewApprovalPlan::Identity {
            auth_domain: full_name,
        }),
        CandidateEvent::Email => Ok(RenewApprovalPlan::Email),
        CandidateEvent::Warning(_) => {
            unreachable!("first_auth_candidate consumes warnings")
        }
        CandidateEvent::Exhausted => {
            whatever!("no authentication candidate is available")
        }
    }
}

async fn validate_and_save_renew(
    dhttp_home: &DhttpHome,
    domain: dhttp::name::DhttpName<'_>,
    kind: dhttp::certificate::CertificateChainKind,
    sequence: u32,
    key_pem: &str,
    detail: &crate::cert_server::CertificateDetail,
) -> Result<(), Error> {
    super::install::validate_and_save(
        dhttp_home,
        detail,
        &super::install::InstallExpectation {
            target: domain,
            kind,
            sequence: Some(sequence),
        },
        key_pem,
    )
    .await?;
    Ok(())
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
            let candidate = super::auth_plan::first_auth_candidate(
                dhttp_home,
                &target,
                crate::cli::flow::target::RemoteTargetState::Exists,
            )
            .await?;
            state.approval_plan = Some(approval_plan_from_candidate(candidate)?);
            continue;
        }

        let approval_plan = state
            .approval_plan
            .clone()
            .whatever_context::<_, Error>("interactive renew approval plan is unavailable")?;

        let identity_profile = dhttp_home.resolve_identity_profile(domain.borrow()).await?;
        let local_identity = identity_profile.load_identity().await?;
        let chain_key = cli::certificate_chain_key_from_identity(&local_identity)?
            .whatever_context::<_, Error>("local identity does not expose a certificate chain")?;
        let chain_kind = chain_key.kind();
        let kind = chain_kind.as_str();
        let sequence = chain_key.sequence().get();
        let device_name =
            super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
        let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&domain)?;

        let detail = match approval_plan {
            RenewApprovalPlan::Email => {
                let token = super::email::run_cert_server_email_session(
                    cert_server,
                    super::email::EmailLogin::Domain(domain.as_full().to_string()),
                    command.email.as_deref(),
                    command.verify_code.as_deref(),
                    true,
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

        validate_and_save_renew(
            dhttp_home,
            domain.borrow(),
            chain_kind,
            sequence,
            &key_pem,
            &detail,
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
    let approval_plan = approval_plan_from_candidate(
        super::auth_plan::first_auth_candidate(
            dhttp_home,
            &target,
            crate::cli::flow::target::RemoteTargetState::Exists,
        )
        .await?,
    )?;
    let identity_profile = dhttp_home.resolve_identity_profile(domain.borrow()).await?;
    let local_identity = identity_profile.load_identity().await?;
    let chain_key = cli::certificate_chain_key_from_identity(&local_identity)?
        .whatever_context::<_, Error>("local identity does not expose a certificate chain")?;
    let chain_kind = chain_key.kind();
    let kind = chain_kind.as_str();
    let sequence = chain_key.sequence().get();
    let device_name =
        super::device::resolve_device_name(command.device_name.as_deref(), home_scope);

    let (key_pem, csr_pem) = cli::generate_private_key_and_csr(&domain)?;
    let detail = match approval_plan {
        RenewApprovalPlan::Email => {
            let token = super::email::run_cert_server_email_session(
                cert_server,
                super::email::EmailLogin::Domain(domain.as_full().to_string()),
                command.email.as_deref(),
                command.verify_code.as_deref(),
                false,
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

    validate_and_save_renew(
        dhttp_home,
        domain.borrow(),
        chain_kind,
        sequence,
        &key_pem,
        &detail,
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
        CandidateEvent, RenewApprovalPlan, approval_plan_from_candidate,
        renew_not_saved_root_message,
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
    fn renew_prefers_ready_identity_non_interactively() {
        assert_eq!(
            approval_plan_from_candidate(CandidateEvent::Identity {
                short_name: "alice.smith".to_string(),
                full_name: "alice.smith.dhttp.net".to_string(),
            })
            .unwrap(),
            RenewApprovalPlan::Identity {
                auth_domain: "alice.smith.dhttp.net".to_string()
            }
        );
    }

    #[test]
    fn renew_without_ready_identity_uses_email_non_interactively() {
        assert_eq!(
            approval_plan_from_candidate(CandidateEvent::Email).unwrap(),
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
}
