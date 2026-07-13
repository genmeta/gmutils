use std::io::IsTerminal;

use dhttp::{
    certificate::CertificateChainKind,
    home::{DhttpHome, HomeScope},
};
use snafu::{FromString, whatever};

use super::{auth_plan::CandidateEvent, local};
use crate::{
    cert_server::{CertServer, CertificateDetail},
    cli::{Error, Renew},
};

const RENEWED: &str = "Identity successfully renewed on this device.";

fn renew_not_saved_root_message(short_name: &str) -> String {
    format!("Failed to renew: {short_name} not found!")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RenewPreflight {
    target: super::target::IdentityTarget,
    kind: CertificateChainKind,
    sequence: u32,
}

impl RenewPreflight {
    pub(crate) fn from_summary(
        summary: &local::LocalIdentitySummary,
        force: bool,
    ) -> Result<Self, Error> {
        match summary.status {
            local::LocalIdentityStatus::Ready { .. }
            | local::LocalIdentityStatus::Expired { .. } => {}
            local::LocalIdentityStatus::Invalid { .. }
            | local::LocalIdentityStatus::Incomplete { .. }
                if !force =>
            {
                return Err(Error::without_source(format!(
                    "Failed to renew: {} is {}; use --force only if its certificate remains readable.",
                    summary.target.short_name(),
                    summary.status.label()
                )));
            }
            local::LocalIdentityStatus::Invalid { .. }
            | local::LocalIdentityStatus::Incomplete { .. } => {}
        }

        let kind = match summary.usage {
            Some(local::IdentityUsage::BothClientAndServer) => CertificateChainKind::Primary,
            Some(local::IdentityUsage::ClientOnly) => CertificateChainKind::Secondary,
            None => {
                return Err(Self::unrecoverable(&summary.target));
            }
        };
        let Some(sequence) = summary.sequence else {
            return Err(Self::unrecoverable(&summary.target));
        };
        Ok(Self {
            target: summary.target.clone(),
            kind,
            sequence,
        })
    }

    fn validate_assessment(
        &self,
        assessment: &local::LocalIdentityAssessment,
    ) -> Result<(), Error> {
        let actual_kind = match assessment.usage {
            Some(local::IdentityUsage::BothClientAndServer) => CertificateChainKind::Primary,
            Some(local::IdentityUsage::ClientOnly) => CertificateChainKind::Secondary,
            None => return Err(Self::unrecoverable(&self.target)),
        };
        if assessment.certificate_target_matches != Some(true)
            || actual_kind != self.kind
            || assessment.sequence != Some(self.sequence)
        {
            return Err(Self::unrecoverable(&self.target));
        }
        Ok(())
    }

    fn unrecoverable(target: &super::target::IdentityTarget) -> Error {
        Error::without_source(format!(
            "Failed to renew: {} does not contain a readable certificate with recoverable target and chain metadata.",
            target.short_name()
        ))
    }
}

async fn resolve_preflight(
    command: &Renew,
    dhttp_home: &DhttpHome,
) -> Result<RenewPreflight, Error> {
    let domain = match command.name.as_deref() {
        Some(name) => crate::cli::parse_identity_name(name)?,
        None => crate::cli::resolve_default_target_name(dhttp_home).await?,
    };
    let Some(summary) = local::try_load_summary_exact(dhttp_home, domain.borrow(), None).await?
    else {
        whatever!("{}", renew_not_saved_root_message(domain.as_partial()));
    };
    let preflight = RenewPreflight::from_summary(&summary, command.force)?;
    let assessment = local::assess_profile_exact(dhttp_home, domain.borrow()).await?;
    preflight.validate_assessment(&assessment)?;
    Ok(preflight)
}

#[derive(Debug, Clone, Copy)]
enum RenewProof<'a> {
    AccessToken(&'a str),
    Identity(&'a str),
}

#[derive(Debug)]
enum RequestFailure {
    Local(Error),
    Remote(crate::cert_server::Error),
}

async fn request_renewal(
    cert_server: &CertServer,
    proof: RenewProof<'_>,
    preflight: &RenewPreflight,
    device_name: &str,
    key_material: &mut super::key_material::LazyKeyMaterial,
) -> Result<CertificateDetail, RequestFailure> {
    key_material.ensure_key().map_err(RequestFailure::Local)?;
    super::progress::run(super::progress::RENEW_IDENTITY, async {
        let csr_pem = key_material
            .csr_pem()
            .map_err(RequestFailure::Local)?
            .to_string();
        let result = match proof {
            RenewProof::AccessToken(token) => {
                cert_server
                    .renew_cert(
                        token,
                        preflight.target.full_name(),
                        preflight.kind.as_str(),
                        preflight.sequence,
                        Some(device_name),
                        &csr_pem,
                    )
                    .await
            }
            RenewProof::Identity(identity) => {
                cert_server
                    .renew_cert_with_identity(
                        identity,
                        preflight.target.full_name(),
                        preflight.kind.as_str(),
                        preflight.sequence,
                        Some(device_name),
                        &csr_pem,
                    )
                    .await
            }
        };
        result.map_err(RequestFailure::Remote)
    })
    .await
}

fn renew_remote_error(error: crate::cert_server::Error, target: &str) -> Error {
    if error.is_api_code("cert_sequence_not_found") {
        let message = error.to_string();
        return Error::with_source(
            Box::new(error),
            format!(
                "{message}\nRun `genmeta identity apply {target}` to request a new certificate chain."
            ),
        );
    }
    error.into()
}

fn print_auth_rejection(name: &str, error: &crate::cert_server::Error) {
    super::transcript::print_warning(&format!(
        "Cannot authenticate with {name}: {error}; trying the next authentication method"
    ));
}

async fn request_with_candidates(
    command: &Renew,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
    preflight: &RenewPreflight,
    device_name: &str,
    interactive: bool,
    key_material: &mut super::key_material::LazyKeyMaterial,
) -> Result<CertificateDetail, Error> {
    let specs = super::auth_plan::candidate_specs(
        &preflight.target,
        super::target::RemoteTargetState::Exists,
    );
    let loader = super::auth_plan::HomeExactIdentityLoader::new(dhttp_home);
    let mut candidates = super::auth_plan::AuthCandidateRunner::new(loader, specs);
    let mut last_rejection = None;

    loop {
        match candidates.next().await? {
            CandidateEvent::Warning(warning) => super::transcript::print_warning(&warning),
            CandidateEvent::Identity {
                short_name,
                full_name,
            } => match request_renewal(
                cert_server,
                RenewProof::Identity(&full_name),
                preflight,
                device_name,
                key_material,
            )
            .await
            {
                Ok(detail) => return Ok(detail),
                Err(RequestFailure::Local(error)) => return Err(error),
                Err(RequestFailure::Remote(error))
                    if crate::auth::classify_identity_attempt(&error)
                        == crate::auth::AuthAttemptDisposition::TryNext =>
                {
                    print_auth_rejection(&short_name, &error);
                    last_rejection = Some(error);
                }
                Err(RequestFailure::Remote(error)) => {
                    return Err(renew_remote_error(error, preflight.target.short_name()));
                }
            },
            CandidateEvent::Email => {
                let token = super::email::run_cert_server_email_session(
                    cert_server,
                    super::email::EmailLogin::Domain(preflight.target.full_name().to_string()),
                    command.email.as_deref(),
                    command.verify_code.as_deref(),
                    interactive,
                )
                .await?;
                return match request_renewal(
                    cert_server,
                    RenewProof::AccessToken(&token),
                    preflight,
                    device_name,
                    key_material,
                )
                .await
                {
                    Ok(detail) => Ok(detail),
                    Err(RequestFailure::Local(error)) => Err(error),
                    Err(RequestFailure::Remote(error)) => {
                        Err(renew_remote_error(error, preflight.target.short_name()))
                    }
                };
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

pub(crate) async fn run(
    command: &Renew,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
) -> Result<(), Error> {
    let interactive = std::io::stdin().is_terminal();
    let preflight = resolve_preflight(command, dhttp_home).await?;
    let device_name =
        super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
    let mut key_material =
        super::key_material::LazyKeyMaterial::for_name(preflight.target.dhttp_name());
    let detail = request_with_candidates(
        command,
        dhttp_home,
        cert_server,
        &preflight,
        &device_name,
        interactive,
        &mut key_material,
    )
    .await?;
    let key_pem = key_material
        .key_pem()
        .expect("a renewal response requires the request key");
    super::install::validate_and_save(
        dhttp_home,
        &detail,
        &super::install::InstallExpectation {
            target: preflight.target.dhttp_name(),
            kind: preflight.kind,
            sequence: Some(preflight.sequence),
        },
        key_pem,
    )
    .await?;
    super::transcript::print_line(RENEWED);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use dhttp::home::{DhttpHome, HomeScope};

    use super::{RenewPreflight, renew_not_saved_root_message, renew_remote_error};
    use crate::cli::{
        Renew,
        flow::{
            local::{IdentityUsage, LocalIdentityStatus, LocalIdentitySummary},
            target::IdentityTarget,
        },
    };

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

    fn summary(status: LocalIdentityStatus, facts: bool) -> LocalIdentitySummary {
        LocalIdentitySummary {
            target: IdentityTarget::parse("alice.smith").unwrap(),
            usage: facts.then_some(IdentityUsage::ClientOnly),
            sequence: facts.then_some(2),
            valid_from: Some(1_700_000_000),
            expires_at: Some(1_900_000_000),
            status,
            dir: PathBuf::from("/tmp/alice.smith"),
            is_default: false,
        }
    }

    #[test]
    fn renew_preflight_accepts_healthy_near_expiry_and_expired_without_force() {
        for summary in [
            summary(
                LocalIdentityStatus::Ready {
                    expires_at: 1_900_000_000,
                },
                true,
            ),
            summary(
                LocalIdentityStatus::Ready {
                    expires_at: 1_800_000_001,
                },
                true,
            ),
            summary(
                LocalIdentityStatus::Expired {
                    expired_at: 1_700_000_000,
                },
                true,
            ),
        ] {
            let preflight = RenewPreflight::from_summary(&summary, false).unwrap();
            assert_eq!(
                preflight.kind,
                dhttp::certificate::CertificateChainKind::Secondary
            );
            assert_eq!(preflight.sequence, 2);
        }
    }

    #[test]
    fn force_only_recovers_nonready_material_with_certificate_facts() {
        let incomplete = summary(
            LocalIdentityStatus::Incomplete {
                detail: "private key missing".to_string(),
            },
            true,
        );
        let invalid = summary(
            LocalIdentityStatus::Invalid {
                detail: "certificate does not match local key".to_string(),
            },
            true,
        );
        let missing_certificate = summary(
            LocalIdentityStatus::Incomplete {
                detail: "certificate missing".to_string(),
            },
            false,
        );

        assert!(RenewPreflight::from_summary(&incomplete, false).is_err());
        assert!(RenewPreflight::from_summary(&incomplete, true).is_ok());
        assert!(RenewPreflight::from_summary(&invalid, true).is_ok());
        assert!(RenewPreflight::from_summary(&missing_certificate, true).is_err());
    }

    #[test]
    fn missing_chain_error_keeps_server_message_and_appends_apply_hint() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::NOT_FOUND,
            code: "cert_sequence_not_found".to_string(),
            message: "certificate chain was not found".to_string(),
        };
        assert_eq!(
            renew_remote_error(error, "alice.smith").to_string(),
            "certificate chain was not found\nRun `genmeta identity apply alice.smith` to request a new certificate chain."
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
    async fn renew_reports_saved_local_requirement_before_network_or_email() {
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

        assert_eq!(error.to_string(), "Failed to renew: alice.smith not found!");
    }

    #[test]
    fn renewed_success_copy_is_visible_and_stable() {
        assert_eq!(
            super::RENEWED,
            "Identity successfully renewed on this device."
        );
    }
}
