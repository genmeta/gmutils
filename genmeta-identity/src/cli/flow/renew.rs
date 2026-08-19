use std::{io::IsTerminal, path::Path};

use dhttp::home::{DhttpHome, HomeScope};
use snafu::{FromString, whatever};

use super::{auth_plan::CandidateEvent, local};
use crate::{
    cert_server::{CertServer, CertificateDetail, CertificateRenewalRequest},
    cli::{Error, Renew},
};

const RENEWED: &str = "✔ Identity successfully renewed on this device.";
const RENEWAL_THRESHOLD_SECONDS: i64 = 15 * 24 * 60 * 60;

fn renew_not_saved_root_message(short_name: &str) -> String {
    format!("Failed to renew: {short_name} not found!")
}

fn renewal_is_due(expires_at: Option<i64>, now: i64) -> bool {
    match expires_at {
        Some(expires_at) => expires_at.saturating_sub(now) < RENEWAL_THRESHOLD_SECONDS,
        None => true,
    }
}

fn renew_not_due_message(short_name: &str, expires_at: i64, now: i64) -> String {
    let days_left = expires_at.saturating_sub(now) / (24 * 60 * 60);
    let day_label = if days_left == 1 { "day" } else { "days" };
    format!("Renewal skipped: {short_name} is valid for {days_left} more {day_label}.")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RenewPreflight {
    target: super::target::IdentityTarget,
    kind: super::kind::IdentityKind,
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
            Some(local::IdentityUsage::BothClientAndServer) => super::kind::IdentityKind::Primary,
            Some(local::IdentityUsage::ClientOnly) => super::kind::IdentityKind::Secondary,
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
            Some(local::IdentityUsage::BothClientAndServer) => super::kind::IdentityKind::Primary,
            Some(local::IdentityUsage::ClientOnly) => super::kind::IdentityKind::Secondary,
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

    fn certificate_kind(&self) -> &'static str {
        self.kind.as_str()
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
    identity: Option<&str>,
) -> Result<(RenewPreflight, Option<i64>), Error> {
    let domain = match identity {
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
    Ok((preflight, summary.expires_at))
}

#[derive(Debug, Clone, Copy)]
enum RenewProof<'a> {
    AccessToken(&'a str),
    IdentityProfile(&'a Path),
}

#[derive(Debug)]
enum RequestFailure {
    Remote(crate::cert_server::Error),
}

async fn request_renewal(
    cert_server: &CertServer,
    proof: RenewProof<'_>,
    preflight: &RenewPreflight,
    pending: &super::key_material::PendingRenewal,
) -> Result<CertificateDetail, RequestFailure> {
    super::progress::run(super::progress::RENEW_IDENTITY, async {
        let result = match proof {
            RenewProof::AccessToken(token) => {
                let request = CertificateRenewalRequest::new(
                    preflight.target.full_name(),
                    preflight.certificate_kind(),
                    preflight.sequence,
                    Some(pending.device_name()),
                    pending.csr_pem(),
                )
                .with_idempotency_key(pending.operation_key());
                cert_server.renew_cert_request(token, request).await
            }
            RenewProof::IdentityProfile(profile_dir) => {
                let request = CertificateRenewalRequest::new(
                    preflight.target.full_name(),
                    preflight.certificate_kind(),
                    preflight.sequence,
                    Some(pending.device_name()),
                    pending.csr_pem(),
                )
                .with_idempotency_key(pending.operation_key());
                cert_server
                    .renew_cert_with_identity_profile_request(profile_dir, request)
                    .await
            }
        };
        result.map_err(RequestFailure::Remote)
    })
    .await
}

fn renew_remote_error(error: crate::cert_server::Error, target: &str) -> Error {
    if error.is_api(reqwest::StatusCode::NOT_FOUND, "cert_sequence_not_found") {
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

#[cfg(any(unix, test))]
fn stops_automatic_renewal(error: &crate::cert_server::Error) -> bool {
    matches!(error.api_code(), Some("domain_expired" | "domain_revoked"))
}

async fn handle_renew_remote_error(
    error: crate::cert_server::Error,
    preflight: &RenewPreflight,
    dhttp_home: &DhttpHome,
) -> Error {
    #[cfg(not(unix))]
    let _ = dhttp_home;
    #[cfg(unix)]
    if stops_automatic_renewal(&error)
        && let Err(disable_error) = super::auto_renew::disable_identity(
            dhttp_home,
            preflight.target.dhttp_name(),
            error.api_code().unwrap_or("terminal-domain-state"),
        )
        .await
    {
        super::transcript::print_warning(&format!(
            "Automatic certificate renewal could not be disabled for {}: {disable_error}",
            preflight.target.short_name()
        ));
    }
    renew_remote_error(error, preflight.target.short_name())
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
    interactive: bool,
    pending: &super::key_material::PendingRenewal,
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
                profile_dir,
                ..
            } => match request_renewal(
                cert_server,
                RenewProof::IdentityProfile(&profile_dir),
                preflight,
                pending,
            )
            .await
            {
                Ok(detail) => return Ok(detail),
                Err(RequestFailure::Remote(error))
                    if crate::auth::classify_identity_attempt(&error)
                        == crate::auth::AuthAttemptDisposition::TryNext =>
                {
                    print_auth_rejection(&short_name, &error);
                    last_rejection = Some(error);
                }
                Err(RequestFailure::Remote(error)) => {
                    return Err(handle_renew_remote_error(error, preflight, dhttp_home).await);
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
                    pending,
                )
                .await
                {
                    Ok(detail) => Ok(detail),
                    Err(RequestFailure::Remote(error)) => {
                        Err(handle_renew_remote_error(error, preflight, dhttp_home).await)
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

async fn ensure_automatic_renewal(home_scope: HomeScope) {
    #[cfg(all(unix, not(test)))]
    if let Err(error) = super::auto_renew::ensure_schedule(home_scope).await {
        super::transcript::print_warning(&format!(
            "Automatic certificate renewal could not be scheduled: {error}"
        ));
    }
    #[cfg(any(not(unix), test))]
    let _ = home_scope;
}

async fn enable_automatic_renewal(dhttp_home: &DhttpHome, preflight: &RenewPreflight) {
    #[cfg(unix)]
    if let Err(error) =
        super::auto_renew::enable_identity(dhttp_home, preflight.target.dhttp_name()).await
    {
        super::transcript::print_warning(&format!(
            "Automatic certificate renewal could not be enabled for {}: {error}",
            preflight.target.short_name()
        ));
    }
    #[cfg(not(unix))]
    let _ = (dhttp_home, preflight);
}

async fn renew_one(
    command: &Renew,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
    preflight: RenewPreflight,
    expires_at: Option<i64>,
    interactive: bool,
) -> Result<(), Error> {
    let now = local::now_unix_timestamp();
    let existing_pending = super::key_material::PendingRenewal::load(
        dhttp_home,
        preflight.target.dhttp_name(),
        preflight.certificate_kind(),
        preflight.sequence,
    )
    .await?;
    if existing_pending.is_none() && !command.force && !renewal_is_due(expires_at, now) {
        super::transcript::print_line(renew_not_due_message(
            preflight.target.short_name(),
            expires_at.expect("renewal is not due only when expiry is known"),
            now,
        ));
        enable_automatic_renewal(dhttp_home, &preflight).await;
        return Ok(());
    }
    let device_name =
        super::device::resolve_device_name(command.device_name.as_deref(), home_scope);
    let pending = match existing_pending {
        Some(pending) => pending,
        None => {
            super::key_material::PendingRenewal::create(
                dhttp_home,
                preflight.target.dhttp_name(),
                preflight.certificate_kind(),
                preflight.sequence,
                &device_name,
            )
            .await?
        }
    };
    let detail = request_with_candidates(
        command,
        dhttp_home,
        cert_server,
        &preflight,
        interactive,
        &pending,
    )
    .await?;
    super::install::validate_and_save(
        dhttp_home,
        &detail,
        &super::install::InstallExpectation {
            target: preflight.target.dhttp_name(),
            kind: preflight.kind,
            sequence: Some(preflight.sequence),
        },
        pending.key_pem(),
        dhttp::log::cert::CertificateAction::Renew,
    )
    .await?;
    if let Err(error) = pending
        .remove(dhttp_home, preflight.target.dhttp_name())
        .await
    {
        tracing::warn!(
            identity = %preflight.target.full_name(),
            error = %snafu::Report::from_error(&error),
            "failed to remove installed renewal material"
        );
    }
    enable_automatic_renewal(dhttp_home, &preflight).await;
    super::transcript::print_line(RENEWED);
    Ok(())
}

fn inventory_targets(inventory: local::LocalInventory) -> Vec<super::target::IdentityTarget> {
    let mut targets = Vec::new();
    for group in inventory.groups {
        if let local::LocalInventoryRoot::Saved(summary) = group.root {
            targets.push(summary.target);
        }
        targets.extend(group.children.into_iter().map(|summary| summary.target));
    }
    targets
}

async fn renew_all(
    command: &Renew,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
) -> Result<(), Error> {
    let inventory = local::load_inventory(dhttp_home, None).await?;
    let targets = inventory_targets(inventory);
    if targets.is_empty() {
        super::transcript::print_line("No identities found here");
        return Ok(());
    }

    ensure_automatic_renewal(home_scope).await;
    let interactive = std::io::stdin().is_terminal();
    let total = targets.len();
    let mut failures = 0;

    for target in targets {
        #[cfg(unix)]
        match super::auto_renew::is_identity_enabled(dhttp_home, target.dhttp_name()).await {
            Ok(false) => {
                super::transcript::print_line(format!(
                    "Renewal skipped: automatic renewal is disabled for {}.",
                    target.short_name()
                ));
                continue;
            }
            Ok(true) => {}
            Err(error) => {
                failures += 1;
                super::transcript::print_warning(&format!(
                    "Could not inspect automatic renewal state for {}: {error}",
                    target.short_name()
                ));
                continue;
            }
        }

        let result = async {
            let (preflight, expires_at) =
                resolve_preflight(command, dhttp_home, Some(target.short_name())).await?;
            renew_one(
                command,
                dhttp_home,
                home_scope,
                cert_server,
                preflight,
                expires_at,
                interactive,
            )
            .await
        }
        .await;
        if let Err(error) = result {
            failures += 1;
            super::transcript::print_warning(&format!(
                "Renewal failed for {}: {error}",
                target.short_name()
            ));
        }
    }

    if failures > 0 {
        return Err(Error::without_source(format!(
            "Failed to renew {failures} of {total} identities."
        )));
    }
    Ok(())
}

pub(crate) async fn run(
    command: &Renew,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
) -> Result<(), Error> {
    if command.all {
        return renew_all(command, dhttp_home, home_scope, cert_server).await;
    }
    let (preflight, expires_at) =
        resolve_preflight(command, dhttp_home, command.name.as_deref()).await?;
    ensure_automatic_renewal(home_scope).await;
    renew_one(
        command,
        dhttp_home,
        home_scope,
        cert_server,
        preflight,
        expires_at,
        std::io::stdin().is_terminal(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use dhttp::home::{DhttpHome, HomeScope};

    use super::{
        RenewPreflight, inventory_targets, renew_not_due_message, renew_not_saved_root_message,
        renew_remote_error, renewal_is_due, stops_automatic_renewal,
    };
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
    fn renewal_is_due_only_within_fifteen_days_or_when_expiry_is_unknown() {
        const DAY: i64 = 24 * 60 * 60;
        let now = 1_800_000_000;

        assert!(renewal_is_due(None, now));
        assert!(renewal_is_due(Some(now - 1), now));
        assert!(renewal_is_due(Some(now + 15 * DAY - 1), now));
        assert!(!renewal_is_due(Some(now + 15 * DAY), now));
        assert!(!renewal_is_due(Some(now + 30 * DAY), now));
    }

    #[test]
    fn batch_targets_follow_the_deterministic_inventory_order() {
        let alice = summary(
            LocalIdentityStatus::Ready {
                expires_at: 1_900_000_000,
            },
            true,
        );
        let mut bob = alice.clone();
        bob.target = IdentityTarget::parse("bob.smith").unwrap();
        let inventory = crate::cli::flow::local::build_inventory(vec![bob, alice]);

        let names = inventory_targets(inventory)
            .into_iter()
            .map(|target| target.short_name().to_string())
            .collect::<Vec<_>>();
        assert_eq!(names, ["alice.smith", "bob.smith"]);
    }

    #[test]
    fn not_due_message_reports_remaining_days_and_force_hint() {
        const DAY: i64 = 24 * 60 * 60;
        let now = 1_800_000_000;

        assert_eq!(
            renew_not_due_message("alice.smith", now + 20 * DAY, now),
            "Renewal skipped: alice.smith is valid for 20 more days."
        );
        assert_eq!(
            renew_not_due_message("alice.smith", now + 15 * DAY, now),
            "Renewal skipped: alice.smith is valid for 15 more days."
        );
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
                crate::cli::flow::kind::IdentityKind::Secondary
            );
            assert_eq!(preflight.sequence, 2);
        }
    }

    #[test]
    fn renew_maps_certificate_usage_to_server_kind() {
        let mut primary = summary(
            LocalIdentityStatus::Ready {
                expires_at: 1_900_000_000,
            },
            true,
        );
        primary.usage = Some(IdentityUsage::BothClientAndServer);
        let primary = RenewPreflight::from_summary(&primary, false).unwrap();
        assert_eq!(primary.certificate_kind(), "primary");

        let secondary = RenewPreflight::from_summary(
            &summary(
                LocalIdentityStatus::Ready {
                    expires_at: 1_900_000_000,
                },
                true,
            ),
            false,
        )
        .unwrap();
        assert_eq!(secondary.certificate_kind(), "secondary");
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
    fn server_failure_with_reused_code_does_not_offer_apply_recovery() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            code: "cert_sequence_not_found".to_string(),
            message: "internal server error".to_string(),
        };

        assert_eq!(
            renew_remote_error(error, "alice.smith").to_string(),
            "internal server error"
        );
    }

    #[test]
    fn expired_and_revoked_domains_stop_automatic_renewal() {
        for code in ["domain_expired", "domain_revoked", "1212", "1213"] {
            let error = crate::cert_server::Error::Api {
                status: reqwest::StatusCode::CONFLICT,
                code: code.to_string(),
                message: "terminal domain state".to_string(),
            };
            assert!(stops_automatic_renewal(&error), "code {code}");
        }

        let retryable = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::CONFLICT,
            code: "certificate_renewal_not_due".to_string(),
            message: "renewal is not due".to_string(),
        };
        assert!(!stops_automatic_renewal(&retryable));
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
            all: false,
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
            "✔ Identity successfully renewed on this device."
        );
    }
}
