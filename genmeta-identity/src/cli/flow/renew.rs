use std::{io::IsTerminal, path::Path};

use dhttp_home::{DhttpHome, HomeScope};
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
#[path = "../../../tests/unit/cli/flow/renew.rs"]
mod tests;
