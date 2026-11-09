use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use dhttp_home::DhttpHome;
use dhttp_identity::{identity::extract_dhttp_subject_key_identifier, name::DhttpName};
use futures::TryStreamExt;
use rustls::pki_types::{CertificateDer, UnixTime};
use tokio::fs;

use super::target::{IdentityLevel, IdentityTarget};
use crate::cli::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocalIdentityMaterialState {
    Present,
    Missing(&'static str),
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalIdentityAssessment {
    pub(crate) certificate: LocalIdentityMaterialState,
    pub(crate) private_key: LocalIdentityMaterialState,
    pub(crate) certificate_target_matches: Option<bool>,
    pub(crate) usage: Option<IdentityUsage>,
    pub(crate) code_signing: Option<bool>,
    pub(crate) sequence: Option<u32>,
    pub(crate) valid_from: Option<i64>,
    pub(crate) expires_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityUsage {
    BothClientAndServer,
    ClientOnly,
}

impl IdentityUsage {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::BothClientAndServer => "clientAuth, serverAuth",
            Self::ClientOnly => "clientAuth",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocalIdentityStatus {
    Ready { expires_at: i64 },
    Expired { expired_at: i64 },
    Incomplete { detail: String },
    Invalid { detail: String },
}

impl LocalIdentityStatus {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Ready { .. } => "ready",
            Self::Expired { .. } => "expired",
            Self::Incomplete { .. } => "incomplete",
            Self::Invalid { .. } => "invalid",
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalIdentitySummary {
    pub(crate) target: IdentityTarget,
    pub(crate) usage: Option<IdentityUsage>,
    pub(crate) code_signing: Option<bool>,
    pub(crate) sequence: Option<u32>,
    pub(crate) valid_from: Option<i64>,
    pub(crate) expires_at: Option<i64>,
    pub(crate) status: LocalIdentityStatus,
    pub(crate) dir: PathBuf,
    pub(crate) is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocalInventoryRoot {
    Saved(LocalIdentitySummary),
    Organization { target: IdentityTarget },
}

impl LocalInventoryRoot {
    fn short_name(&self) -> &str {
        match self {
            Self::Saved(summary) => summary.target.short_name(),
            Self::Organization { target } => target.short_name(),
        }
    }

    fn carries_default(&self, children: &[LocalIdentitySummary]) -> bool {
        match self {
            Self::Saved(summary) => summary.is_default,
            Self::Organization { .. } => children.iter().any(|summary| summary.is_default),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalInventoryGroup {
    pub(crate) root: LocalInventoryRoot,
    pub(crate) children: Vec<LocalIdentitySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalInventory {
    pub(crate) groups: Vec<LocalInventoryGroup>,
}

pub(crate) fn classify_status(
    assessment: &LocalIdentityAssessment,
    now_unix_timestamp: i64,
) -> LocalIdentityStatus {
    match &assessment.certificate {
        LocalIdentityMaterialState::Invalid(detail) => {
            return LocalIdentityStatus::Invalid {
                detail: detail.clone(),
            };
        }
        LocalIdentityMaterialState::Missing(detail) => {
            return LocalIdentityStatus::Incomplete {
                detail: (*detail).to_string(),
            };
        }
        LocalIdentityMaterialState::Present => {}
    }

    match &assessment.private_key {
        LocalIdentityMaterialState::Invalid(detail) => {
            return LocalIdentityStatus::Invalid {
                detail: detail.clone(),
            };
        }
        LocalIdentityMaterialState::Missing(detail) => {
            return LocalIdentityStatus::Incomplete {
                detail: (*detail).to_string(),
            };
        }
        LocalIdentityMaterialState::Present => {}
    }

    if assessment.usage.is_none() || assessment.sequence.is_none() {
        return LocalIdentityStatus::Invalid {
            detail: "certificate chain metadata is invalid".to_string(),
        };
    }
    let Some(expires_at) = assessment.expires_at else {
        return LocalIdentityStatus::Invalid {
            detail: "certificate expiry is unavailable".to_string(),
        };
    };
    let Some(valid_from) = assessment.valid_from else {
        return LocalIdentityStatus::Invalid {
            detail: "certificate validity start is unavailable".to_string(),
        };
    };
    if valid_from > now_unix_timestamp {
        return LocalIdentityStatus::Invalid {
            detail: "certificate is not valid yet".to_string(),
        };
    }

    if expires_at <= now_unix_timestamp {
        LocalIdentityStatus::Expired {
            expired_at: expires_at,
        }
    } else {
        LocalIdentityStatus::Ready { expires_at }
    }
}

pub(crate) fn is_near_expiry(valid_from: i64, expires_at: i64, now: i64) -> bool {
    now < expires_at
        && now
            >= valid_from
                .saturating_add((expires_at.saturating_sub(valid_from).saturating_mul(2)) / 3)
}

pub(crate) fn build_inventory(mut summaries: Vec<LocalIdentitySummary>) -> LocalInventory {
    summaries.sort_by(summary_sort_key);

    #[derive(Default)]
    struct GroupBuilder {
        root: Option<LocalIdentitySummary>,
        children: Vec<LocalIdentitySummary>,
    }

    let mut groups: BTreeMap<String, GroupBuilder> = BTreeMap::new();
    for summary in summaries {
        match summary.target.level() {
            IdentityLevel::Identity => {
                let root_name = summary.target.short_name().to_string();
                groups.entry(root_name).or_default().root = Some(summary);
            }
            IdentityLevel::SubIdentity => {
                let parent = summary
                    .target
                    .parent()
                    .expect("BUG: sub-identity always has a parent");
                groups
                    .entry(parent.as_partial().to_string())
                    .or_default()
                    .children
                    .push(summary);
            }
        }
    }

    let mut built_groups: Vec<LocalInventoryGroup> = groups
        .into_iter()
        .map(|(root_name, mut group)| {
            group.children.sort_by(summary_sort_key);
            let root = match group.root {
                Some(summary) => LocalInventoryRoot::Saved(summary),
                None => LocalInventoryRoot::Organization {
                    target: IdentityTarget::parse(&root_name)
                        .expect("BUG: derived organization root should stay valid"),
                },
            };
            LocalInventoryGroup {
                root,
                children: group.children,
            }
        })
        .collect();

    built_groups.sort_by(|left, right| {
        right
            .root
            .carries_default(&right.children)
            .cmp(&left.root.carries_default(&left.children))
            .then_with(|| left.root.short_name().cmp(right.root.short_name()))
    });

    LocalInventory {
        groups: built_groups,
    }
}

pub(crate) async fn load_inventory(
    dhttp_home: &DhttpHome,
    default_name: Option<DhttpName<'_>>,
) -> Result<LocalInventory, Error> {
    let names = match dhttp_home
        .identity_profile_names()
        .try_collect::<Vec<_>>()
        .await
    {
        Ok(names) => names,
        Err(dhttp_home::identity::ssl::ListIdentityProfilesError::ReadDir { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(LocalInventory { groups: Vec::new() });
        }
        Err(error) => return Err(Error::from(error)),
    };
    let mut summaries = Vec::with_capacity(names.len());
    for name in names {
        summaries.push(
            load_summary_exact(
                dhttp_home,
                DhttpName::try_from(name.as_str()).expect("validated profile name"),
                default_name.clone(),
            )
            .await?,
        );
    }
    Ok(build_inventory(summaries))
}

pub(crate) async fn try_load_summary_exact(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
    default_name: Option<DhttpName<'_>>,
) -> Result<Option<LocalIdentitySummary>, Error> {
    match load_summary_exact(dhttp_home, name, default_name).await {
        Ok(summary) => Ok(Some(summary)),
        Err(Error::ResolveIdentityProfile {
            source: dhttp_home::identity::ssl::ResolveIdentityProfileError::ExactNotFound { .. },
        }) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) async fn load_summary_exact(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
    default_name: Option<DhttpName<'_>>,
) -> Result<LocalIdentitySummary, Error> {
    let target = IdentityTarget::parse(name.as_partial())?;
    let profile = dhttp_home
        .resolve_identity_profile_exactly((name.clone()).as_full())
        .await?;
    let assessment = assess_profile(&profile).await;
    let status = classify_status(&assessment, now_unix_timestamp());

    Ok(LocalIdentitySummary {
        target,
        usage: assessment.usage,
        code_signing: assessment.code_signing,
        sequence: assessment.sequence,
        valid_from: assessment.valid_from,
        expires_at: assessment.expires_at,
        status,
        dir: profile.path().to_path_buf(),
        is_default: default_name
            .as_ref()
            .map(|default| default.as_partial() == name.as_partial())
            .unwrap_or(false),
    })
}

fn summary_sort_key(
    left: &LocalIdentitySummary,
    right: &LocalIdentitySummary,
) -> std::cmp::Ordering {
    right
        .is_default
        .cmp(&left.is_default)
        .then_with(|| left.target.short_name().cmp(right.target.short_name()))
}

pub(crate) fn now_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_secs() as i64
}

async fn assess_profile(
    profile: &dhttp_home::identity::IdentityProfile,
) -> LocalIdentityAssessment {
    let certs = match profile.load_certs().await {
        Ok(certs) => certs,
        Err(error) => {
            return LocalIdentityAssessment {
                certificate: certificate_state_from_error(&error),
                private_key: LocalIdentityMaterialState::Present,
                certificate_target_matches: None,
                usage: None,
                code_signing: None,
                sequence: None,
                valid_from: None,
                expires_at: None,
            };
        }
    };

    let cert_pem = fs::read(
        profile
            .ssl_dir()
            .join(dhttp_home::identity::ssl::CERT_FILE_NAME),
    )
    .await
    .ok();
    let mut assessment = LocalIdentityAssessment {
        certificate: LocalIdentityMaterialState::Present,
        private_key: LocalIdentityMaterialState::Present,
        certificate_target_matches: None,
        usage: None,
        code_signing: None,
        sequence: None,
        valid_from: None,
        expires_at: None,
    };

    match profile.load_key().await {
        Ok(key) => {
            if let Some(cert_pem) = cert_pem.as_deref() {
                match crate::local_identity::private_key_matches_certificate(
                    key.secret_der(),
                    cert_pem,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        assessment.certificate = LocalIdentityMaterialState::Invalid(
                            "certificate does not match local key".to_string(),
                        );
                    }
                    Err(_) => {
                        assessment.certificate = LocalIdentityMaterialState::Invalid(
                            "certificate does not match local key".to_string(),
                        );
                    }
                }
            }
        }
        Err(error) => {
            assessment.private_key = private_key_state_from_error(&error);
        }
    }

    let leaf = match certs.first() {
        Some(leaf) => leaf,
        None => {
            assessment.certificate =
                LocalIdentityMaterialState::Invalid("certificate chain is empty".to_string());
            return assessment;
        }
    };
    match x509_parser::parse_x509_certificate(leaf.as_ref()) {
        Ok((_, certificate)) => {
            assessment.code_signing = certificate
                .extended_key_usage()
                .ok()
                .map(|extension| extension.is_some_and(|eku| eku.value.code_signing));
            assessment.valid_from = Some(certificate.validity().not_before.timestamp());
            assessment.expires_at = Some(certificate.validity().not_after.timestamp());
            let target_matches = certificate
                .subject_alternative_name()
                .ok()
                .flatten()
                .is_some_and(|extension| {
                    extension.value.general_names.iter().any(|name| {
                        matches!(
                            name,
                            x509_parser::extensions::GeneralName::DNSName(candidate)
                                if candidate == &profile.name()
                        )
                    })
                });
            assessment.certificate_target_matches = Some(target_matches);
            if !target_matches {
                assessment.certificate = LocalIdentityMaterialState::Invalid(
                    "certificate target does not match identity profile".to_string(),
                );
            }
        }
        Err(_) => {
            assessment.certificate =
                LocalIdentityMaterialState::Invalid("certificate is unreadable".to_string());
            return assessment;
        }
    }

    match extract_dhttp_subject_key_identifier(&certs) {
        Ok(ski) => {
            assessment.usage = super::kind::IdentityKind::from_ski_flag(
                ski.chain().usage().kind_flag(),
            )
            .map(|kind| match kind {
                super::kind::IdentityKind::Primary => IdentityUsage::BothClientAndServer,
                super::kind::IdentityKind::Secondary => IdentityUsage::ClientOnly,
            });
            assessment.sequence = Some(ski.chain().sequence().get());
        }
        Err(_) => {
            assessment.certificate = LocalIdentityMaterialState::Invalid(
                "certificate chain metadata is invalid".to_string(),
            );
        }
    }

    if matches!(assessment.certificate, LocalIdentityMaterialState::Present)
        && let (Some(valid_from), Some(expires_at)) = (assessment.valid_from, assessment.expires_at)
        && !certificate_chain_is_trusted(&certs, valid_from, expires_at, now_unix_timestamp())
    {
        assessment.certificate =
            LocalIdentityMaterialState::Invalid("certificate chain is not trusted".to_string());
    }

    assessment
}

pub(crate) async fn assess_profile_exact(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
) -> Result<LocalIdentityAssessment, Error> {
    let profile = dhttp_home
        .resolve_identity_profile_exactly((name).as_full())
        .await?;
    Ok(assess_profile(&profile).await)
}

fn certificate_state_from_error(
    error: &dhttp_home::identity::ssl::LoadCertsError,
) -> LocalIdentityMaterialState {
    match error {
        dhttp_home::identity::ssl::LoadCertsError::Read { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            LocalIdentityMaterialState::Missing("certificate missing")
        }
        _ => LocalIdentityMaterialState::Invalid("certificate is unreadable".to_string()),
    }
}

fn private_key_state_from_error(
    error: &dhttp_home::identity::ssl::LoadKeyError,
) -> LocalIdentityMaterialState {
    match error {
        dhttp_home::identity::ssl::LoadKeyError::Metadata { source, .. }
        | dhttp_home::identity::ssl::LoadKeyError::Read { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            LocalIdentityMaterialState::Missing("private key missing")
        }
        _ => LocalIdentityMaterialState::Invalid("private key is invalid".to_string()),
    }
}

fn certificate_chain_is_trusted(
    certs: &[CertificateDer<'_>],
    valid_from: i64,
    expires_at: i64,
    now: i64,
) -> bool {
    let Some(leaf) = certs.first() else {
        return false;
    };
    let Some(verify_at) = trust_check_timestamp(valid_from, expires_at, now) else {
        return false;
    };
    let Ok(verify_at) = u64::try_from(verify_at) else {
        return false;
    };
    dhttp::trust::dhttp_client_cert_verifier(dhttp::trust::ClientIdentityPolicy::Required)
        .verify_client_cert(
            leaf,
            &certs[1..],
            UnixTime::since_unix_epoch(Duration::from_secs(verify_at)),
        )
        .is_ok()
}

fn trust_check_timestamp(valid_from: i64, expires_at: i64, now: i64) -> Option<i64> {
    if expires_at < valid_from {
        return None;
    }
    Some(now.clamp(valid_from, expires_at))
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/local.rs"]
mod tests;

#[cfg(test)]
#[path = "../../../tests/common/cli/flow/local_inventory.rs"]
mod test_support;
#[cfg(test)]
pub(crate) use test_support::{
    InteractiveInventoryChoice, build_default_inventory_choices, build_renew_inventory_choices,
};
