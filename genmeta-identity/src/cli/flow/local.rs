use std::{collections::BTreeMap, path::PathBuf};

use dhttp::{home::DhttpHome, identity::extract_dhttp_subject_key_identifier, name::DhttpName};
use futures::TryStreamExt;
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
    pub(crate) certificate_chain: Option<String>,
    pub(crate) expires_at: Option<i64>,
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
    pub(crate) certificate_chain: Option<String>,
    pub(crate) status: LocalIdentityStatus,
    pub(crate) saved_at: PathBuf,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InteractiveInventoryChoice {
    Saved(LocalIdentitySummary),
    Organization { target: IdentityTarget },
    EnterAnotherIdentity,
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

    let Some(_) = assessment.certificate_chain.as_ref() else {
        return LocalIdentityStatus::Invalid {
            detail: "certificate chain metadata is invalid".to_string(),
        };
    };
    let Some(expires_at) = assessment.expires_at else {
        return LocalIdentityStatus::Invalid {
            detail: "certificate expiry is unavailable".to_string(),
        };
    };

    if expires_at <= now_unix_timestamp {
        LocalIdentityStatus::Expired {
            expired_at: expires_at,
        }
    } else {
        LocalIdentityStatus::Ready { expires_at }
    }
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
    let names = dhttp_home
        .identity_profile_names()
        .try_collect::<Vec<_>>()
        .await?;
    let mut summaries = Vec::with_capacity(names.len());
    for name in names {
        summaries.push(load_summary(dhttp_home, name.borrow(), default_name.clone()).await?);
    }
    Ok(build_inventory(summaries))
}

pub(crate) async fn load_summary(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
    default_name: Option<DhttpName<'_>>,
) -> Result<LocalIdentitySummary, Error> {
    let target = IdentityTarget::parse(name.as_partial())?;
    let profile = dhttp_home.resolve_identity_profile(name.clone()).await?;
    let assessment = assess_profile(&profile).await;
    let status = classify_status(&assessment, now_unix_timestamp());

    Ok(LocalIdentitySummary {
        target,
        certificate_chain: assessment.certificate_chain,
        status,
        saved_at: profile.path().to_path_buf(),
        is_default: default_name
            .as_ref()
            .map(|default| default.as_partial() == name.as_partial())
            .unwrap_or(false),
    })
}

pub(crate) fn build_apply_inventory_choices(
    inventory: &LocalInventory,
) -> Vec<InteractiveInventoryChoice> {
    let mut choices = Vec::new();
    for group in &inventory.groups {
        match &group.root {
            LocalInventoryRoot::Saved(summary) => {
                choices.push(InteractiveInventoryChoice::Saved(summary.clone()));
            }
            LocalInventoryRoot::Organization { target } => {
                choices.push(InteractiveInventoryChoice::Organization {
                    target: target.clone(),
                });
            }
        }
        choices.extend(
            group
                .children
                .iter()
                .cloned()
                .map(InteractiveInventoryChoice::Saved),
        );
    }
    choices.push(InteractiveInventoryChoice::EnterAnotherIdentity);
    choices
}

pub(crate) fn build_renew_inventory_choices(
    inventory: &LocalInventory,
) -> Vec<InteractiveInventoryChoice> {
    let mut choices = Vec::new();
    for group in &inventory.groups {
        match &group.root {
            LocalInventoryRoot::Saved(summary) => {
                choices.push(InteractiveInventoryChoice::Saved(summary.clone()));
            }
            LocalInventoryRoot::Organization { target } => {
                choices.push(InteractiveInventoryChoice::Organization {
                    target: target.clone(),
                });
            }
        }
        choices.extend(
            group
                .children
                .iter()
                .cloned()
                .map(InteractiveInventoryChoice::Saved),
        );
    }
    choices
}

pub(crate) fn build_default_inventory_choices(
    inventory: &LocalInventory,
) -> Vec<InteractiveInventoryChoice> {
    let mut choices = Vec::new();
    for group in &inventory.groups {
        match &group.root {
            LocalInventoryRoot::Saved(summary) => {
                choices.push(InteractiveInventoryChoice::Saved(summary.clone()));
            }
            LocalInventoryRoot::Organization { target } => {
                choices.push(InteractiveInventoryChoice::Organization {
                    target: target.clone(),
                });
            }
        }
        choices.extend(
            group
                .children
                .iter()
                .cloned()
                .map(InteractiveInventoryChoice::Saved),
        );
    }
    choices
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

fn now_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_secs() as i64
}

async fn assess_profile(
    profile: &dhttp::home::identity::IdentityProfile,
) -> LocalIdentityAssessment {
    let certs = match profile.load_certs().await {
        Ok(certs) => certs,
        Err(error) => {
            return LocalIdentityAssessment {
                certificate: certificate_state_from_error(&error),
                private_key: LocalIdentityMaterialState::Present,
                certificate_chain: None,
                expires_at: None,
            };
        }
    };

    let cert_pem = fs::read(
        profile
            .ssl_dir()
            .join(dhttp::home::identity::ssl::CERT_FILE_NAME),
    )
    .await
    .ok();
    let mut assessment = LocalIdentityAssessment {
        certificate: LocalIdentityMaterialState::Present,
        private_key: LocalIdentityMaterialState::Present,
        certificate_chain: None,
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
            assessment.expires_at = Some(certificate.validity().not_after.timestamp());
        }
        Err(_) => {
            assessment.certificate =
                LocalIdentityMaterialState::Invalid("certificate is unreadable".to_string());
            return assessment;
        }
    }

    match extract_dhttp_subject_key_identifier(&certs) {
        Ok(ski) => {
            assessment.certificate_chain = Some(ski.chain().to_string());
        }
        Err(_) => {
            assessment.certificate = LocalIdentityMaterialState::Invalid(
                "certificate chain metadata is invalid".to_string(),
            );
        }
    }

    assessment
}

fn certificate_state_from_error(
    error: &dhttp::home::identity::ssl::LoadCertsError,
) -> LocalIdentityMaterialState {
    match error {
        dhttp::home::identity::ssl::LoadCertsError::Read { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            LocalIdentityMaterialState::Missing("certificate missing")
        }
        _ => LocalIdentityMaterialState::Invalid("certificate is unreadable".to_string()),
    }
}

fn private_key_state_from_error(
    error: &dhttp::home::identity::ssl::LoadKeyError,
) -> LocalIdentityMaterialState {
    match error {
        dhttp::home::identity::ssl::LoadKeyError::Metadata { source, .. }
        | dhttp::home::identity::ssl::LoadKeyError::Read { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            LocalIdentityMaterialState::Missing("private key missing")
        }
        _ => LocalIdentityMaterialState::Invalid("private key is invalid".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        InteractiveInventoryChoice, LocalIdentityAssessment, LocalIdentityMaterialState,
        LocalIdentityStatus, LocalIdentitySummary, LocalInventoryRoot,
        build_apply_inventory_choices, build_default_inventory_choices, build_inventory,
        build_renew_inventory_choices, classify_status,
    };
    use crate::cli::flow::target::IdentityTarget;

    const NOW: i64 = 1_794_298_000;

    fn ready_summary(name: &str, is_default: bool, chain: &str) -> LocalIdentitySummary {
        LocalIdentitySummary {
            target: IdentityTarget::parse(name).unwrap(),
            certificate_chain: Some(chain.to_string()),
            status: LocalIdentityStatus::Ready {
                expires_at: NOW + 300,
            },
            saved_at: PathBuf::from(format!("/tmp/{name}")),
            is_default,
        }
    }

    #[test]
    fn classifies_ready_expired_incomplete_and_invalid() {
        let ready = classify_status(
            &LocalIdentityAssessment {
                certificate: LocalIdentityMaterialState::Present,
                private_key: LocalIdentityMaterialState::Present,
                certificate_chain: Some("primary:0".to_string()),
                expires_at: Some(NOW + 300),
            },
            NOW,
        );
        assert_eq!(
            ready,
            LocalIdentityStatus::Ready {
                expires_at: NOW + 300,
            }
        );

        let expired = classify_status(
            &LocalIdentityAssessment {
                certificate: LocalIdentityMaterialState::Present,
                private_key: LocalIdentityMaterialState::Present,
                certificate_chain: Some("secondary:2".to_string()),
                expires_at: Some(NOW - 1),
            },
            NOW,
        );
        assert_eq!(
            expired,
            LocalIdentityStatus::Expired {
                expired_at: NOW - 1,
            }
        );

        let incomplete = classify_status(
            &LocalIdentityAssessment {
                certificate: LocalIdentityMaterialState::Present,
                private_key: LocalIdentityMaterialState::Missing("private key missing"),
                certificate_chain: Some("secondary:3".to_string()),
                expires_at: Some(NOW + 300),
            },
            NOW,
        );
        assert_eq!(
            incomplete,
            LocalIdentityStatus::Incomplete {
                detail: "private key missing".to_string(),
            }
        );

        let invalid = classify_status(
            &LocalIdentityAssessment {
                certificate: LocalIdentityMaterialState::Invalid(
                    "certificate does not match local key".to_string(),
                ),
                private_key: LocalIdentityMaterialState::Present,
                certificate_chain: Some("secondary:4".to_string()),
                expires_at: Some(NOW + 300),
            },
            NOW,
        );
        assert_eq!(
            invalid,
            LocalIdentityStatus::Invalid {
                detail: "certificate does not match local key".to_string(),
            }
        );
    }

    #[test]
    fn builds_inventory_with_saved_and_organization_roots() {
        let mut tv = ready_summary("tv.alice.smith", false, "secondary:3");
        tv.status = LocalIdentityStatus::Incomplete {
            detail: "private key missing".to_string(),
        };
        tv.certificate_chain = None;

        let inventory = build_inventory(vec![
            ready_summary("tablet.reimu.scarlet", false, "secondary:1"),
            tv,
            ready_summary("phone.alice.smith", false, "secondary:2"),
            ready_summary("alice.smith", true, "primary:0"),
        ]);

        match &inventory.groups[0].root {
            LocalInventoryRoot::Saved(summary) => {
                assert_eq!(summary.target.short_name(), "alice.smith");
                assert!(summary.is_default);
            }
            other => panic!("expected saved root, got {other:?}"),
        }
        assert_eq!(inventory.groups[0].children.len(), 2);
        assert_eq!(
            inventory.groups[0].children[0].target.short_name(),
            "phone.alice.smith"
        );
        assert_eq!(
            inventory.groups[0].children[1].target.short_name(),
            "tv.alice.smith"
        );

        match &inventory.groups[1].root {
            LocalInventoryRoot::Organization { target } => {
                assert_eq!(target.short_name(), "reimu.scarlet");
            }
            other => panic!("expected organization root, got {other:?}"),
        }
        assert_eq!(inventory.groups[1].children.len(), 1);
        assert_eq!(
            inventory.groups[1].children[0].target.short_name(),
            "tablet.reimu.scarlet"
        );
    }

    #[test]
    fn builds_apply_inventory_choices_with_organization_root_and_enter_another_identity() {
        let mut tv = ready_summary("tv.alice.smith", false, "secondary:3");
        tv.status = LocalIdentityStatus::Incomplete {
            detail: "private key missing".to_string(),
        };
        tv.certificate_chain = None;

        let inventory = build_inventory(vec![
            ready_summary("tablet.reimu.scarlet", false, "secondary:1"),
            tv.clone(),
            ready_summary("phone.alice.smith", false, "secondary:2"),
        ]);

        assert_eq!(
            build_apply_inventory_choices(&inventory),
            vec![
                InteractiveInventoryChoice::Organization {
                    target: IdentityTarget::parse("alice.smith").unwrap(),
                },
                InteractiveInventoryChoice::Saved(ready_summary(
                    "phone.alice.smith",
                    false,
                    "secondary:2",
                )),
                InteractiveInventoryChoice::Saved(tv),
                InteractiveInventoryChoice::Organization {
                    target: IdentityTarget::parse("reimu.scarlet").unwrap(),
                },
                InteractiveInventoryChoice::Saved(ready_summary(
                    "tablet.reimu.scarlet",
                    false,
                    "secondary:1",
                )),
                InteractiveInventoryChoice::EnterAnotherIdentity,
            ]
        );
    }

    #[test]
    fn build_renew_inventory_choices_keeps_missing_parent_roots() {
        let child = ready_summary("shanghai.alice.ma", false, "secondary:1");
        let inventory = build_inventory(vec![child.clone()]);

        assert_eq!(
            build_renew_inventory_choices(&inventory),
            vec![
                InteractiveInventoryChoice::Organization {
                    target: IdentityTarget::parse("alice.ma").unwrap(),
                },
                InteractiveInventoryChoice::Saved(child),
            ]
        );
    }

    #[test]
    fn builds_default_inventory_choices_with_organization_roots_without_enter_another_identity() {
        let inventory = build_inventory(vec![
            ready_summary("phone.alice.smith", false, "secondary:2"),
            ready_summary("tablet.reimu.scarlet", false, "secondary:1"),
        ]);

        assert_eq!(
            build_default_inventory_choices(&inventory),
            vec![
                InteractiveInventoryChoice::Organization {
                    target: IdentityTarget::parse("alice.smith").unwrap(),
                },
                InteractiveInventoryChoice::Saved(ready_summary(
                    "phone.alice.smith",
                    false,
                    "secondary:2",
                )),
                InteractiveInventoryChoice::Organization {
                    target: IdentityTarget::parse("reimu.scarlet").unwrap(),
                },
                InteractiveInventoryChoice::Saved(ready_summary(
                    "tablet.reimu.scarlet",
                    false,
                    "secondary:1",
                )),
            ]
        );
    }
}
