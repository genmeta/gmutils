use dhttp::home::DhttpHome;

use super::{
    local::{self, LocalIdentityStatus, LocalIdentitySummary},
    target::{IdentityLevel, IdentityTarget},
};
use crate::cli::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthCandidate {
    Identity {
        short_name: String,
        full_name: String,
    },
    Email,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthPlan {
    pub(crate) candidates: Vec<AuthCandidate>,
    pub(crate) warnings: Vec<String>,
}

impl AuthPlan {
    pub(crate) fn first_identity_full_name(&self) -> Option<&str> {
        self.candidates
            .iter()
            .find_map(|candidate| match candidate {
                AuthCandidate::Identity { full_name, .. } => Some(full_name.as_str()),
                AuthCandidate::Email => None,
            })
    }
}

fn unavailable_reason(summary: &LocalIdentitySummary) -> String {
    match &summary.status {
        LocalIdentityStatus::Expired { .. } => "its local certificate has expired".to_string(),
        LocalIdentityStatus::Incomplete { detail } => {
            format!("its local identity is incomplete: {detail}")
        }
        LocalIdentityStatus::Invalid { detail } => {
            format!("its local identity is invalid: {detail}")
        }
        LocalIdentityStatus::Ready { .. } => unreachable!("ready identities are available"),
    }
}

pub(crate) fn plan_auth_candidates(
    target: Option<&LocalIdentitySummary>,
    parent: Option<&LocalIdentitySummary>,
) -> AuthPlan {
    let summaries = [target, parent];
    let mut candidates = Vec::new();
    let mut warnings = Vec::new();

    for (index, summary) in summaries.iter().enumerate() {
        let Some(summary) = summary else {
            continue;
        };
        if summary.status.is_ready() {
            candidates.push(AuthCandidate::Identity {
                short_name: summary.target.short_name().to_string(),
                full_name: summary.target.full_name().to_string(),
            });
            continue;
        }

        let next_ready = summaries[index + 1..]
            .iter()
            .flatten()
            .find(|candidate| candidate.status.is_ready());
        let problem = format!(
            "Cannot verify with {} because {}.",
            summary.target.short_name(),
            unavailable_reason(summary),
        );
        let later_saved_candidate_exists = summaries[index + 1..].iter().flatten().next().is_some();
        let warning = match next_ready {
            Some(next) => format!(
                "{problem}\nTrying its parent identity, {}.",
                next.target.short_name()
            ),
            None if later_saved_candidate_exists => problem,
            None => format!("{problem}\nFalling back to email verification."),
        };
        warnings.push(warning);
    }

    candidates.push(AuthCandidate::Email);
    AuthPlan {
        candidates,
        warnings,
    }
}

pub(crate) async fn load_apply_auth_plan(
    dhttp_home: &DhttpHome,
    target: &IdentityTarget,
) -> Result<AuthPlan, Error> {
    let target_summary = local::try_load_summary(dhttp_home, target.dhttp_name(), None).await?;
    let parent_summary = if target.level() == IdentityLevel::SubIdentity {
        match target.parent() {
            Some(parent) => local::try_load_summary(dhttp_home, parent, None).await?,
            None => None,
        }
    } else {
        None
    };
    Ok(plan_auth_candidates(
        target_summary.as_ref(),
        parent_summary.as_ref(),
    ))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::flow::{
        local::{LocalIdentityStatus, LocalIdentitySummary},
        target::IdentityTarget,
    };

    fn summary(name: &str, status: LocalIdentityStatus) -> LocalIdentitySummary {
        LocalIdentitySummary {
            target: IdentityTarget::parse(name).unwrap(),
            certificate_chain: Some("primary:0".to_string()),
            valid_from: Some(1_600_000_000),
            issuer: Some("CN=Genmeta Test CA".to_string()),
            status,
            saved_at: PathBuf::from(format!("/tmp/{name}")),
            is_default: false,
        }
    }

    fn ready(name: &str) -> LocalIdentitySummary {
        summary(
            name,
            LocalIdentityStatus::Ready {
                expires_at: 1_900_000_000,
            },
        )
    }

    #[test]
    fn ready_subidentity_prefers_target_then_parent_then_email() {
        let target = ready("handle.alice.smith");
        let parent = ready("alice.smith");
        let plan = plan_auth_candidates(Some(&target), Some(&parent));

        assert_eq!(
            plan.candidates,
            vec![
                AuthCandidate::Identity {
                    short_name: "handle.alice.smith".into(),
                    full_name: "handle.alice.smith.dhttp.net".into(),
                },
                AuthCandidate::Identity {
                    short_name: "alice.smith".into(),
                    full_name: "alice.smith.dhttp.net".into(),
                },
                AuthCandidate::Email,
            ]
        );
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn expired_target_warns_then_uses_ready_parent() {
        let target = summary(
            "handle.alice.smith",
            LocalIdentityStatus::Expired {
                expired_at: 1_700_000_000,
            },
        );
        let parent = ready("alice.smith");
        let plan = plan_auth_candidates(Some(&target), Some(&parent));

        assert_eq!(
            plan.candidates,
            vec![
                AuthCandidate::Identity {
                    short_name: "alice.smith".into(),
                    full_name: "alice.smith.dhttp.net".into(),
                },
                AuthCandidate::Email,
            ]
        );
        assert_eq!(
            plan.warnings,
            vec![
                "Cannot verify with handle.alice.smith because its local certificate has expired.\nTrying its parent identity, alice.smith."
            ]
        );
    }

    #[test]
    fn invalid_parent_warns_before_email() {
        let parent = summary(
            "alice.smith",
            LocalIdentityStatus::Invalid {
                detail: "certificate does not match local key".into(),
            },
        );
        let plan = plan_auth_candidates(None, Some(&parent));

        assert_eq!(plan.candidates, vec![AuthCandidate::Email]);
        assert_eq!(
            plan.warnings,
            vec![
                "Cannot verify with alice.smith because its local identity is invalid: certificate does not match local key.\nFalling back to email verification."
            ]
        );
    }

    #[test]
    fn unavailable_target_and_parent_explain_each_skip_before_one_email_fallback() {
        let target = summary(
            "phone.alice.smith",
            LocalIdentityStatus::Incomplete {
                detail: "private key missing".into(),
            },
        );
        let parent = summary(
            "alice.smith",
            LocalIdentityStatus::Invalid {
                detail: "certificate is unreadable".into(),
            },
        );

        let plan = plan_auth_candidates(Some(&target), Some(&parent));

        assert_eq!(plan.candidates, vec![AuthCandidate::Email]);
        assert_eq!(
            plan.warnings,
            vec![
                "Cannot verify with phone.alice.smith because its local identity is incomplete: private key missing.",
                "Cannot verify with alice.smith because its local identity is invalid: certificate is unreadable.\nFalling back to email verification.",
            ]
        );
    }

    #[test]
    fn unrelated_default_is_never_a_candidate() {
        let plan = plan_auth_candidates(None, None);
        assert_eq!(plan.candidates, vec![AuthCandidate::Email]);
    }
}
