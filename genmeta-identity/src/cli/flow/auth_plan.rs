use std::collections::VecDeque;

use dhttp::{home::DhttpHome, name::DhttpName};

use super::{
    local::{self, LocalIdentityStatus, LocalIdentitySummary},
    target::{IdentityLevel, IdentityTarget, RemoteTargetState},
};
use crate::cli::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthCandidateSpec {
    Identity(DhttpName<'static>),
    Email,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CandidateEvent {
    Identity {
        short_name: String,
        full_name: String,
    },
    Warning(String),
    Email,
    Exhausted,
}

pub(crate) fn candidate_specs(
    target: &IdentityTarget,
    remote: RemoteTargetState,
) -> Vec<AuthCandidateSpec> {
    let mut candidates = Vec::new();
    match (target.level(), remote) {
        (IdentityLevel::Identity, RemoteTargetState::Missing) => {}
        (IdentityLevel::SubIdentity, RemoteTargetState::Missing) => {
            if let Some(parent) = target.parent() {
                candidates.push(AuthCandidateSpec::Identity(parent.into_owned()));
            }
        }
        (IdentityLevel::Identity, _) => {
            candidates.push(AuthCandidateSpec::Identity(
                target.dhttp_name().into_owned(),
            ));
        }
        (IdentityLevel::SubIdentity, _) => {
            candidates.push(AuthCandidateSpec::Identity(
                target.dhttp_name().into_owned(),
            ));
            if let Some(parent) = target.parent() {
                candidates.push(AuthCandidateSpec::Identity(parent.into_owned()));
            }
        }
    }
    candidates.push(AuthCandidateSpec::Email);
    candidates
}

pub(crate) trait ExactIdentityLoader {
    async fn load_exact(
        &mut self,
        name: DhttpName<'_>,
    ) -> Result<Option<LocalIdentitySummary>, Error>;
}

pub(crate) struct HomeExactIdentityLoader<'a> {
    home: &'a DhttpHome,
}

impl<'a> HomeExactIdentityLoader<'a> {
    pub(crate) fn new(home: &'a DhttpHome) -> Self {
        Self { home }
    }
}

impl ExactIdentityLoader for HomeExactIdentityLoader<'_> {
    async fn load_exact(
        &mut self,
        name: DhttpName<'_>,
    ) -> Result<Option<LocalIdentitySummary>, Error> {
        let Some(mut summary) =
            local::try_load_summary_exact(self.home, name.clone(), None).await?
        else {
            return Ok(None);
        };
        if !summary.status.is_ready() {
            return Ok(Some(summary));
        }

        let profile = match self.home.resolve_identity_profile_exactly(name).await {
            Ok(profile) => profile,
            Err(dhttp::home::identity::ssl::ResolveIdentityProfileError::ExactNotFound {
                ..
            }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = profile.load_identity().await {
            summary.status = LocalIdentityStatus::Invalid {
                detail: format!("local credentials could not be loaded: {error}"),
            };
        }
        Ok(Some(summary))
    }
}

pub(crate) struct AuthCandidateRunner<L> {
    loader: L,
    pending: VecDeque<AuthCandidateSpec>,
}

impl<L> AuthCandidateRunner<L>
where
    L: ExactIdentityLoader,
{
    pub(crate) fn new(loader: L, candidates: Vec<AuthCandidateSpec>) -> Self {
        Self {
            loader,
            pending: candidates.into(),
        }
    }

    #[cfg(test)]
    pub(crate) fn loader(&self) -> &L {
        &self.loader
    }

    pub(crate) async fn next(&mut self) -> Result<CandidateEvent, Error> {
        loop {
            let Some(candidate) = self.pending.pop_front() else {
                return Ok(CandidateEvent::Exhausted);
            };
            match candidate {
                AuthCandidateSpec::Email => return Ok(CandidateEvent::Email),
                AuthCandidateSpec::Identity(name) => {
                    let Some(summary) = self.loader.load_exact(name.borrow()).await? else {
                        continue;
                    };
                    if summary.status.is_ready() {
                        return Ok(CandidateEvent::Identity {
                            short_name: summary.target.short_name().to_string(),
                            full_name: summary.target.full_name().to_string(),
                        });
                    }
                    return Ok(CandidateEvent::Warning(self.warning_for(&summary)));
                }
            }
        }
    }

    fn warning_for(&self, summary: &LocalIdentitySummary) -> String {
        let reason = match summary.status {
            LocalIdentityStatus::Expired { .. } => "its local certificate has expired",
            LocalIdentityStatus::Incomplete { .. } => "its local identity is incomplete",
            LocalIdentityStatus::Invalid { .. } => "its local identity is invalid",
            LocalIdentityStatus::Ready { .. } => unreachable!("ready identity is usable"),
        };
        let continuation = match self.pending.front() {
            Some(AuthCandidateSpec::Identity(name)) => {
                format!("trying {}", name.as_partial())
            }
            Some(AuthCandidateSpec::Email) | None => {
                "falling back to email verification".to_string()
            }
        };
        format!(
            "WARN: Cannot authenticate with {} because {reason}; {continuation}",
            summary.target.short_name()
        )
    }
}

pub(crate) async fn first_auth_candidate(
    dhttp_home: &DhttpHome,
    target: &IdentityTarget,
    remote: RemoteTargetState,
) -> Result<CandidateEvent, Error> {
    let mut runner = AuthCandidateRunner::new(
        HomeExactIdentityLoader::new(dhttp_home),
        candidate_specs(target, remote),
    );
    loop {
        match runner.next().await? {
            CandidateEvent::Warning(warning) => {
                super::transcript::print_warning(&warning);
            }
            selected => return Ok(selected),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use super::*;
    use crate::cli::flow::local::{IdentityUsage, LocalIdentityStatus};

    fn identity(name: &str) -> AuthCandidateSpec {
        AuthCandidateSpec::Identity(DhttpName::try_from(name).unwrap().into_owned())
    }

    fn email() -> AuthCandidateSpec {
        AuthCandidateSpec::Email
    }

    #[test]
    fn candidate_orders_cover_existing_and_missing_root_and_child() {
        let root = IdentityTarget::parse("alice.smith").unwrap();
        let child = IdentityTarget::parse("phone.alice.smith").unwrap();
        assert_eq!(
            candidate_specs(&root, RemoteTargetState::Exists),
            vec![identity("alice.smith"), email()]
        );
        assert_eq!(
            candidate_specs(&child, RemoteTargetState::Exists),
            vec![
                identity("phone.alice.smith"),
                identity("alice.smith"),
                email()
            ]
        );
        assert_eq!(
            candidate_specs(&root, RemoteTargetState::Missing),
            vec![email()]
        );
        assert_eq!(
            candidate_specs(&child, RemoteTargetState::Missing),
            vec![identity("alice.smith"), email()]
        );
    }

    fn summary(name: &str, status: LocalIdentityStatus) -> LocalIdentitySummary {
        LocalIdentitySummary {
            target: IdentityTarget::parse(name).unwrap(),
            usage: Some(IdentityUsage::BothClientAndServer),
            sequence: Some(0),
            valid_from: Some(1_600_000_000),
            expires_at: Some(1_900_000_000),
            status,
            dir: PathBuf::from(format!("/tmp/{name}")),
            is_default: false,
        }
    }

    #[derive(Default)]
    struct FakeExactLoader {
        summaries: BTreeMap<String, LocalIdentitySummary>,
        requested: Vec<String>,
    }

    impl FakeExactLoader {
        fn with(summaries: impl IntoIterator<Item = LocalIdentitySummary>) -> Self {
            Self {
                summaries: summaries
                    .into_iter()
                    .map(|summary| (summary.target.short_name().to_string(), summary))
                    .collect(),
                requested: Vec::new(),
            }
        }

        fn requested(&self) -> &[String] {
            &self.requested
        }
    }

    impl ExactIdentityLoader for FakeExactLoader {
        async fn load_exact(
            &mut self,
            name: DhttpName<'_>,
        ) -> Result<Option<LocalIdentitySummary>, Error> {
            self.requested.push(name.as_partial().to_string());
            Ok(self.summaries.get(name.as_partial()).cloned())
        }
    }

    #[tokio::test]
    async fn successful_current_identity_never_loads_parent_or_email() {
        let ready = |name| {
            summary(
                name,
                LocalIdentityStatus::Ready {
                    expires_at: 1_900_000_000,
                },
            )
        };
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        let loader = FakeExactLoader::with([ready("phone.alice.smith"), ready("alice.smith")]);
        let mut runner =
            AuthCandidateRunner::new(loader, candidate_specs(&target, RemoteTargetState::Exists));

        assert!(matches!(
            runner.next().await.unwrap(),
            CandidateEvent::Identity { short_name, .. } if short_name == "phone.alice.smith"
        ));
        assert_eq!(runner.loader().requested(), ["phone.alice.smith"]);
    }

    #[tokio::test]
    async fn abnormal_candidates_warn_only_when_visited() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        let loader = FakeExactLoader::with([
            summary(
                "phone.alice.smith",
                LocalIdentityStatus::Expired {
                    expired_at: 1_700_000_000,
                },
            ),
            summary(
                "alice.smith",
                LocalIdentityStatus::Incomplete {
                    detail: "private key is missing".to_string(),
                },
            ),
        ]);
        let mut runner =
            AuthCandidateRunner::new(loader, candidate_specs(&target, RemoteTargetState::Exists));

        assert_eq!(
            runner.next().await.unwrap(),
            CandidateEvent::Warning(
                "WARN: Cannot authenticate with phone.alice.smith because its local certificate has expired; trying alice.smith".to_string()
            )
        );
        assert_eq!(runner.loader().requested(), ["phone.alice.smith"]);
        assert_eq!(
            runner.next().await.unwrap(),
            CandidateEvent::Warning(
                "WARN: Cannot authenticate with alice.smith because its local identity is incomplete; falling back to email verification".to_string()
            )
        );
        assert_eq!(
            runner.loader().requested(),
            ["phone.alice.smith", "alice.smith"]
        );
        assert_eq!(runner.next().await.unwrap(), CandidateEvent::Email);
    }

    #[tokio::test]
    async fn missing_candidates_advance_silently() {
        let target = IdentityTarget::parse("phone.alice.smith").unwrap();
        let mut runner = AuthCandidateRunner::new(
            FakeExactLoader::default(),
            candidate_specs(&target, RemoteTargetState::Exists),
        );

        assert_eq!(runner.next().await.unwrap(), CandidateEvent::Email);
        assert_eq!(
            runner.loader().requested(),
            ["phone.alice.smith", "alice.smith"]
        );
    }
}
