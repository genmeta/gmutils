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
        code_signing: None,
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
        CandidateEvent::Identity {
            short_name,
            profile_dir,
            ..
        } if short_name == "phone.alice.smith"
            && profile_dir == std::path::Path::new("/tmp/phone.alice.smith")
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

impl<L: super::ExactIdentityLoader> super::AuthCandidateRunner<L> {
    pub(crate) fn loader(&self) -> &L {
        &self.loader
    }
}
