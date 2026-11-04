use std::{collections::VecDeque, path::PathBuf};

use dhttp_home::DhttpHome;
use dhttp_identity::name::DhttpName;

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
        profile_dir: PathBuf,
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

        let profile = match self
            .home
            .resolve_identity_profile_exactly((name).as_full())
            .await
        {
            Ok(profile) => profile,
            Err(dhttp_home::identity::ssl::ResolveIdentityProfileError::ExactNotFound {
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
                            profile_dir: summary.dir,
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

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/auth_plan.rs"]
mod tests;
