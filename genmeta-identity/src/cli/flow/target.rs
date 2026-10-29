use std::fmt;

use dhttp_identity::name::{DhttpName, InvalidDhttpName};
use snafu::{ResultExt, Snafu};

use super::local::{LocalIdentityStatus, LocalIdentitySummary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteTargetState {
    Unknown,
    Exists,
    Missing,
    Unavailable,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedApplyTarget {
    pub(crate) target: IdentityTarget,
    pub(crate) remote: RemoteTargetState,
    pub(crate) local: Option<LocalIdentitySummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplacementRequirement {
    None,
    Confirm,
}

#[derive(Debug, Snafu)]
#[snafu(display("cert server returned unsupported domain availability: {availability}"))]
pub(crate) struct UnsupportedRemoteTargetState {
    availability: String,
}

pub(crate) fn remote_state_from_availability(
    availability: &str,
) -> Result<RemoteTargetState, UnsupportedRemoteTargetState> {
    match availability {
        "conflict" => Ok(RemoteTargetState::Exists),
        "available" => Ok(RemoteTargetState::Missing),
        "reserved" | "unavailable" => Ok(RemoteTargetState::Unavailable),
        availability => Err(UnsupportedRemoteTargetState {
            availability: availability.to_string(),
        }),
    }
}

pub(crate) fn replacement_requirement(
    summary: Option<&LocalIdentitySummary>,
) -> ReplacementRequirement {
    match summary.map(|summary| &summary.status) {
        Some(LocalIdentityStatus::Ready { .. } | LocalIdentityStatus::Expired { .. }) => {
            ReplacementRequirement::Confirm
        }
        None
        | Some(LocalIdentityStatus::Invalid { .. } | LocalIdentityStatus::Incomplete { .. }) => {
            ReplacementRequirement::None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityLevel {
    Identity,
    SubIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityTarget {
    name: DhttpName<'static>,
    level: IdentityLevel,
    parent: Option<DhttpName<'static>>,
}

impl IdentityTarget {
    pub(crate) fn parse(identity: &str) -> Result<Self, ParseIdentityTargetError> {
        let name = DhttpName::try_from(identity).context(parse_identity_target_error::NameSnafu)?;
        let partial = name.as_partial().to_string();
        let labels: Vec<&str> = partial.split('.').collect();

        match labels.len() {
            2 => Ok(Self {
                name: name.into_owned(),
                level: IdentityLevel::Identity,
                parent: None,
            }),
            3 => {
                let parent = DhttpName::try_from(format!("{}.{}", labels[1], labels[2])).context(
                    parse_identity_target_error::ParentSnafu {
                        identity: partial.to_string(),
                    },
                )?;
                Ok(Self {
                    name: name.into_owned(),
                    level: IdentityLevel::SubIdentity,
                    parent: Some(parent.into_owned()),
                })
            }
            _ => parse_identity_target_error::UnsupportedDepthSnafu { identity: partial }.fail(),
        }
    }

    pub(crate) fn level(&self) -> IdentityLevel {
        self.level
    }

    pub(crate) fn short_name(&self) -> &str {
        self.name.as_partial()
    }

    pub(crate) fn full_name(&self) -> &str {
        self.name.as_full()
    }

    pub(crate) fn parent(&self) -> Option<DhttpName<'_>> {
        self.parent.as_ref().map(DhttpName::borrow)
    }

    pub(crate) fn sub_identity_label(&self) -> Option<&str> {
        match self.level {
            IdentityLevel::Identity => None,
            IdentityLevel::SubIdentity => self.short_name().split('.').next(),
        }
    }

    pub(crate) fn dhttp_name(&self) -> DhttpName<'_> {
        self.name.borrow()
    }

    pub(crate) fn into_dhttp_name(self) -> DhttpName<'static> {
        self.name
    }
}

impl fmt::Display for IdentityTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.short_name())
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ParseIdentityTargetError {
    #[snafu(display("This name contains unsupported special characters."))]
    Name { source: InvalidDhttpName },

    #[snafu(display("This name contains unsupported special characters."))]
    Parent {
        identity: String,
        source: InvalidDhttpName,
    },

    #[snafu(display("This name must match [handle.]your.name."))]
    UnsupportedDepth { identity: String },
}

impl ParseIdentityTargetError {
    pub(crate) fn prompt_message(&self) -> &'static str {
        match self {
            Self::Name { .. } | Self::Parent { .. } => {
                "This name contains unsupported special characters."
            }
            Self::UnsupportedDepth { .. } => "This name must match [handle.]your.name.",
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/target.rs"]
mod tests;
