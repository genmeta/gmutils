use std::fmt;

use dhttp_identity::name::{DhttpName, InvalidDhttpName};
use snafu::{ResultExt, Snafu};

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
    #[snafu(display("identity name is invalid"))]
    Name { source: InvalidDhttpName },

    #[snafu(display("identity name {identity} has an invalid parent identity"))]
    Parent {
        identity: String,
        source: InvalidDhttpName,
    },

    #[snafu(display(
        "identity name {identity} is not supported; use <given_name>.<surname> or <sub_identity>.<given_name>.<surname>"
    ))]
    UnsupportedDepth { identity: String },
}

#[cfg(test)]
mod tests {
    use dhttp_identity::name::DhttpName;

    use super::{IdentityLevel, IdentityTarget};

    #[test]
    fn parses_short_and_full_identity_names() {
        let identity = IdentityTarget::parse("alice.smith").unwrap();
        assert_eq!(identity.level(), IdentityLevel::Identity);
        assert_eq!(identity.short_name(), "alice.smith");
        assert_eq!(identity.full_name(), "alice.smith.dhttp.net");
        assert_eq!(identity.parent(), None);

        let sub_identity = IdentityTarget::parse("phone.alice.smith.dhttp.net").unwrap();
        assert_eq!(sub_identity.level(), IdentityLevel::SubIdentity);
        assert_eq!(sub_identity.short_name(), "phone.alice.smith");
        assert_eq!(sub_identity.full_name(), "phone.alice.smith.dhttp.net");
        assert_eq!(
            sub_identity.parent().unwrap(),
            DhttpName::try_from("alice.smith").unwrap(),
        );
    }

    #[test]
    fn rejects_unsupported_identity_depths() {
        for input in ["alice", "one.two.three.four"] {
            let error = IdentityTarget::parse(input).unwrap_err();
            let rendered = error.to_string();
            assert!(rendered.contains(input), "{rendered}");
        }
    }

    #[test]
    fn extracts_sub_identity_label_from_first_label() {
        let identity = IdentityTarget::parse("phone.alice.smith").unwrap();
        assert_eq!(identity.sub_identity_label(), Some("phone"));

        let root_identity = IdentityTarget::parse("alice.smith").unwrap();
        assert_eq!(root_identity.sub_identity_label(), None);
    }
}
