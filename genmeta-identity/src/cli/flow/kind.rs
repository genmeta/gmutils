use std::{fmt, str::FromStr};

use snafu::Snafu;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityKind {
    Primary,
    Secondary,
}

impl IdentityKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        }
    }

    pub(crate) fn ski_flag(self) -> &'static str {
        match self {
            Self::Primary => "0",
            Self::Secondary => "1",
        }
    }

    pub(crate) fn from_ski_flag(flag: &str) -> Option<Self> {
        match flag {
            "0" => Some(Self::Primary),
            "1" => Some(Self::Secondary),
            _ => None,
        }
    }
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IdentityKind {
    type Err = ParseIdentityKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "primary" => Ok(Self::Primary),
            "secondary" => Ok(Self::Secondary),
            other => parse_identity_kind_error::InvalidSnafu {
                value: other.to_string(),
            }
            .fail(),
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ParseIdentityKindError {
    #[snafu(display("identity kind {value} is invalid; use primary or secondary"))]
    Invalid { value: String },
}

#[cfg(test)]
mod tests {
    use super::IdentityKind;

    #[test]
    fn parses_primary_and_secondary() {
        assert_eq!(
            "primary".parse::<IdentityKind>().unwrap(),
            IdentityKind::Primary
        );
        assert_eq!(
            "secondary".parse::<IdentityKind>().unwrap(),
            IdentityKind::Secondary
        );
    }

    #[test]
    fn keeps_wire_labels_separate_from_user_facing_usage_copy() {
        assert_eq!(IdentityKind::Primary.to_string(), "primary");
        assert_eq!(IdentityKind::Secondary.to_string(), "secondary");
        assert_eq!(IdentityKind::Primary.ski_flag(), "0");
        assert_eq!(IdentityKind::Secondary.ski_flag(), "1");
        assert_eq!(
            IdentityKind::from_ski_flag("0"),
            Some(IdentityKind::Primary)
        );
        assert_eq!(
            IdentityKind::from_ski_flag("1"),
            Some(IdentityKind::Secondary)
        );
        assert_eq!(IdentityKind::from_ski_flag("2"), None);
    }
}
