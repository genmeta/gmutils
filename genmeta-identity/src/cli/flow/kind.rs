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
#[path = "../../../tests/unit/cli/flow/kind.rs"]
mod tests;
