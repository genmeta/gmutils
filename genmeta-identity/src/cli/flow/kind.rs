use std::{fmt, str::FromStr};

use dhttp::certificate::CertificateChainKind;
use snafu::Snafu;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityKind {
    Primary,
    Secondary,
}

impl IdentityKind {
    pub(crate) const SELECT_PROMPT: &str =
        "Choose how this device should be used for this identity.";
    pub(crate) const PRIMARY_HELP: &str =
        "Primary\n  For a main host, server, desktop, home gateway, or always-on endpoint.";
    pub(crate) const SECONDARY_HELP: &str =
        "Secondary\n  For an additional device, such as a phone, laptop, or temporary endpoint.";

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
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

impl From<IdentityKind> for CertificateChainKind {
    fn from(value: IdentityKind) -> Self {
        match value {
            IdentityKind::Primary => Self::Primary,
            IdentityKind::Secondary => Self::Secondary,
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
    fn displays_labels_and_help_copy() {
        assert_eq!(IdentityKind::Primary.to_string(), "primary");
        assert_eq!(IdentityKind::Secondary.to_string(), "secondary");
        assert_eq!(
            IdentityKind::SELECT_PROMPT,
            "Choose how this device should be used for this identity."
        );
        assert!(IdentityKind::PRIMARY_HELP.contains("main host"));
        assert!(IdentityKind::SECONDARY_HELP.contains("additional device"));
    }
}
