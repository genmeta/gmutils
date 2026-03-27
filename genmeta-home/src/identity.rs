use std::{
    borrow::Cow,
    fmt::Display,
    path::{Path, PathBuf},
    str::FromStr,
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use snafu::Snafu;

use crate::GenmetaHome;

pub mod default;
pub mod fs;

/// Name of an identity, always ends with `.genmeta.net`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name<'a>(Cow<'a, str>);

impl Name<'_> {
    pub const SUFFIX: &'static str = ".genmeta.net";

    /// "Labels must be 63 characters or less."
    pub const MAX_LABEL_LENGTH: usize = 63;

    /// https://devblogs.microsoft.com/oldnewthing/20120412-00/?p=7873
    pub const MAX_LENGTH: usize = 253;

    pub fn as_partial(&self) -> &str {
        debug_assert!(self.0.ends_with(Self::SUFFIX));
        &self.0.as_ref()[..self.0.len() - Self::SUFFIX.len()]
    }

    pub fn as_full(&self) -> &str {
        self.0.as_ref()
    }

    pub fn to_owned(&self) -> Name<'static> {
        Name(Cow::Owned(self.0.to_string()))
    }

    pub fn into_owned(self) -> Name<'static> {
        Name(Cow::Owned(self.0.into_owned()))
    }

    pub fn borrow(&self) -> Name<'_> {
        Name(Cow::Borrowed(self.0.as_ref()))
    }
}

impl<'a> From<Name<'a>> for Cow<'a, str> {
    fn from(Name(name): Name<'a>) -> Self {
        name
    }
}

impl Display for Name<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_partial().fmt(f)
    }
}

impl serde::Serialize for Name<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_partial())
    }
}

#[derive(Snafu, Debug)]
pub enum InvalidName {
    #[snafu(display("name too long (max {} characters)", Name::MAX_LENGTH))]
    TooLong {},
    #[snafu(display("label too long (max {} characters)", Name::MAX_LABEL_LENGTH))]
    LabelTooLong {},
    #[snafu(display("name contains empty or numberic / hyphen only label"))]
    EmptyLabel {},
    #[snafu(display("name contains invalid characters"))]
    InvalidCharacter {},
    #[snafu(display("name is missing required suffix {}", Name::SUFFIX))]
    MissingSuffix {},
}

impl FromStr for Name<'_> {
    type Err = InvalidName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_str(s).map(Name::into_owned)
    }
}

impl<'de> serde::Deserialize<'de> for Name<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        Name::try_from_str(s)
            .map(Name::into_owned)
            .map_err(serde::de::Error::custom)
    }
}

impl<'n> Name<'n> {
    pub fn to_wildcard_name(self) -> Name<'n> {
        if !self.0.starts_with('*') {
            let (.., tails) = self
                .0
                .split_once('.')
                .expect("BUG: Name always contains a dot (validated suffix)");
            return Name(Cow::Owned(format!("*.{tails}")));
        }
        self
    }

    pub fn is_wildcard(&self) -> bool {
        self.0.starts_with('*')
    }

    pub fn is_match(&self, name: &Name) -> bool {
        if !self.is_wildcard() {
            return self == name;
        }

        let self_tails = &self.0.as_ref()[1..]; // skip '*'
        name.0
            .split_once('.')
            .is_some_and(|(.., tails)| tails == self_tails)
    }

    pub fn validate(input: &[u8]) -> Result<(), InvalidName> {
        if !input.ends_with(Self::SUFFIX.as_bytes()) {
            return Err(InvalidName::MissingSuffix {});
        }

        enum State {
            Start,
            Next,
            NumericOnly { len: usize },
            NextAfterNumericOnly,
            Subsequent { len: usize },
            Hyphen { len: usize },
            Wildcard,
        }

        use State::*;
        let mut state = Start;

        /// https://devblogs.microsoft.com/oldnewthing/20120412-00/?p=7873
        const MAX_NAME_LENGTH: usize = 253;

        if input.len() > MAX_NAME_LENGTH {
            return Err(InvalidName::TooLong {});
        }

        let mut idx = 0;
        while idx < input.len() {
            let ch = input[idx];
            state = match (state, ch) {
                (Start, b'*') => Wildcard,
                (Wildcard, b'.') => Next,
                (Start | Next | NextAfterNumericOnly | Hyphen { .. }, b'.') => {
                    return Err(InvalidName::EmptyLabel {});
                }
                (Subsequent { .. }, b'.') => Next,
                (NumericOnly { .. }, b'.') => NextAfterNumericOnly,
                (Subsequent { len } | NumericOnly { len } | Hyphen { len }, _)
                    if len >= Self::MAX_LABEL_LENGTH =>
                {
                    return Err(InvalidName::EmptyLabel {});
                }
                (Start | Next | NextAfterNumericOnly, b'0'..=b'9') => NumericOnly { len: 1 },
                (NumericOnly { len }, b'0'..=b'9') => NumericOnly { len: len + 1 },
                (Start | Next | NextAfterNumericOnly, b'a'..=b'z' | b'A'..=b'Z' | b'_') => {
                    Subsequent { len: 1 }
                }
                (Subsequent { len } | NumericOnly { len } | Hyphen { len }, b'-') => {
                    Hyphen { len: len + 1 }
                }
                (
                    Subsequent { len } | NumericOnly { len } | Hyphen { len },
                    b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'0'..=b'9',
                ) => Subsequent { len: len + 1 },
                _ => return Err(InvalidName::InvalidCharacter {}),
            };
            idx += 1;
        }

        if matches!(
            state,
            Start | Hyphen { .. } | NumericOnly { .. } | NextAfterNumericOnly
        ) {
            return Err(InvalidName::EmptyLabel {});
        }

        Ok(())
    }

    pub fn try_from_str<'a>(name: impl Into<Cow<'a, str>>) -> Result<Name<'a>, InvalidName> {
        let name = name.into();

        match name.ends_with(Self::SUFFIX) {
            true => Self::try_from_str_full(name),
            false => Self::try_from_str_partial(name),
        }
    }

    pub fn try_from_str_full<'a>(name: impl Into<Cow<'a, str>>) -> Result<Name<'a>, InvalidName> {
        let name = name.into();
        Name::validate(name.as_bytes())?;
        Ok(Name(name))
    }

    pub fn try_from_str_partial<'a>(
        name: impl Into<Cow<'a, str>>,
    ) -> Result<Name<'static>, InvalidName> {
        let name = Cow::Owned(name.into().into_owned() + Self::SUFFIX);
        Name::try_from_str_full(name)
    }

    pub fn try_expand_from(str: impl Into<Cow<'n, str>>) -> Result<Option<Name<'n>>, InvalidName> {
        let str = str.into();
        if str.ends_with(Self::SUFFIX) {
            return Self::try_from_str_full(str).map(Some);
        }
        if str.ends_with('~') {
            let partial = match str {
                Cow::Borrowed(str) => Cow::Borrowed(&str[..str.len() - 1]),
                Cow::Owned(mut str) => {
                    str.pop();
                    Cow::Owned(str)
                }
            };
            return Self::try_from_str_partial(partial).map(Some);
        }

        Ok(None)
    }
}

/// An identity home directory (e.g. `.genmeta/reimu.pilot/`).
#[derive(Debug, Clone)]
pub struct IdentityHome {
    pub(crate) path: PathBuf,
    pub(crate) name: Name<'static>,
}

/// Loaded TLS material (certificates + private key) for an identity.
#[derive(Debug)]
pub struct Identity {
    pub(crate) name: Name<'static>,
    pub(crate) certs: Vec<CertificateDer<'static>>,
    pub(crate) key: PrivateKeyDer<'static>,
}

impl IdentityHome {
    pub const SSL_DIR_NAME: &'static str = "ssl";

    pub fn name(&self) -> &Name<'static> {
        &self.name
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn ssl_path(&self) -> PathBuf {
        self.path.join(Self::SSL_DIR_NAME)
    }
}

impl Identity {
    pub fn name(&self) -> &Name<'static> {
        &self.name
    }

    pub fn certs(&self) -> &[CertificateDer<'static>] {
        &self.certs
    }

    pub fn key(&self) -> &PrivateKeyDer<'static> {
        &self.key
    }
}

impl GenmetaHome {
    pub fn join_identity_name(&self, name: Name<'_>) -> PathBuf {
        self.join(name.as_partial())
    }
}
