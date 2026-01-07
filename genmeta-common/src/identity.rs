use std::{
    borrow::Cow,
    convert::Infallible,
    fmt::{Debug, Display},
    ops::Deref,
    str::FromStr,
};

pub mod config;

pub const SUFFIX: &str = ".genmeta.net";

pub fn expand_id(name: &str) -> Cow<'_, str> {
    if let Some(name) = name.strip_suffix('~') {
        return Cow::Owned(format!("{name}{SUFFIX}"));
    }
    Cow::Borrowed(name)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientName(String);

impl ClientName {
    pub fn new(s: &str) -> Self {
        match s.parse() {
            Ok(clientname) => clientname,
        }
    }
}

impl From<&ClientName> for String {
    fn from(name: &ClientName) -> Self {
        name.0.clone()
    }
}

impl Display for ClientName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Deref for ClientName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for ClientName {
    type Err = Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(expand_id(s).to_string()))
    }
}
