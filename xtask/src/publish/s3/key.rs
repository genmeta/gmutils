#![allow(dead_code)]

use snafu::Snafu;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePrefix(String);

impl RemotePrefix {
    pub fn parse(value: &str) -> Result<Self, RemotePrefixError> {
        let trimmed = value.trim_matches('/');
        snafu::ensure!(!trimmed.is_empty(), remote_prefix_error::EmptyPrefixSnafu);
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn join(&self, relative: &str) -> String {
        format!("{}/{relative}", self.0)
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RemotePrefixError {
    #[snafu(display("remote prefix must not be empty"))]
    EmptyPrefix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBaseUrl(String);

impl PublicBaseUrl {
    pub fn parse(value: &str) -> Result<Self, PublicBaseUrlError> {
        let trimmed = value.trim_end_matches('/');
        snafu::ensure!(
            !trimmed.is_empty(),
            public_base_url_error::EmptyPublicBaseUrlSnafu
        );
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn join(&self, archive_name: &str) -> String {
        format!("{}/{archive_name}", self.0)
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum PublicBaseUrlError {
    #[snafu(display("public base url must not be empty"))]
    EmptyPublicBaseUrl,
}

#[cfg(test)]
mod tests {
    use super::{PublicBaseUrl, RemotePrefix};

    #[test]
    fn prefix_trims_slashes_and_joins_keys() {
        let prefix = RemotePrefix::parse("/brew/gmutils/").expect("prefix should parse");
        assert_eq!(prefix.as_str(), "brew/gmutils");
        assert_eq!(prefix.join("gmutils.rb"), "brew/gmutils/gmutils.rb");
    }

    #[test]
    fn empty_prefix_is_rejected() {
        let error = RemotePrefix::parse("///").expect_err("empty prefix should fail");
        assert_eq!(error.to_string(), "remote prefix must not be empty");
    }

    #[test]
    fn public_base_url_trims_trailing_slashes() {
        let base =
            PublicBaseUrl::parse("https://download.example/brew///").expect("url should parse");
        assert_eq!(
            base.join("gmutils-0.5.2.tar.gz"),
            "https://download.example/brew/gmutils-0.5.2.tar.gz"
        );
    }
}
