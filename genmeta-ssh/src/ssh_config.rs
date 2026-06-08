//! SSH configuration file parser.
//!
//! Parses OpenSSH-style config files (`~/.ssh/config`, `/etc/ssh/ssh_config`)
//! with support for standard keywords plus the custom `Id` keyword for
//! genmeta identity selection.
//!
//! Uses [`dssh::config`] for syntax-level parsing (PEG), providing
//! precise source location tracking on all parsed elements.
//!
//! ## Supported keywords
//!
//! | Keyword          | Description                                |
//! |------------------|--------------------------------------------|
//! | `Host`           | Host pattern (glob matching)               |
//! | `User`           | Login username                             |
//! | `Hostname`       | Real hostname or IP                        |
//! | `Port`           | Port number                                |
//! | `Id`             | Genmeta identity name (custom extension)   |
//! | `ConnectTimeout` | Connection timeout in seconds              |
//! | `LocalForward`   | Local port forwarding rule                 |
//! | `RemoteForward`  | Remote port forwarding rule                |
//! | `DynamicForward` | Dynamic (SOCKS) forwarding endpoint        |
//!
//! Unknown keywords are silently ignored (matching OpenSSH behavior).
//!
//! ## Priority
//!
//! Within a file, the **first** matching value wins (per OpenSSH semantics).
//! Across files: user config (`~/.ssh/config`) takes precedence over system
//! config (`/etc/ssh/ssh_config`).

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use dssh::config::{self as ssh_config, Directive, Entry, HostArgs, Located, Pattern, SourceFile};
use snafu::prelude::*;

use crate::forward::{DynamicForward, LocalForward, RemoteForward};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
#[snafu(module(read_config_error))]
pub enum ReadConfigError {
    #[snafu(display("failed to determine home directory"))]
    NoHomeDir,

    #[snafu(display("failed to read config file `{}`", path.display()))]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// A non-fatal warning from parsing a single directive.
#[derive(Debug)]
pub struct ParseWarning {
    pub location: ssh_config::Location,
    pub message: String,
}

impl std::fmt::Display for ParseWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

// ---------------------------------------------------------------------------
// Parsed config
// ---------------------------------------------------------------------------

/// Resolved SSH configuration for a target host.
#[derive(Debug, Default)]
pub struct SshConfig {
    pub user: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub id: Option<String>,
    pub connect_timeout: Option<Duration>,
    pub local_forwards: Vec<LocalForward>,
    pub remote_forwards: Vec<RemoteForward>,
    pub dynamic_forwards: Vec<DynamicForward>,
}

impl SshConfig {
    /// Merge `other` into self. First-match-wins: only fills `None` fields.
    fn merge(&mut self, other: &SshConfig) {
        if self.user.is_none() {
            self.user.clone_from(&other.user);
        }
        if self.hostname.is_none() {
            self.hostname.clone_from(&other.hostname);
        }
        if self.port.is_none() {
            self.port = other.port;
        }
        if self.id.is_none() {
            self.id.clone_from(&other.id);
        }
        if self.connect_timeout.is_none() {
            self.connect_timeout = other.connect_timeout;
        }
        // Forwarding rules accumulate (not first-match-wins).
        self.local_forwards
            .extend(other.local_forwards.iter().cloned());
        self.remote_forwards
            .extend(other.remote_forwards.iter().cloned());
        self.dynamic_forwards
            .extend(other.dynamic_forwards.iter().cloned());
    }
}

// ---------------------------------------------------------------------------
// Interpreter: walk parsed entries, build Host blocks
// ---------------------------------------------------------------------------

/// Parsed Host patterns for a block.
struct HostBlock<'a> {
    patterns: Vec<Located<Pattern<'a>>>,
    config: SshConfig,
}

/// Interpret parsed entries into per-host blocks.
///
/// Returns blocks plus any non-fatal warnings (e.g., invalid port values).
fn interpret_entries<'a>(entries: &[Entry<'a>]) -> (Vec<HostBlock<'a>>, Vec<ParseWarning>) {
    let mut blocks: Vec<HostBlock<'a>> = Vec::new();
    let mut current_patterns: Option<Vec<Located<Pattern<'a>>>> = None;
    let mut current_config = SshConfig::default();
    let mut warnings: Vec<ParseWarning> = Vec::new();

    for entry in entries {
        let Entry::Directive(d) = entry else {
            continue;
        };

        let kw_lower = d.keyword.value.to_ascii_lowercase();
        match kw_lower.as_str() {
            "host" => {
                // Save current block.
                blocks.push(HostBlock {
                    patterns: current_patterns.take().unwrap_or_default(),
                    config: std::mem::take(&mut current_config),
                });
                // Start new block with parsed patterns.
                match d.parse_args::<HostArgs>() {
                    Ok(host_args) => {
                        current_patterns = Some(host_args.value.patterns);
                    }
                    Err(err) => {
                        warnings.push(ParseWarning {
                            location: err.location.clone(),
                            message: format!("invalid Host directive: {}", err.value),
                        });
                        current_patterns = None;
                    }
                }
            }
            "user" => {
                if current_config.user.is_none()
                    && let Some(token) = single_token(d)
                {
                    current_config.user = Some(token.value.to_string());
                }
            }
            "hostname" => {
                if current_config.hostname.is_none()
                    && let Some(token) = single_token(d)
                {
                    current_config.hostname = Some(token.value.to_string());
                }
            }
            "port" => {
                if current_config.port.is_none()
                    && let Some(token) = single_token(d)
                {
                    match token.value.parse::<u16>() {
                        Ok(port) => current_config.port = Some(port),
                        Err(_) => warnings.push(ParseWarning {
                            location: token.location.clone(),
                            message: format!("invalid port `{}`", token.value),
                        }),
                    }
                }
            }
            "id" => {
                if current_config.id.is_none()
                    && let Some(token) = single_token(d)
                {
                    current_config.id = Some(token.value.to_string());
                }
            }
            "connecttimeout" => {
                if current_config.connect_timeout.is_none()
                    && let Some(token) = single_token(d)
                {
                    match token.value.parse::<u64>() {
                        Ok(secs) => {
                            current_config.connect_timeout = Some(Duration::from_secs(secs))
                        }
                        Err(_) => warnings.push(ParseWarning {
                            location: token.location.clone(),
                            message: format!("invalid timeout `{}`", token.value),
                        }),
                    }
                }
            }
            "localforward" => match d.arguments.value.parse::<LocalForward>() {
                Ok(rule) => current_config.local_forwards.push(rule),
                Err(reason) => warnings.push(ParseWarning {
                    location: d.arguments.location.clone(),
                    message: format!("invalid local forward `{}`: {reason}", d.arguments.value),
                }),
            },
            "remoteforward" => match d.arguments.value.parse::<RemoteForward>() {
                Ok(rule) => current_config.remote_forwards.push(rule),
                Err(reason) => warnings.push(ParseWarning {
                    location: d.arguments.location.clone(),
                    message: format!("invalid remote forward `{}`: {reason}", d.arguments.value),
                }),
            },
            "dynamicforward" => match d.arguments.value.parse::<DynamicForward>() {
                Ok(rule) => current_config.dynamic_forwards.push(rule),
                Err(reason) => warnings.push(ParseWarning {
                    location: d.arguments.location.clone(),
                    message: format!("invalid dynamic forward `{}`: {reason}", d.arguments.value),
                }),
            },
            _ => {
                tracing::trace!(
                    keyword = d.keyword.value,
                    value = d.arguments.value,
                    "ignoring unknown ssh config keyword"
                );
            }
        }
    }

    blocks.push(HostBlock {
        patterns: current_patterns.take().unwrap_or_default(),
        config: std::mem::take(&mut current_config),
    });
    (blocks, warnings)
}

/// Extract the single token from a directive's arguments.
fn single_token<'a>(d: &Directive<'a>) -> Option<Located<&'a str>> {
    let tokens = d.arguments.tokenize();
    if tokens.len() == 1 {
        tokens.into_iter().next()
    } else {
        None
    }
}

/// Resolve config for a given hostname by matching against all blocks.
fn resolve_for_host(blocks: &[HostBlock<'_>], hostname: &str) -> SshConfig {
    let mut result = SshConfig::default();

    for block in blocks {
        if block.patterns.is_empty() {
            // Global block (before any Host directive) matches everything.
            result.merge(&block.config);
            continue;
        }

        let mut any_positive = false;
        let mut any_negative = false;

        for located_pattern in &block.patterns {
            let pattern = &located_pattern.value;
            if pattern.negated {
                if pattern.glob_matches(hostname) {
                    any_negative = true;
                }
            } else if pattern.glob_matches(hostname) {
                any_positive = true;
            }
        }

        if any_positive && !any_negative {
            result.merge(&block.config);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Read and resolve SSH config for the given hostname.
///
/// Reads user config (`~/.ssh/config`) and system config (`/etc/ssh/ssh_config`)
/// in order. Returns the merged configuration and any non-fatal errors
/// encountered while reading individual files.
pub async fn read_config(
    cli_options: &[String],
    hostname: &str,
) -> Result<(SshConfig, Vec<ParseWarning>), ReadConfigError> {
    let mut all_warnings: Vec<ParseWarning> = Vec::new();
    let mut result = SshConfig::default();

    // 1. Inline CLI options (highest priority).
    if !cli_options.is_empty() {
        let inline_content = cli_options.join("\n");
        let sf = SourceFile::new("<cli-options>", inline_content);
        let entries = sf.parse();
        let (blocks, warnings) = interpret_entries(&entries);
        all_warnings.extend(warnings);
        let resolved = resolve_for_host(&blocks, hostname);
        result.merge(&resolved);
    }

    // 2. User config (~/.ssh/config).
    let home = dirs::home_dir().ok_or(ReadConfigError::NoHomeDir)?;
    let user_config_path = home.join(".ssh").join("config");
    match read_and_resolve(&user_config_path, hostname).await {
        Ok((config, warnings)) => {
            all_warnings.extend(warnings);
            result.merge(&config);
        }
        Err(ReadConfigError::ReadFile { ref source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(
                error = %snafu::Report::from_error(&e),
                "failed to read user ssh config"
            );
        }
    }

    // 3. System config (/etc/ssh/ssh_config).
    let system_config_path = PathBuf::from("/etc/ssh/ssh_config");
    match read_and_resolve(&system_config_path, hostname).await {
        Ok((config, warnings)) => {
            all_warnings.extend(warnings);
            result.merge(&config);
        }
        Err(ReadConfigError::ReadFile { ref source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(
                error = %snafu::Report::from_error(&e),
                "failed to read system ssh config"
            );
        }
    }

    Ok((result, all_warnings))
}

/// Read a single config file and resolve for the given hostname.
async fn read_and_resolve(
    path: &Path,
    hostname: &str,
) -> Result<(SshConfig, Vec<ParseWarning>), ReadConfigError> {
    let content = tokio::fs::read_to_string(path)
        .await
        .context(read_config_error::ReadFileSnafu { path })?;

    let sf = SourceFile::new(path, content);
    let entries = sf.parse();
    let (blocks, warnings) = interpret_entries(&entries);
    let resolved = resolve_for_host(&blocks, hostname);

    Ok((resolved, warnings))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_resolve(content: &str, hostname: &str) -> (SshConfig, Vec<ParseWarning>) {
        let sf = SourceFile::new("<test>", content.to_string());
        let entries = sf.parse();
        let (blocks, warnings) = interpret_entries(&entries);
        (resolve_for_host(&blocks, hostname), warnings)
    }

    #[test]
    fn parse_simple_config() {
        let (resolved, warnings) = parse_and_resolve(
            "\
Host example
    User alice
    Hostname example.dhttp.net
    Port 443
    Id alice
    ConnectTimeout 30
",
            "example",
        );
        assert!(warnings.is_empty());
        assert_eq!(resolved.user.as_deref(), Some("alice"));
        assert_eq!(resolved.hostname.as_deref(), Some("example.dhttp.net"));
        assert_eq!(resolved.port, Some(443));
        assert_eq!(resolved.id.as_deref(), Some("alice"));
        assert_eq!(resolved.connect_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn parse_global_block() {
        let (resolved, _) = parse_and_resolve(
            "\
User default_user
ConnectTimeout 10

Host specific
    User specific_user
",
            "specific",
        );
        assert_eq!(resolved.user.as_deref(), Some("default_user"));
        assert_eq!(resolved.connect_timeout, Some(Duration::from_secs(10)));

        let (resolved, _) = parse_and_resolve(
            "\
User default_user
ConnectTimeout 10

Host specific
    User specific_user
",
            "other",
        );
        assert_eq!(resolved.user.as_deref(), Some("default_user"));
    }

    #[test]
    fn first_match_wins() {
        let (resolved, _) = parse_and_resolve(
            "\
Host *
    User global

Host example
    User specific
",
            "example",
        );
        assert_eq!(resolved.user.as_deref(), Some("global"));
    }

    #[test]
    fn forwarding_accumulates() {
        let (resolved, _) = parse_and_resolve(
            "\
Host *
    LocalForward 8080:localhost:80

Host example
    LocalForward 9090:localhost:90
",
            "example",
        );
        assert_eq!(resolved.local_forwards.len(), 2);
    }

    #[test]
    fn parse_comments_and_empty_lines() {
        let (resolved, _) = parse_and_resolve(
            "\
# This is a comment
Host example

    # Another comment
    User alice

",
            "example",
        );
        assert_eq!(resolved.user.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_equals_separator() {
        let (resolved, _) = parse_and_resolve("Host=example\nUser=alice\n", "example");
        assert_eq!(resolved.user.as_deref(), Some("alice"));
    }

    #[test]
    fn unmatched_host_ignored() {
        let (resolved, _) = parse_and_resolve(
            "\
Host other
    User bob
",
            "example",
        );
        assert!(resolved.user.is_none());
    }

    #[test]
    fn invalid_port_produces_warning() {
        let (resolved, warnings) = parse_and_resolve("Port notanumber\n", "anything");
        assert!(resolved.port.is_none());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("invalid port"));
        // Warning has location info
        assert_eq!(warnings[0].location.line, 1);
    }

    #[test]
    fn invalid_timeout_produces_warning() {
        let (resolved, warnings) = parse_and_resolve("ConnectTimeout bad\n", "anything");
        assert!(resolved.connect_timeout.is_none());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("invalid timeout"));
    }
}
