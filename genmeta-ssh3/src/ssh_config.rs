//! SSH configuration file parser.
//!
//! Parses OpenSSH-style config files (`~/.ssh/config`, `/etc/ssh/ssh_config`)
//! with support for standard keywords plus the custom `Id` keyword for
//! genmeta identity selection.
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

use std::path::{Path, PathBuf};
use std::time::Duration;

use snafu::prelude::*;

use crate::forward::{DynamicForwardEndpoint, LocalForwardRule, RemoteForwardRule};

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

    #[snafu(display("parse error in `{}`", path.display()))]
    Parse {
        path: PathBuf,
        source: ParseError,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module(parse_error))]
pub enum ParseError {
    #[snafu(display("line {line}: {message}"))]
    InvalidLine { line: usize, message: String },

    #[snafu(display("line {line}: invalid port `{value}`"))]
    InvalidPort {
        line: usize,
        value: String,
        source: std::num::ParseIntError,
    },

    #[snafu(display("line {line}: invalid timeout `{value}`"))]
    InvalidTimeout {
        line: usize,
        value: String,
        source: std::num::ParseIntError,
    },

    #[snafu(display("line {line}: invalid forward rule `{value}`"))]
    InvalidForwardRule {
        line: usize,
        value: String,
        source: peg::error::ParseError<peg::str::LineCol>,
    },
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
    pub local_forwards: Vec<LocalForwardRule>,
    pub remote_forwards: Vec<RemoteForwardRule>,
    pub dynamic_forwards: Vec<DynamicForwardEndpoint>,
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
        self.local_forwards.extend(other.local_forwards.iter().cloned());
        self.remote_forwards.extend(other.remote_forwards.iter().cloned());
        self.dynamic_forwards.extend(other.dynamic_forwards.iter().cloned());
    }
}

// ---------------------------------------------------------------------------
// Host pattern matching
// ---------------------------------------------------------------------------

/// Match a hostname against an SSH Host pattern.
///
/// Supports `*` (match any) and `?` (match single char) wildcards.
/// Patterns starting with `!` negate the match.
fn host_pattern_matches(pattern: &str, hostname: &str) -> bool {
    let (negated, pattern) = match pattern.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, pattern),
    };
    let matches = glob_match(pattern, hostname);
    if negated { !matches } else { matches }
}

/// Simple glob matching: `*` matches any sequence, `?` matches one char.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_match_inner(&pat, &txt)
}

fn glob_match_inner(pat: &[char], txt: &[char]) -> bool {
    match (pat.first(), txt.first()) {
        (None, None) => true,
        (Some(&'*'), _) => {
            // Try skipping the * (match zero) or consuming one text char
            glob_match_inner(&pat[1..], txt)
                || (!txt.is_empty() && glob_match_inner(pat, &txt[1..]))
        }
        (Some(&'?'), Some(_)) => glob_match_inner(&pat[1..], &txt[1..]),
        (Some(&p), Some(&t)) if p.eq_ignore_ascii_case(&t) => {
            glob_match_inner(&pat[1..], &txt[1..])
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse a single config file's content into per-host blocks.
fn parse_config(content: &str) -> Result<Vec<(Vec<String>, SshConfig)>, ParseError> {
    let mut blocks: Vec<(Vec<String>, SshConfig)> = Vec::new();
    // Start with a global block (matches everything).
    let mut current_patterns: Vec<String> = vec!["*".to_string()];
    let mut current_config = SshConfig::default();

    for (line_idx, raw_line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let line = raw_line.trim();

        // Skip empty lines and comments.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split into keyword and value. Accept both `Keyword Value` and `Keyword=Value`.
        let (keyword, value) = split_keyword_value(line)
            .ok_or_else(|| ParseError::InvalidLine {
                line: line_num,
                message: format!("cannot parse keyword from `{line}`"),
            })?;

        let kw_lower = keyword.to_ascii_lowercase();
        match kw_lower.as_str() {
            "host" => {
                // Save current block, start a new one.
                blocks.push((
                    std::mem::replace(&mut current_patterns, parse_host_patterns(value)),
                    std::mem::take(&mut current_config),
                ));
            }
            "user" => {
                if current_config.user.is_none() {
                    current_config.user = Some(value.to_string());
                }
            }
            "hostname" => {
                if current_config.hostname.is_none() {
                    current_config.hostname = Some(value.to_string());
                }
            }
            "port" => {
                if current_config.port.is_none() {
                    current_config.port = Some(
                        value.parse().context(parse_error::InvalidPortSnafu {
                            line: line_num,
                            value,
                        })?,
                    );
                }
            }
            "id" => {
                if current_config.id.is_none() {
                    current_config.id = Some(value.to_string());
                }
            }
            "connecttimeout" => {
                if current_config.connect_timeout.is_none() {
                    let secs: u64 =
                        value.parse().context(parse_error::InvalidTimeoutSnafu {
                            line: line_num,
                            value,
                        })?;
                    current_config.connect_timeout = Some(Duration::from_secs(secs));
                }
            }
            "localforward" => {
                let rule: LocalForwardRule =
                    value.parse().context(parse_error::InvalidForwardRuleSnafu {
                        line: line_num,
                        value,
                    })?;
                current_config.local_forwards.push(rule);
            }
            "remoteforward" => {
                let rule: RemoteForwardRule =
                    value.parse().context(parse_error::InvalidForwardRuleSnafu {
                        line: line_num,
                        value,
                    })?;
                current_config.remote_forwards.push(rule);
            }
            "dynamicforward" => {
                let ep: DynamicForwardEndpoint =
                    value.parse().context(parse_error::InvalidForwardRuleSnafu {
                        line: line_num,
                        value,
                    })?;
                current_config.dynamic_forwards.push(ep);
            }
            _ => {
                // Unknown keywords are silently ignored (OpenSSH behavior).
                tracing::trace!(keyword, value, "ignoring unknown ssh config keyword");
            }
        }
    }

    // Push the final block.
    blocks.push((current_patterns, current_config));

    Ok(blocks)
}

/// Split `Keyword Value` or `Keyword=Value` into (keyword, value).
fn split_keyword_value(line: &str) -> Option<(&str, &str)> {
    // Try `=` separator first.
    if let Some((k, v)) = line.split_once('=') {
        let k = k.trim();
        let v = v.trim();
        if !k.is_empty() && !v.is_empty() {
            return Some((k, v));
        }
    }
    // Whitespace separator.
    let (k, v) = line.split_once(|c: char| c.is_ascii_whitespace())?;
    let v = v.trim();
    if k.is_empty() || v.is_empty() {
        return None;
    }
    Some((k, v))
}

/// Parse space-separated host patterns from a `Host` line value.
fn parse_host_patterns(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

/// Resolve config for a given hostname by matching against all blocks.
fn resolve_for_host(blocks: &[(Vec<String>, SshConfig)], hostname: &str) -> SshConfig {
    let mut result = SshConfig::default();

    for (patterns, config) in blocks {
        let mut any_positive = false;
        let mut any_negative = false;

        for pattern in patterns {
            if pattern.starts_with('!') {
                if host_pattern_matches(pattern, hostname) {
                    // Negated pattern matched → this block is excluded.
                    any_negative = true;
                }
            } else if host_pattern_matches(pattern, hostname) {
                any_positive = true;
            }
        }

        if any_positive && !any_negative {
            result.merge(config);
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
) -> Result<(SshConfig, Vec<(PathBuf, ReadConfigError)>), ReadConfigError> {
    let mut errors: Vec<(PathBuf, ReadConfigError)> = Vec::new();
    let mut result = SshConfig::default();

    // 1. Inline CLI options (highest priority).
    if !cli_options.is_empty() {
        let inline_content = cli_options.join("\n");
        match parse_config(&inline_content) {
            Ok(blocks) => {
                let resolved = resolve_for_host(&blocks, hostname);
                result.merge(&resolved);
            }
            Err(source) => {
                tracing::warn!("failed to parse inline SSH options: {source}");
            }
        }
    }

    // 2. User config (~/.ssh/config).
    let home = dirs::home_dir().ok_or(ReadConfigError::NoHomeDir)?;
    let user_config_path = home.join(".ssh").join("config");
    match read_and_resolve(&user_config_path, hostname).await {
        Ok(config) => result.merge(&config),
        Err(ReadConfigError::ReadFile { ref source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => errors.push((user_config_path, e)),
    }

    // 3. System config (/etc/ssh/ssh_config).
    let system_config_path = PathBuf::from("/etc/ssh/ssh_config");
    match read_and_resolve(&system_config_path, hostname).await {
        Ok(config) => result.merge(&config),
        Err(ReadConfigError::ReadFile { ref source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => errors.push((system_config_path, e)),
    }

    Ok((result, errors))
}

/// Read a single config file and resolve for the given hostname.
async fn read_and_resolve(path: &Path, hostname: &str) -> Result<SshConfig, ReadConfigError> {
    let content = tokio::fs::read_to_string(path)
        .await
        .context(read_config_error::ReadFileSnafu { path })?;

    let blocks = parse_config(&content).context(read_config_error::ParseSnafu { path })?;

    Ok(resolve_for_host(&blocks, hostname))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.example.com", "www.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
    }

    #[test]
    fn glob_match_question() {
        assert!(glob_match("host?", "host1"));
        assert!(!glob_match("host?", "host12"));
    }

    #[test]
    fn glob_case_insensitive() {
        assert!(glob_match("Host", "host"));
        assert!(glob_match("HOST", "host"));
    }

    #[test]
    fn host_pattern_negation() {
        assert!(!host_pattern_matches("!*.internal", "srv.internal"));
        assert!(host_pattern_matches("!*.internal", "srv.public"));
    }

    #[test]
    fn parse_simple_config() {
        let content = "\
Host example
    User alice
    Hostname example.genmeta.net
    Port 443
    Id alice
    ConnectTimeout 30
";
        let blocks = parse_config(content).unwrap();
        let resolved = resolve_for_host(&blocks, "example");
        assert_eq!(resolved.user.as_deref(), Some("alice"));
        assert_eq!(resolved.hostname.as_deref(), Some("example.genmeta.net"));
        assert_eq!(resolved.port, Some(443));
        assert_eq!(resolved.id.as_deref(), Some("alice"));
        assert_eq!(resolved.connect_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn parse_global_block() {
        let content = "\
User default_user
ConnectTimeout 10

Host specific
    User specific_user
";
        let blocks = parse_config(content).unwrap();

        // "specific" matches both global and specific blocks.
        let resolved = resolve_for_host(&blocks, "specific");
        assert_eq!(resolved.user.as_deref(), Some("default_user"));
        assert_eq!(resolved.connect_timeout, Some(Duration::from_secs(10)));

        // "other" matches only global block.
        let resolved = resolve_for_host(&blocks, "other");
        assert_eq!(resolved.user.as_deref(), Some("default_user"));
    }

    #[test]
    fn first_match_wins() {
        let content = "\
Host *
    User global

Host example
    User specific
";
        let blocks = parse_config(content).unwrap();
        let resolved = resolve_for_host(&blocks, "example");
        // Global block matches first, so "global" wins.
        assert_eq!(resolved.user.as_deref(), Some("global"));
    }

    #[test]
    fn forwarding_accumulates() {
        let content = "\
Host *
    LocalForward 8080:localhost:80

Host example
    LocalForward 9090:localhost:90
";
        let blocks = parse_config(content).unwrap();
        let resolved = resolve_for_host(&blocks, "example");
        assert_eq!(resolved.local_forwards.len(), 2);
    }

    #[test]
    fn parse_comments_and_empty_lines() {
        let content = "\
# This is a comment
Host example

    # Another comment
    User alice

";
        let blocks = parse_config(content).unwrap();
        let resolved = resolve_for_host(&blocks, "example");
        assert_eq!(resolved.user.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_equals_separator() {
        let content = "Host=example\nUser=alice\n";
        let blocks = parse_config(content).unwrap();
        let resolved = resolve_for_host(&blocks, "example");
        assert_eq!(resolved.user.as_deref(), Some("alice"));
    }

    #[test]
    fn unmatched_host_ignored() {
        let content = "\
Host other
    User bob
";
        let blocks = parse_config(content).unwrap();
        let resolved = resolve_for_host(&blocks, "example");
        assert!(resolved.user.is_none());
    }

    #[test]
    fn split_keyword_value_whitespace() {
        assert_eq!(split_keyword_value("User alice"), Some(("User", "alice")));
    }

    #[test]
    fn split_keyword_value_equals() {
        assert_eq!(split_keyword_value("User=alice"), Some(("User", "alice")));
    }

    #[test]
    fn split_keyword_value_tabs() {
        assert_eq!(split_keyword_value("User\talice"), Some(("User", "alice")));
    }
}
