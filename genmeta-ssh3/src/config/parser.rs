use std::{
    collections::HashMap,
    ops::{Add, AddAssign},
    str::FromStr,
};

use regex::Regex;

#[derive(Default, Debug, Clone)]
pub struct SshConfig {
    pub hosts: Vec<Host>,
}

impl SshConfig {
    pub fn query(&self, host: &str) -> HashMap<String, String> {
        let mut host_config = HashMap::new();
        (self.hosts.iter())
            .filter(|h| h.matches(host))
            .for_each(|host| {
                for (key, value) in &host.options {
                    host_config
                        .entry(key.clone())
                        .or_insert_with(|| value.clone());
                }
            });
        host_config
    }
}

impl Add<SshConfig> for SshConfig {
    type Output = Self;

    fn add(mut self, rhs: SshConfig) -> Self::Output {
        self += rhs;
        self
    }
}

impl AddAssign<SshConfig> for SshConfig {
    fn add_assign(&mut self, rhs: SshConfig) {
        self.hosts.extend(rhs.hosts);
    }
}

impl FromStr for SshConfig {
    type Err = peg::error::ParseError<peg::str::LineCol>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        ssh_config_parser::config(input)
    }
}

#[derive(Default, Debug, Clone)]
pub struct Host {
    pub patterns: Vec<Regex>,
    pub options: HashMap<String, String>,
}

impl Host {
    pub fn new(patterns: Vec<String>, options: HashMap<String, String>) -> Self {
        /// 将SSH通配符模式转换为正则表达式
        fn pattern_to_regex(pattern: &str) -> String {
            let mut regex = String::with_capacity(pattern.len() * 2);

            // 添加起始边界
            regex.push('^');

            // 逐字符处理模式
            for c in pattern.chars() {
                match c {
                    '*' => regex.push_str(".*"), // * 匹配0或多个任意字符
                    '?' => regex.push('.'),      // ? 匹配任何单个字符
                    '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' | '^' | '$' | '|' => {
                        // 转义正则表达式中的特殊字符
                        regex.push('\\');
                        regex.push(c);
                    }
                    _ => regex.push(c), // 普通字符直接添加
                }
            }

            // 添加结束边界
            regex.push('$');

            regex
        }

        Self {
            patterns: patterns
                .into_iter()
                .filter_map(|pattern| {
                    let re = pattern_to_regex(&pattern);
                    Regex::new(&re).inspect_err(|e| {
                        tracing::error!(target: "config", "Failed to compile regex for pattern '{pattern}': {e:?}");
                    }).ok()
                }).collect(),
            options,
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        self.patterns.iter().any(|pattern| pattern.is_match(host))
    }
}

peg::parser! {
    grammar ssh_config_parser() for str {
        rule whitespace() = [' ' | '\t']+

        rule newline() = "\r\n" / "\n" / "\r"

        rule comment() = "#" (!newline() [_])* newline()?

        rule _ = (whitespace() / comment() / newline())*

        rule i(literal: &'static str) -> &'static str =
            input:$([_]*<{literal.len()}>)
            {? if input.to_lowercase() == literal.to_lowercase() { Ok(literal) } else { Err(literal) } }

        rule host_patterns() -> Vec<String>
            = s:$([^' ' | '\t' | '\n' | '\r' | ',']+) { s.trim().split(',').map(|s| s.to_owned()).collect() }

        rule key() -> String
            = s:$(['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_']+) { s.to_lowercase() }

        rule value() -> String
            = s:$((!newline() [_])+) { s.trim().to_string() }

        rule option() -> (String, String)
            = k:key() _ v:value() _ { (k, v) }

        rule option_list() -> Vec<(String, String)>
            = options:((!host_declaration() o:option() { o })* ) { options }

        rule host_declaration() -> Vec<String>
            = i("Host") whitespace() p:host_patterns() _ { p }

        rule host_block() -> Either<(Vec<String>, Vec<(String, String)>), (String, String)>
            = h:host_declaration() options:option_list() {
                Either::Left((h, options))
            }

        rule global_option() -> Either<(Vec<String>, Vec<(String, String)>), (String, String)>
            = o:option() { Either::Right(o) }

        pub rule config() -> SshConfig
            = _ blocks:(host_block() / global_option())* _ {
                let mut config = SshConfig::default();

                for block in blocks {
                    match block {
                        Either::Left((host_pattern, options)) => {
                            let mut host_config = HashMap::new();
                            for (key, value) in options {
                                host_config.entry(key).or_insert(value);
                            }
                            config.hosts.push(Host::new(host_pattern, host_config));
                        },
                        Either::Right((key, value)) => {
                            if config.hosts.is_empty() {
                                config.hosts
                                    .push(Host::new(vec!["*".to_string()], HashMap::new()));
                            }
                            config.hosts[0].options.entry(key.clone()).or_insert(value);
                        }
                    }
                }

                config
            }
    }
}

enum Either<L, R> {
    Left(L),
    Right(R),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_config() {
        let config = r#"
IgnoreUnknown Custom

# Host-specific settings
Host github.com
    User git
    IdentityFile ~/.ssh/github_key

Host *.example.org
    Port 2222
    User admin

Host my-remote-dev
    Hostname alice.premium.genmeta.net

Host *
    Port 22
    User default_user
"#;

        let parsed = config.parse::<SshConfig>().unwrap();

        let github = parsed.query("github.com");
        assert_eq!(github["user"], "git");
        assert_eq!(github["identityfile"], "~/.ssh/github_key");

        let example = parsed.query("*.example.org");
        assert_eq!(example["port"], "2222");
        assert_eq!(example["user"], "admin");

        let example = parsed.query("www.example.org");
        assert_eq!(example["port"], "2222");
        assert_eq!(example["user"], "admin");

        let my_remote = parsed.query("my-remote-dev");
        assert_eq!(my_remote["hostname"], "alice.premium.genmeta.net");
        assert_eq!(my_remote["user"], "default_user");
        assert_eq!(my_remote["port"], "22");
        assert_eq!(my_remote["ignoreunknown"], "Custom");
    }
}
