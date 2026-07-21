#[cfg(target_os = "linux")]
use std::fs;

use dhttp::home::HomeScope;

const MAX_DEVICE_NAME_LEN: usize = 128;
const UNKNOWN_USER: &str = "unknown-user";
const UNKNOWN_PLATFORM: &str = "unknown platform";

pub(crate) fn normalize_explicit_device_name(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_generated_component(value: Option<&str>) -> Option<String> {
    let cleaned = value?
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
    }
}

fn normalize_platform_component(value: Option<&str>) -> Option<String> {
    let value = normalize_generated_component(value)?;
    let lower = value.to_ascii_lowercase();
    if lower == "unknown" || lower.starts_with("unknown:") {
        None
    } else {
        Some(value)
    }
}

fn truncate_to_device_name_limit(value: String) -> String {
    if value.len() <= MAX_DEVICE_NAME_LEN {
        return value;
    }

    let mut truncated = String::with_capacity(MAX_DEVICE_NAME_LEN);
    for ch in value.chars() {
        if truncated.len() + ch.len_utf8() > MAX_DEVICE_NAME_LEN {
            break;
        }
        truncated.push(ch);
    }

    let truncated = truncated.trim().to_string();
    if truncated.is_empty() {
        crate::DEFAULT_DEVICE_NAME.to_string()
    } else {
        truncated
    }
}

pub(crate) fn select_host_label(
    hostname: Option<&str>,
    devicename: Option<&str>,
    fallback: &str,
) -> String {
    normalize_generated_component(hostname)
        .or_else(|| normalize_generated_component(devicename))
        .or_else(|| normalize_generated_component(Some(fallback)))
        .unwrap_or_else(|| crate::DEFAULT_DEVICE_NAME.to_string())
}

pub(crate) fn format_generated_device_name(
    home_scope: HomeScope,
    username: Option<&str>,
    host: &str,
    platform: Option<&str>,
) -> String {
    let host = normalize_generated_component(Some(host))
        .unwrap_or_else(|| crate::DEFAULT_DEVICE_NAME.to_string());
    let platform =
        normalize_platform_component(platform).unwrap_or_else(|| UNKNOWN_PLATFORM.to_string());

    let generated = match home_scope {
        HomeScope::Global => format!("{host} ({platform})"),
        HomeScope::User => {
            let username =
                normalize_generated_component(username).unwrap_or_else(|| UNKNOWN_USER.to_string());
            format!("{username}@{host} ({platform})")
        }
    };

    truncate_to_device_name_limit(generated)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_os_release_name(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let value = line.trim().strip_prefix("NAME=")?.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(value);
        normalize_generated_component(Some(value))
    })
}

#[cfg(target_os = "linux")]
fn detect_platform_label() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| linux_os_release_name(&content))
        .unwrap_or_else(|| "Linux".to_string())
}

#[cfg(not(target_os = "linux"))]
fn detect_platform_label() -> String {
    let platform = whoami::platform().to_string();
    normalize_platform_component(Some(&platform)).unwrap_or_else(|| UNKNOWN_PLATFORM.to_string())
}

pub(crate) fn resolve_device_name(explicit: Option<&str>, home_scope: HomeScope) -> String {
    if let Some(explicit) = normalize_explicit_device_name(explicit) {
        return explicit;
    }

    let username = if matches!(home_scope, HomeScope::User) {
        whoami::username().ok()
    } else {
        None
    };
    let hostname = whoami::hostname().ok();
    let devicename = whoami::devicename().ok();
    let host = select_host_label(
        hostname.as_deref(),
        devicename.as_deref(),
        crate::DEFAULT_DEVICE_NAME,
    );
    let platform = detect_platform_label();

    format_generated_device_name(home_scope, username.as_deref(), &host, Some(&platform))
}

#[cfg(test)]
mod tests {
    use dhttp::home::HomeScope;

    #[cfg(target_os = "linux")]
    use super::linux_os_release_name;
    use super::{format_generated_device_name, normalize_explicit_device_name, select_host_label};

    #[test]
    fn explicit_device_name_is_only_trimmed() {
        assert_eq!(
            normalize_explicit_device_name(Some("  custom device  ")).as_deref(),
            Some("custom device")
        );
    }

    #[test]
    fn user_home_uses_username_hostname_and_platform() {
        assert_eq!(
            format_generated_device_name(
                HomeScope::User,
                Some("alice"),
                "gateway-01",
                Some("Ubuntu"),
            ),
            "alice@gateway-01 (Ubuntu)"
        );
    }

    #[test]
    fn global_home_omits_username() {
        assert_eq!(
            format_generated_device_name(
                HomeScope::Global,
                Some("alice"),
                "gateway-01",
                Some("Ubuntu"),
            ),
            "gateway-01 (Ubuntu)"
        );
    }

    #[test]
    fn missing_user_name_is_distinct_from_global_home() {
        assert_eq!(
            format_generated_device_name(HomeScope::User, None, "gateway-01", Some("Ubuntu")),
            "unknown-user@gateway-01 (Ubuntu)"
        );
    }

    #[test]
    fn hostname_beats_device_name_for_host_component() {
        assert_eq!(
            select_host_label(Some("host"), Some("Pretty Name"), "fallback"),
            "host"
        );
    }

    #[test]
    fn device_name_is_host_fallback_when_hostname_is_missing() {
        assert_eq!(
            select_host_label(None, Some("Pretty Name"), "fallback"),
            "Pretty Name"
        );
    }

    #[test]
    fn platform_fallback_keeps_parentheses() {
        assert_eq!(
            format_generated_device_name(HomeScope::User, Some("alice"), "host", None),
            "alice@host (unknown platform)"
        );
    }

    #[test]
    fn unknown_platform_label_falls_back_to_unknown_platform() {
        assert_eq!(
            format_generated_device_name(
                HomeScope::User,
                Some("alice"),
                "host",
                Some("Unknown: MysteryOS"),
            ),
            "alice@host (unknown platform)"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_os_release_name_reads_name_not_pretty_name() {
        let content = r#"PRETTY_NAME="Ubuntu 24.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
"#;
        assert_eq!(linux_os_release_name(content).as_deref(), Some("Ubuntu"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_os_release_name_accepts_unquoted_name() {
        let content = "ID=arch\nNAME=Arch Linux\n";
        assert_eq!(
            linux_os_release_name(content).as_deref(),
            Some("Arch Linux")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_os_release_name_ignores_empty_name() {
        assert_eq!(linux_os_release_name("NAME=\"\"\n"), None);
    }

    #[test]
    fn generated_name_is_limited_to_certserver_device_name_size() {
        let long_host = "h".repeat(180);
        let value = format_generated_device_name(
            HomeScope::User,
            Some("alice"),
            &long_host,
            Some("Ubuntu"),
        );
        assert!(
            value.len() <= 128,
            "value length was {}: {value}",
            value.len()
        );
        assert!(value.starts_with("alice@"));
        assert!(!value.chars().any(char::is_control));
    }
}
