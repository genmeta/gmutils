#[cfg(target_os = "linux")]
use std::fs;

use dhttp_home::HomeScope;

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
#[path = "../../../tests/unit/cli/flow/device.rs"]
mod tests;
