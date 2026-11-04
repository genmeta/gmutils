use dhttp_home::HomeScope;

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
        format_generated_device_name(HomeScope::User, Some("alice"), "gateway-01", Some("Ubuntu"),),
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
    let value =
        format_generated_device_name(HomeScope::User, Some("alice"), &long_host, Some("Ubuntu"));
    assert!(
        value.len() <= 128,
        "value length was {}: {value}",
        value.len()
    );
    assert!(value.starts_with("alice@"));
    assert!(!value.chars().any(char::is_control));
}
