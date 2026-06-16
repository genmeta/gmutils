fn normalize_device_name(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn select_device_name(
    explicit: Option<&str>,
    detected_device_name: Option<&str>,
    detected_host_name: Option<&str>,
    fallback: &str,
) -> String {
    normalize_device_name(explicit)
        .or_else(|| normalize_device_name(detected_device_name))
        .or_else(|| normalize_device_name(detected_host_name))
        .or_else(|| normalize_device_name(Some(fallback)))
        .unwrap_or_else(|| crate::DEFAULT_DEVICE_NAME.to_string())
}

pub(crate) fn resolve_device_name(explicit: Option<&str>) -> String {
    let detected_device_name = whoami::devicename().ok();
    let detected_host_name = whoami::hostname().ok();
    select_device_name(
        explicit,
        detected_device_name.as_deref(),
        detected_host_name.as_deref(),
        crate::DEFAULT_DEVICE_NAME,
    )
}

#[cfg(test)]
mod tests {
    use super::select_device_name;

    #[test]
    fn explicit_device_name_wins() {
        assert_eq!(
            select_device_name(
                Some("custom device"),
                Some("Pretty Name"),
                Some("host"),
                "fallback",
            ),
            "custom device"
        );
    }

    #[test]
    fn detected_device_name_beats_hostname() {
        assert_eq!(
            select_device_name(None, Some("Pretty Name"), Some("host"), "fallback"),
            "Pretty Name"
        );
    }

    #[test]
    fn hostname_beats_generated_fallback() {
        assert_eq!(
            select_device_name(None, None, Some("host"), "fallback"),
            "host"
        );
    }

    #[test]
    fn falls_back_when_detection_is_missing() {
        assert_eq!(select_device_name(None, None, None, "fallback"), "fallback");
    }
}
