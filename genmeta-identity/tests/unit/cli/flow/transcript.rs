use super::block_lines;

#[test]
fn block_lines_preserve_internal_blank_lines() {
    assert_eq!(
        block_lines("Open this checkout page to continue:\n\n  https://example.test"),
        vec![
            "Open this checkout page to continue:".to_string(),
            "".to_string(),
            "  https://example.test".to_string(),
        ]
    );
}

#[test]
fn warning_prefix_is_stable() {
    assert_eq!(
        "WARN: already prefixed".strip_prefix("WARN: "),
        Some("already prefixed")
    );
}
