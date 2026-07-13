use tracing_indicatif::{indicatif_eprintln, indicatif_println};

pub(crate) fn block_lines(block: &str) -> Vec<String> {
    block.split('\n').map(ToOwned::to_owned).collect()
}

pub(crate) fn print_block(block: &str) {
    for line in block_lines(block) {
        indicatif_println!("{line}");
    }
}

pub(crate) fn print_line(line: impl AsRef<str>) {
    indicatif_println!("{}", line.as_ref());
}

pub(crate) fn print_err_block(block: &str) {
    for line in block_lines(block) {
        indicatif_eprintln!("{line}");
    }
}

pub(crate) fn print_warning(message: &str) {
    let message = message.strip_prefix("WARN: ").unwrap_or(message);
    indicatif_eprintln!("WARN: {message}");
}

#[cfg(test)]
mod tests {
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
}
