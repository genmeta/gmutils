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

pub(crate) fn print_error(line: impl AsRef<str>) {
    indicatif_eprintln!("{}", line.as_ref());
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
}
