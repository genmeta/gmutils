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
#[path = "../../../tests/unit/cli/flow/transcript.rs"]
mod tests;
