use super::local::{
    LocalIdentityStatus, LocalIdentitySummary, LocalInventory, LocalInventoryRoot, is_near_expiry,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockStyle {
    bold: bool,
    dim: bool,
}

fn style_for(summary: &LocalIdentitySummary) -> BlockStyle {
    BlockStyle {
        bold: summary.is_default,
        dim: !matches!(summary.status, LocalIdentityStatus::Ready { .. }),
    }
}

fn render_block(text: String, style: BlockStyle, ansi: bool) -> String {
    if !ansi || (!style.bold && !style.dim) {
        return text;
    }

    let mut rendered = String::new();
    if style.bold {
        rendered.push_str("\u{1b}[1m");
    }
    if style.dim {
        rendered.push_str("\u{1b}[2m");
    }
    rendered.push_str(&text);
    rendered.push_str("\u{1b}[0m");
    rendered
}

fn marker(summary: &LocalIdentitySummary) -> char {
    if summary.is_default { '*' } else { '-' }
}

pub(crate) fn render_inventory(inventory: &LocalInventory, ansi: bool) -> String {
    inventory_summaries(inventory)
        .into_iter()
        .map(|summary| {
            render_block(
                format!("{} {}", marker(summary), compact_identity_label(summary)),
                style_for(summary),
                ansi,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn render_verbose_inventory(inventory: &LocalInventory, now: i64, ansi: bool) -> String {
    inventory_summaries(inventory)
        .into_iter()
        .map(|summary| format_info(summary, now, ansi))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn inventory_summaries(inventory: &LocalInventory) -> Vec<&LocalIdentitySummary> {
    let mut summaries = Vec::new();
    for group in &inventory.groups {
        if let LocalInventoryRoot::Saved(summary) = &group.root {
            summaries.push(summary);
        }
        summaries.extend(&group.children);
    }
    summaries.sort_by(|left, right| {
        right
            .is_default
            .cmp(&left.is_default)
            .then_with(|| left.target.short_name().cmp(right.target.short_name()))
    });
    summaries
}

pub(crate) fn compact_identity_label(summary: &LocalIdentitySummary) -> String {
    compact_identity_label_parts(
        summary.target.short_name(),
        &summary.status,
        summary.is_default,
    )
}

pub(crate) fn compact_identity_label_parts(
    name: &str,
    status: &LocalIdentityStatus,
    is_default: bool,
) -> String {
    let mut label = name.to_string();
    if !matches!(status, LocalIdentityStatus::Ready { .. }) {
        label.push_str(&format!(" [{}]", status.label()));
    }
    if is_default {
        label.push_str(" (default)");
    }
    label
}

pub(crate) fn format_info(summary: &LocalIdentitySummary, now: i64, ansi: bool) -> String {
    let mut lines = vec![format!(
        "{} {}:",
        marker(summary),
        compact_identity_label(summary)
    )];
    if let Some(usage) = summary.usage {
        lines.push(format!("  usage: {}", usage.label()));
    }
    if let Some(sequence) = summary.sequence {
        lines.push(format!("  sequence: {sequence}"));
    }
    lines.push(format!("  dir: {}", summary.dir.display()));
    if let (Some(valid_from), Some(expires_at)) = (summary.valid_from, summary.expires_at) {
        lines.push(format!(
            "  validity: {}~{}",
            format_slash_date(valid_from),
            format_slash_date(expires_at)
        ));
    }
    if let LocalIdentityStatus::Incomplete { detail } | LocalIdentityStatus::Invalid { detail } =
        &summary.status
    {
        lines.push(format!("  reason: {detail}"));
    }
    if let Some(warning) = warning(summary, now) {
        lines.push(format!("  warn: {warning}"));
    }

    render_block(lines.join("\n"), style_for(summary), ansi)
}

pub(crate) fn format_default_query(summary: &LocalIdentitySummary, now: i64) -> String {
    let mut lines = vec![compact_identity_label_parts(
        summary.target.short_name(),
        &summary.status,
        false,
    )];
    if let Some(warning) = warning(summary, now) {
        lines.push(format!("warn: {warning}"));
    }
    lines.join("\n")
}

fn warning(summary: &LocalIdentitySummary, now: i64) -> Option<String> {
    match summary.status {
        LocalIdentityStatus::Expired { expired_at } => Some(format!(
            "this name expired on {}, renew it in time or the name may be released",
            format_natural_date(expired_at)
        )),
        LocalIdentityStatus::Invalid { .. } => {
            Some("the certificate for this name is invalid".to_string())
        }
        LocalIdentityStatus::Incomplete { .. } => {
            Some("the local identity for this name is incomplete".to_string())
        }
        LocalIdentityStatus::Ready { .. } => match (summary.valid_from, summary.expires_at) {
            (Some(valid_from), Some(expires_at)) if is_near_expiry(valid_from, expires_at, now) => {
                Some(format!(
                    "this name will expire on {}, renew it in time",
                    format_natural_date(expires_at)
                ))
            }
            _ => None,
        },
    }
}

fn format_natural_date(timestamp: i64) -> String {
    let date = time::OffsetDateTime::from_unix_timestamp(timestamp)
        .expect("certificate timestamp should fit OffsetDateTime")
        .date();
    let month = match date.month() {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    };
    format!("{:02} {month} {}", date.day(), date.year())
}

fn format_slash_date(timestamp: i64) -> String {
    let date = time::OffsetDateTime::from_unix_timestamp(timestamp)
        .expect("certificate timestamp should fit OffsetDateTime")
        .date();
    format!(
        "{:04}/{:02}/{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/output.rs"]
mod tests;
