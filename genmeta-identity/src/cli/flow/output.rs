#[cfg(test)]
use super::local::InteractiveInventoryChoice;
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

pub(crate) fn format_current_default_suffix(
    name: &str,
    status: &LocalIdentityStatus,
    ansi: bool,
) -> String {
    render_block(
        format!(
            "(current: {})",
            compact_identity_label_parts(name, status, false)
        ),
        BlockStyle {
            bold: false,
            dim: true,
        },
        ansi,
    )
}

#[cfg(test)]
pub(crate) fn render_choice_label(choice: &InteractiveInventoryChoice, ansi: bool) -> String {
    match choice {
        InteractiveInventoryChoice::Saved(summary) => {
            render_block(compact_identity_label(summary), style_for(summary), ansi)
        }
        InteractiveInventoryChoice::Organization { target } => render_block(
            format!("{} (not saved here)", target.short_name()),
            BlockStyle {
                bold: false,
                dim: true,
            },
            ansi,
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SavedIdentityAction {
    Applied,
}

impl SavedIdentityAction {
    fn verb(self) -> &'static str {
        match self {
            Self::Applied => "Applied",
        }
    }
}

pub(crate) fn format_saved_identity_result(
    action: SavedIdentityAction,
    summary: &LocalIdentitySummary,
    _ansi: bool,
) -> String {
    format!(
        "{} identity {} at {}",
        action.verb(),
        summary.target.short_name(),
        summary.dir.display()
    )
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
mod tests {
    use std::path::PathBuf;

    use super::{
        SavedIdentityAction, format_current_default_suffix, format_default_query, format_info,
        format_saved_identity_result, render_choice_label, render_inventory,
        render_verbose_inventory,
    };
    use crate::cli::flow::{
        local::{
            IdentityUsage, InteractiveInventoryChoice, LocalIdentityStatus, LocalIdentitySummary,
            build_inventory,
        },
        target::IdentityTarget,
    };

    const NOW: i64 = 1_784_026_800; // 14 Jul 2026 UTC

    fn timestamp(year: i32, month: time::Month, day: u8) -> i64 {
        time::Date::from_calendar_date(year, month, day)
            .unwrap()
            .midnight()
            .assume_utc()
            .unix_timestamp()
    }

    fn summary(
        name: &str,
        is_default: bool,
        status: LocalIdentityStatus,
        usage: Option<IdentityUsage>,
        sequence: Option<u32>,
        valid_from: Option<i64>,
        expires_at: Option<i64>,
    ) -> LocalIdentitySummary {
        LocalIdentitySummary {
            target: IdentityTarget::parse(name).unwrap(),
            usage,
            sequence,
            valid_from,
            expires_at,
            status,
            dir: PathBuf::from(format!("/tmp/{name}")),
            is_default,
        }
    }

    fn ready_default() -> LocalIdentitySummary {
        let valid_from = timestamp(2026, time::Month::July, 8);
        let expires_at = timestamp(2027, time::Month::July, 8);
        summary(
            "alice.smith",
            true,
            LocalIdentityStatus::Ready { expires_at },
            Some(IdentityUsage::BothClientAndServer),
            Some(0),
            Some(valid_from),
            Some(expires_at),
        )
    }

    fn near_expiry() -> LocalIdentitySummary {
        let valid_from = timestamp(2025, time::Month::September, 1);
        let expires_at = timestamp(2026, time::Month::September, 1);
        summary(
            "alice.smith",
            true,
            LocalIdentityStatus::Ready { expires_at },
            Some(IdentityUsage::BothClientAndServer),
            Some(0),
            Some(valid_from),
            Some(expires_at),
        )
    }

    fn expired(is_default: bool) -> LocalIdentitySummary {
        let valid_from = timestamp(2025, time::Month::July, 8);
        let expires_at = timestamp(2026, time::Month::July, 8);
        summary(
            "alice.smith",
            is_default,
            LocalIdentityStatus::Expired {
                expired_at: expires_at,
            },
            Some(IdentityUsage::BothClientAndServer),
            Some(0),
            Some(valid_from),
            Some(expires_at),
        )
    }

    fn invalid(name: &str, is_default: bool) -> LocalIdentitySummary {
        summary(
            name,
            is_default,
            LocalIdentityStatus::Invalid {
                detail: "certificate is unreadable".to_string(),
            },
            None,
            None,
            None,
            None,
        )
    }

    fn incomplete(name: &str) -> LocalIdentitySummary {
        let valid_from = timestamp(2026, time::Month::July, 8);
        let expires_at = timestamp(2027, time::Month::July, 8);
        summary(
            name,
            false,
            LocalIdentityStatus::Incomplete {
                detail: "private key is missing".to_string(),
            },
            Some(IdentityUsage::BothClientAndServer),
            Some(0),
            Some(valid_from),
            Some(expires_at),
        )
    }

    #[test]
    fn detailed_renderer_matches_ready_near_expired_invalid_and_incomplete_contract() {
        assert_eq!(
            format_info(&ready_default(), NOW, false),
            "* alice.smith (default):\n  usage: both client and server\n  sequence: 0\n  dir: /tmp/alice.smith\n  validity: 2026/07/08~2027/07/08"
        );
        assert!(
            format_info(&near_expiry(), NOW, false)
                .ends_with("  warn: this name will expire on 01 Sep 2026, renew it in time")
        );
        assert!(format_info(&expired(false), NOW, false).ends_with(
            "  warn: this name expired on 08 Jul 2026, renew it in time or the name may be released"
        ));
        assert_eq!(
            format_info(&invalid("alice.smith", false), NOW, false),
            "- alice.smith [invalid]:\n  dir: /tmp/alice.smith\n  reason: certificate is unreadable\n  warn: the certificate for this name is invalid"
        );
        assert!(format_info(&incomplete("alice.smith"), NOW, false).contains(
            "  reason: private key is missing\n  warn: the local identity for this name is incomplete"
        ));
    }

    #[test]
    fn compact_inventory_is_default_first_then_canonical_name() {
        let mut expired = expired(false);
        expired.target = IdentityTarget::parse("bruce.lee").unwrap();
        expired.dir = PathBuf::from("/tmp/bruce.lee");
        let inventory = build_inventory(vec![
            invalid("phone.alice.smith", false),
            summary(
                "luffy.monkey",
                false,
                LocalIdentityStatus::Ready {
                    expires_at: timestamp(2027, time::Month::July, 8),
                },
                Some(IdentityUsage::BothClientAndServer),
                Some(0),
                Some(timestamp(2026, time::Month::July, 8)),
                Some(timestamp(2027, time::Month::July, 8)),
            ),
            incomplete("tablet.alice.smith"),
            expired,
            ready_default(),
        ]);

        assert_eq!(
            render_inventory(&inventory, false),
            "* alice.smith (default)\n- bruce.lee [expired]\n- luffy.monkey\n- phone.alice.smith [invalid]\n- tablet.alice.smith [incomplete]"
        );
    }

    #[test]
    fn default_and_abnormal_styles_wrap_the_complete_detail_block() {
        let default = format_info(&ready_default(), NOW, true);
        assert!(default.starts_with("\u{1b}[1m"), "{default:?}");
        assert!(default.ends_with("\u{1b}[0m"), "{default:?}");
        assert_eq!(default.matches("\u{1b}[1m").count(), 1, "{default:?}");

        let abnormal_default = format_info(&expired(true), NOW, true);
        assert!(
            abnormal_default.contains("\u{1b}[1m"),
            "{abnormal_default:?}"
        );
        assert!(
            abnormal_default.contains("\u{1b}[2m"),
            "{abnormal_default:?}"
        );
        assert!(
            abnormal_default.contains("  validity:"),
            "{abnormal_default:?}"
        );
        assert_eq!(abnormal_default.matches("\u{1b}[0m").count(), 1);
    }

    #[test]
    fn default_query_uses_compact_warning_fields() {
        assert_eq!(
            format_default_query(&expired(false), NOW),
            "alice.smith [expired]\nwarn: this name expired on 08 Jul 2026, renew it in time or the name may be released"
        );
        assert_eq!(
            format_default_query(&invalid("alice.smith", false), NOW),
            "alice.smith [invalid]\nwarn: the certificate for this name is invalid"
        );
    }

    #[test]
    fn verbose_inventory_reuses_info_renderer() {
        let inventory = build_inventory(vec![ready_default(), incomplete("tablet.alice.smith")]);
        let rendered = render_verbose_inventory(&inventory, NOW, false);
        assert!(rendered.starts_with("* alice.smith (default):"));
        assert!(rendered.contains("\n\n- tablet.alice.smith [incomplete]:"));
    }

    #[test]
    fn saved_result_and_prompt_helpers_remain_stable() {
        let profile = ready_default();
        assert_eq!(
            format_saved_identity_result(SavedIdentityAction::Applied, &profile, false),
            "Applied identity alice.smith at /tmp/alice.smith"
        );
        assert_eq!(
            format_current_default_suffix("alice.smith", &profile.status, false),
            "(current: alice.smith)"
        );
        assert_eq!(
            render_choice_label(&InteractiveInventoryChoice::Saved(profile), false),
            "alice.smith (default)"
        );
    }
}
