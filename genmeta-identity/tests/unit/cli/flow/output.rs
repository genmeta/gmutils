use std::path::PathBuf;

use super::{
    BlockStyle, compact_identity_label, format_default_query, format_info, render_block,
    render_inventory, render_verbose_inventory, style_for,
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
fn verbose_default_info_and_verbose_list_share_the_same_block() {
    let summary = near_expiry();
    let expected = format_info(&summary, NOW, false);
    let inventory = build_inventory(vec![summary]);

    assert_eq!(render_verbose_inventory(&inventory, NOW, false), expected);
}

#[test]
fn saved_choice_label_remains_stable() {
    let profile = ready_default();
    assert_eq!(
        render_choice_label(&InteractiveInventoryChoice::Saved(profile), false),
        "alice.smith (default)"
    );
}

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
