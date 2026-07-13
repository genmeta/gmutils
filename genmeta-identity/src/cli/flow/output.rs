use crossterm::style::Stylize;

#[cfg(test)]
use super::local::InteractiveInventoryChoice;
use super::local::{LocalIdentityStatus, LocalIdentitySummary, LocalInventory, LocalInventoryRoot};

pub(crate) fn render_inventory(inventory: &LocalInventory, ansi: bool) -> String {
    inventory_summaries(inventory)
        .into_iter()
        .map(|summary| {
            render_line(
                format!("- {}", compact_identity_label(summary)),
                summary_line_style(summary),
                ansi,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn render_verbose_inventory(inventory: &LocalInventory, ansi: bool) -> String {
    inventory_summaries(inventory)
        .into_iter()
        .map(|summary| format_info(summary, ansi))
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
    summaries.sort_by_key(|summary| !summary.is_default);
    summaries
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineStyle {
    Plain,
    Bold,
    Dim,
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

pub(crate) fn summary_line_style(summary: &LocalIdentitySummary) -> LineStyle {
    match status_line_style(&summary.status) {
        LineStyle::Dim => LineStyle::Dim,
        LineStyle::Plain if summary.is_default => LineStyle::Bold,
        LineStyle::Plain => LineStyle::Plain,
        LineStyle::Bold => LineStyle::Bold,
    }
}

fn render_line(text: String, style: LineStyle, ansi: bool) -> String {
    if !ansi {
        return text;
    }

    match style {
        LineStyle::Plain => text,
        LineStyle::Bold => text.bold().to_string(),
        LineStyle::Dim => text.dim().to_string(),
    }
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

pub(crate) fn status_line_style(status: &LocalIdentityStatus) -> LineStyle {
    match status {
        LocalIdentityStatus::Expired { .. } => LineStyle::Dim,
        LocalIdentityStatus::Ready { .. }
        | LocalIdentityStatus::Invalid { .. }
        | LocalIdentityStatus::Incomplete { .. } => LineStyle::Plain,
    }
}

pub(crate) fn format_current_default_suffix(
    name: &str,
    status: &LocalIdentityStatus,
    ansi: bool,
) -> String {
    render_line(
        format!(
            "(current: {})",
            compact_identity_label_parts(name, status, false)
        ),
        LineStyle::Dim,
        ansi,
    )
}

#[cfg(test)]
pub(crate) fn render_choice_label(choice: &InteractiveInventoryChoice, ansi: bool) -> String {
    match choice {
        InteractiveInventoryChoice::Saved(summary) => render_line(
            compact_identity_label(summary),
            summary_line_style(summary),
            ansi,
        ),
        InteractiveInventoryChoice::Organization { target } => render_line(
            format!("{} (not saved here)", target.short_name()),
            LineStyle::Dim,
            ansi,
        ),
    }
}

pub(crate) fn format_saved_identity_result(
    action: SavedIdentityAction,
    summary: &LocalIdentitySummary,
    _ansi: bool,
) -> String {
    let mut result = format!("{} identity {}", action.verb(), summary.target.short_name());
    if let Some(chain) = summary.certificate_chain.as_deref() {
        result.push_str(&format!(" as {chain}"));
    }
    result.push_str(&format!(" at {}", summary.saved_at.display()));
    result
}

pub(crate) fn format_info(summary: &LocalIdentitySummary, ansi: bool) -> String {
    let mut lines = Vec::new();
    lines.push(render_line(
        identity_summary_label(summary),
        summary_line_style(summary),
        ansi,
    ));
    lines.extend(detail_lines(summary));
    lines.join("\n")
}

fn identity_summary_label(summary: &LocalIdentitySummary) -> String {
    let mut label = summary.target.short_name().to_string();
    if !matches!(summary.status, LocalIdentityStatus::Ready { .. }) {
        label.push_str(&format!(" [{}]", summary.status.label()));
    }
    if let Some(chain) = summary.certificate_chain.as_deref() {
        label.push_str(&format!(" as {chain}"));
    }
    if summary.is_default {
        label.push_str(" (default)");
    }
    label
}

#[cfg(test)]
pub(crate) fn format_default_summary(summary: &LocalIdentitySummary, ansi: bool) -> String {
    format_info(summary, ansi)
}

pub(crate) fn format_default_query(summary: &LocalIdentitySummary) -> String {
    let name = summary.target.short_name();
    match summary.status {
        LocalIdentityStatus::Expired { expired_at } => format!(
            "{name}\n\nWARNING: This name expired on {}. Renew it in time or the name may be released!\n         Run `genmeta identity renew {name}` to renew it.",
            format_natural_date(expired_at),
        ),
        _ => name.to_string(),
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

fn format_iso_date(timestamp: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(timestamp)
        .expect("certificate timestamp should fit OffsetDateTime")
        .date()
        .to_string()
}

fn detail_lines(summary: &LocalIdentitySummary) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(issuer) = summary.issuer.as_deref() {
        lines.push(format!("Issuer: {issuer}"));
    }
    if let Some(valid_from) = summary.valid_from {
        lines.push(format!("Valid from: {}", format_iso_date(valid_from)));
    }
    if let Some(expires_at) = summary.status.expires_at() {
        let label = if matches!(summary.status, LocalIdentityStatus::Expired { .. }) {
            "Expired"
        } else {
            "Expires"
        };
        lines.push(format!("{label}: {}", format_iso_date(expires_at)));
    }
    lines.push(format!("dir: {}", summary.saved_at.display()));
    if let LocalIdentityStatus::Incomplete { detail } | LocalIdentityStatus::Invalid { detail } =
        &summary.status
    {
        lines.push(format!("reason: {detail}"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        LineStyle, SavedIdentityAction, compact_identity_label, format_current_default_suffix,
        format_default_query, format_default_summary, format_info, format_saved_identity_result,
        render_choice_label, render_inventory, render_verbose_inventory, summary_line_style,
    };
    use crate::cli::flow::{
        local::{
            InteractiveInventoryChoice, LocalIdentityStatus, LocalIdentitySummary, build_inventory,
        },
        target::IdentityTarget,
    };

    const EXPIRES_AT: i64 = 1_794_298_364;

    fn summary(
        name: &str,
        is_default: bool,
        status: LocalIdentityStatus,
        chain: Option<&str>,
    ) -> LocalIdentitySummary {
        LocalIdentitySummary {
            target: IdentityTarget::parse(name).unwrap(),
            certificate_chain: chain.map(ToOwned::to_owned),
            valid_from: Some(1_700_000_000),
            issuer: Some("CN=Genmeta Test CA".to_string()),
            status,
            saved_at: PathBuf::from(format!("/tmp/{name}")),
            is_default,
        }
    }

    #[test]
    fn formats_info_with_dir_detail() {
        let profile = summary(
            "phone.alice.smith",
            true,
            LocalIdentityStatus::Ready {
                expires_at: EXPIRES_AT,
            },
            Some("secondary:2"),
        );

        let rendered = format_info(&profile, false);
        assert_eq!(
            rendered,
            "phone.alice.smith as secondary:2 (default)\nIssuer: CN=Genmeta Test CA\nValid from: 2023-11-14\nExpires: 2026-11-10\ndir: /tmp/phone.alice.smith"
        );
        assert_eq!(format_default_summary(&profile, false), rendered);
    }

    #[test]
    fn formats_saved_identity_as_one_line_result() {
        let profile = summary(
            "alice.smith",
            false,
            LocalIdentityStatus::Ready {
                expires_at: EXPIRES_AT,
            },
            Some("primary:0"),
        );

        assert_eq!(
            format_saved_identity_result(SavedIdentityAction::Applied, &profile, false),
            "Applied identity alice.smith as primary:0 at /tmp/alice.smith"
        );
    }

    #[test]
    fn expired_default_query_keeps_name_and_actionable_warning() {
        let profile = summary(
            "alice.smith",
            true,
            LocalIdentityStatus::Expired {
                expired_at: 1_783_478_400,
            },
            Some("primary:0"),
        );

        assert_eq!(
            format_default_query(&profile),
            "alice.smith\n\nWARNING: This name expired on 08 Jul 2026. Renew it in time or the name may be released!\n         Run `genmeta identity renew alice.smith` to renew it.",
        );
    }

    #[test]
    fn ready_default_line_prefers_bold() {
        let profile = summary(
            "alice.smith",
            true,
            LocalIdentityStatus::Ready {
                expires_at: EXPIRES_AT,
            },
            Some("primary:0"),
        );

        assert_eq!(summary_line_style(&profile), LineStyle::Bold);
    }

    #[test]
    fn expired_line_is_dimmed() {
        let profile = summary(
            "alice.smith",
            false,
            LocalIdentityStatus::Expired {
                expired_at: EXPIRES_AT,
            },
            Some("primary:0"),
        );

        assert_eq!(summary_line_style(&profile), LineStyle::Dim);
    }

    #[test]
    fn compact_label_hides_ready_status() {
        let profile = summary(
            "alice.smith",
            false,
            LocalIdentityStatus::Ready {
                expires_at: EXPIRES_AT,
            },
            Some("primary:0"),
        );

        assert_eq!(compact_identity_label(&profile), "alice.smith");
    }

    #[test]
    fn invalid_default_line_remains_bold_and_visible() {
        let profile = summary(
            "alice.smith",
            true,
            LocalIdentityStatus::Invalid {
                detail: "certificate is unreadable".to_string(),
            },
            None,
        );

        assert_eq!(summary_line_style(&profile), LineStyle::Bold);
    }

    #[test]
    fn formats_invalid_identity_with_reason_detail() {
        let profile = summary(
            "alice.smith",
            false,
            LocalIdentityStatus::Invalid {
                detail: "certificate chain metadata is invalid".to_string(),
            },
            None,
        );

        let rendered = format_info(&profile, false);
        assert!(rendered.starts_with("alice.smith [invalid]"));
        assert!(rendered.contains("\ndir: /tmp/alice.smith"));
        assert!(rendered.contains("\nreason: certificate chain metadata is invalid"));
    }

    #[test]
    fn current_default_suffix_uses_compact_label_text() {
        assert_eq!(
            format_current_default_suffix(
                "meng.lin",
                &LocalIdentityStatus::Invalid {
                    detail: "certificate is unreadable".to_string(),
                },
                false,
            ),
            "(current: meng.lin [invalid])"
        );
    }

    #[test]
    fn renders_flat_compact_inventory_lines() {
        let inventory = build_inventory(vec![
            summary(
                "tablet.reimu.scarlet",
                false,
                LocalIdentityStatus::Expired {
                    expired_at: EXPIRES_AT,
                },
                Some("secondary:1"),
            ),
            summary(
                "tv.alice.smith",
                false,
                LocalIdentityStatus::Incomplete {
                    detail: "private key missing".to_string(),
                },
                None,
            ),
            summary(
                "phone.alice.smith",
                false,
                LocalIdentityStatus::Ready {
                    expires_at: EXPIRES_AT,
                },
                Some("secondary:2"),
            ),
            summary(
                "alice.smith",
                true,
                LocalIdentityStatus::Ready {
                    expires_at: EXPIRES_AT,
                },
                Some("primary:0"),
            ),
        ]);

        let expected = "\
- alice.smith (default)\n\
- phone.alice.smith\n\
- tv.alice.smith [incomplete]\n\
- tablet.reimu.scarlet [expired]";

        assert_eq!(render_inventory(&inventory, false), expected);
    }

    #[test]
    fn default_sub_identity_is_the_first_list_entry() {
        let inventory = build_inventory(vec![
            summary(
                "alice.smith",
                false,
                LocalIdentityStatus::Ready {
                    expires_at: EXPIRES_AT,
                },
                Some("primary:0"),
            ),
            summary(
                "phone.alice.smith",
                true,
                LocalIdentityStatus::Ready {
                    expires_at: EXPIRES_AT,
                },
                Some("secondary:1"),
            ),
        ]);

        assert_eq!(
            render_inventory(&inventory, false),
            "- phone.alice.smith (default)\n- alice.smith"
        );
    }

    #[test]
    fn verbose_inventory_reuses_info_renderer() {
        let inventory = build_inventory(vec![summary(
            "alice.smith",
            true,
            LocalIdentityStatus::Ready {
                expires_at: EXPIRES_AT,
            },
            Some("primary:0"),
        )]);

        let summary = &match &inventory.groups[0].root {
            crate::cli::flow::local::LocalInventoryRoot::Saved(summary) => summary,
            crate::cli::flow::local::LocalInventoryRoot::Organization { .. } => unreachable!(),
        };
        assert_eq!(
            render_verbose_inventory(&inventory, false),
            format_info(summary, false)
        );
    }

    #[test]
    fn renew_chain_key_labels_include_parent_root_before_child() {
        let labels = vec![
            render_choice_label(
                &InteractiveInventoryChoice::Organization {
                    target: IdentityTarget::parse("alice.ma").unwrap(),
                },
                false,
            ),
            render_choice_label(
                &InteractiveInventoryChoice::Saved(summary(
                    "shanghai.alice.ma",
                    false,
                    LocalIdentityStatus::Ready {
                        expires_at: EXPIRES_AT,
                    },
                    Some("secondary:1"),
                )),
                false,
            ),
        ];

        assert_eq!(
            labels,
            vec![
                "alice.ma (not saved here)".to_string(),
                "shanghai.alice.ma".to_string(),
            ]
        );
    }

    #[test]
    fn renders_choice_labels_without_ansi_effects() {
        let labels = vec![
            render_choice_label(
                &InteractiveInventoryChoice::Saved(summary(
                    "alice.smith",
                    true,
                    LocalIdentityStatus::Ready {
                        expires_at: EXPIRES_AT,
                    },
                    Some("primary:0"),
                )),
                false,
            ),
            render_choice_label(
                &InteractiveInventoryChoice::Organization {
                    target: IdentityTarget::parse("reimu.scarlet").unwrap(),
                },
                false,
            ),
            render_choice_label(
                &InteractiveInventoryChoice::Saved(summary(
                    "tablet.reimu.scarlet",
                    false,
                    LocalIdentityStatus::Ready {
                        expires_at: EXPIRES_AT,
                    },
                    Some("secondary:1"),
                )),
                false,
            ),
        ];

        assert_eq!(
            labels,
            vec![
                "alice.smith (default)".to_string(),
                "reimu.scarlet (not saved here)".to_string(),
                "tablet.reimu.scarlet".to_string(),
            ]
        );
    }
}
