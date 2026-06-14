use crossterm::style::Stylize;
use time::OffsetDateTime;

use super::{
    local::{
        InteractiveInventoryChoice, LocalIdentityStatus, LocalIdentitySummary, LocalInventory,
        LocalInventoryRoot,
    },
    target::IdentityLevel,
};

pub(crate) fn render_inventory(inventory: &LocalInventory, ansi: bool) -> String {
    let mut lines = Vec::new();
    let width = inventory
        .groups
        .iter()
        .flat_map(|group| {
            std::iter::once(root_label(&group.root).len()).chain(
                group
                    .children
                    .iter()
                    .map(|summary| child_label(summary).len()),
            )
        })
        .max()
        .unwrap_or_default()
        .max(40);

    for group in &inventory.groups {
        lines.push(render_root(&group.root, width, ansi));
        for (index, child) in group.children.iter().enumerate() {
            let branch = if index + 1 == group.children.len() {
                "└─ "
            } else {
                "├─ "
            };
            lines.push(render_line(
                render_summary_text(
                    &format!("{branch}{}", child.target.short_name()),
                    child,
                    width,
                ),
                summary_line_style(child),
                ansi,
            ));
        }
    }

    lines.join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineStyle {
    Plain,
    Bold,
    Dim,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DefaultIdentityBlock {
    None,
    NewlySet { name: String },
    Unchanged { name: String },
    Changed { old: String, new: String },
}

pub(crate) fn summary_line_style(summary: &LocalIdentitySummary) -> LineStyle {
    if matches!(
        summary.status,
        LocalIdentityStatus::Invalid { .. } | LocalIdentityStatus::Incomplete { .. }
    ) {
        LineStyle::Dim
    } else if summary.is_default {
        LineStyle::Bold
    } else {
        LineStyle::Plain
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

pub(crate) fn render_choice_label(choice: &InteractiveInventoryChoice, ansi: bool) -> String {
    match choice {
        InteractiveInventoryChoice::Saved(summary) => {
            let prefix = if matches!(summary.target.level(), IdentityLevel::SubIdentity) {
                "  "
            } else {
                ""
            };
            let mut label = format!(
                "{prefix}{} [{}]",
                summary.target.short_name(),
                summary.status.label()
            );
            if summary.is_default {
                label.push_str(" (default identity)");
            }
            render_line(label, summary_line_style(summary), ansi)
        }
        InteractiveInventoryChoice::Organization { target } => render_line(
            format!("{} (not saved locally)", target.short_name()),
            LineStyle::Dim,
            ansi,
        ),
        InteractiveInventoryChoice::EnterAnotherIdentity => "Enter another identity".to_string(),
    }
}

pub(crate) fn format_default_identity_block(block: &DefaultIdentityBlock) -> String {
    match block {
        DefaultIdentityBlock::None => "Default identity: (none)".to_string(),
        DefaultIdentityBlock::NewlySet { name } => {
            format!("Default identity: {name} (newly set)")
        }
        DefaultIdentityBlock::Unchanged { name } => {
            format!("Default identity: {name} (unchanged)")
        }
        DefaultIdentityBlock::Changed { old, new } => {
            format!("Default identity: {new} (changed from {old})")
        }
    }
}

pub(crate) fn format_safekeeping_reminder(ansi: bool) -> String {
    render_line(
        "Keep this identity material safe".to_string(),
        LineStyle::Bold,
        ansi,
    )
}

pub(crate) fn format_info(summary: &LocalIdentitySummary, ansi: bool) -> String {
    let mut lines = Vec::new();
    lines.push(render_line(
        format!("name: {}", summary_name(summary)),
        summary_line_style(summary),
        ansi,
    ));
    if let Some(certificate_chain) = summary.certificate_chain.as_ref() {
        lines.push(format!("certificate chain: {certificate_chain}"));
    }
    lines.push(format!("status: {}", format_status(summary.status.clone())));
    lines.push(format!("saved at: {}", summary.saved_at.display()));
    lines.join("\n")
}

pub(crate) fn format_default_summary(summary: &LocalIdentitySummary, ansi: bool) -> String {
    format_info(summary, ansi)
}

fn render_root(root: &LocalInventoryRoot, width: usize, ansi: bool) -> String {
    match root {
        LocalInventoryRoot::Saved(summary) => render_line(
            render_summary_text(&root_label(root), summary, width),
            summary_line_style(summary),
            ansi,
        ),
        LocalInventoryRoot::Organization { .. } => {
            render_line(root_label(root), LineStyle::Dim, ansi)
        }
    }
}

fn render_summary_text(label: &str, summary: &LocalIdentitySummary, width: usize) -> String {
    let supplement = match &summary.status {
        LocalIdentityStatus::Ready { .. } | LocalIdentityStatus::Expired { .. } => summary
            .certificate_chain
            .as_deref()
            .unwrap_or("(certificate chain unavailable)")
            .to_string(),
        LocalIdentityStatus::Incomplete { detail } | LocalIdentityStatus::Invalid { detail } => {
            format!("({detail})")
        }
    };

    format!(
        "{label:<width$}  {:<10}  {supplement}",
        summary.status.label(),
        width = width
    )
}

fn root_label(root: &LocalInventoryRoot) -> String {
    match root {
        LocalInventoryRoot::Saved(summary) => summary_label(summary),
        LocalInventoryRoot::Organization { target } => {
            format!("{} (not saved locally)", target.short_name())
        }
    }
}

fn child_label(summary: &LocalIdentitySummary) -> String {
    format!("├─ {}", summary.target.short_name())
}

fn summary_label(summary: &LocalIdentitySummary) -> String {
    let mut label = summary.target.short_name().to_string();
    if summary.is_default {
        label.push_str(" (default identity)");
    }
    label
}

fn summary_name(summary: &LocalIdentitySummary) -> String {
    let mut name = summary.target.short_name().to_string();
    if matches!(summary.target.level(), IdentityLevel::SubIdentity)
        && let Some(parent) = summary.target.parent()
    {
        name.push_str(&format!(" (sub-identity of {})", parent.as_partial()));
    }
    if summary.is_default {
        name.push_str(" (default identity)");
    }
    name
}

fn format_status(status: LocalIdentityStatus) -> String {
    match status {
        LocalIdentityStatus::Ready { expires_at } => {
            format!("ready (expires after {})", format_timestamp(expires_at))
        }
        LocalIdentityStatus::Expired { expired_at } => {
            format!("expired (expired after {})", format_timestamp(expired_at))
        }
        LocalIdentityStatus::Incomplete { detail } => format!("incomplete ({detail})"),
        LocalIdentityStatus::Invalid { detail } => format!("invalid ({detail})"),
    }
}

fn format_timestamp(timestamp: i64) -> String {
    let datetime = OffsetDateTime::from_unix_timestamp(timestamp)
        .expect("BUG: timestamps should be representable");
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        DefaultIdentityBlock, LineStyle, format_default_identity_block, format_default_summary,
        format_info, render_choice_label, render_inventory, summary_line_style,
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
            status,
            saved_at: PathBuf::from(format!("/tmp/{name}")),
            is_default,
        }
    }

    #[test]
    fn formats_compact_info_and_default_summary() {
        let profile = summary(
            "phone.alice.smith",
            true,
            LocalIdentityStatus::Ready {
                expires_at: EXPIRES_AT,
            },
            Some("secondary:2"),
        );

        let expected = "\
name: phone.alice.smith (sub-identity of alice.smith) (default identity)\n\
certificate chain: secondary:2\n\
status: ready (expires after 2026-11-10 08:12:44 UTC)\n\
saved at: /tmp/phone.alice.smith";

        assert_eq!(format_info(&profile, false), expected);
        assert_eq!(format_default_summary(&profile, false), expected);
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
    fn invalid_default_line_prefers_dim_over_bold() {
        let profile = summary(
            "alice.smith",
            true,
            LocalIdentityStatus::Invalid {
                detail: "certificate is unreadable".to_string(),
            },
            None,
        );

        assert_eq!(summary_line_style(&profile), LineStyle::Dim);
    }

    #[test]
    fn formats_none_default_block() {
        assert_eq!(
            format_default_identity_block(&DefaultIdentityBlock::None),
            "Default identity: (none)"
        );
    }

    #[test]
    fn renders_tree_inventory_lines() {
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
alice.smith (default identity)            ready       primary:0\n\
├─ phone.alice.smith                      ready       secondary:2\n\
└─ tv.alice.smith                         incomplete  (private key missing)\n\
reimu.scarlet (not saved locally)\n\
└─ tablet.reimu.scarlet                   expired     secondary:1";

        assert_eq!(render_inventory(&inventory, false), expected);
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
            render_choice_label(&InteractiveInventoryChoice::EnterAnotherIdentity, false),
        ];

        assert_eq!(
            labels,
            vec![
                "alice.smith [ready] (default identity)".to_string(),
                "reimu.scarlet (not saved locally)".to_string(),
                "  tablet.reimu.scarlet [ready]".to_string(),
                "Enter another identity".to_string(),
            ]
        );
    }
}
