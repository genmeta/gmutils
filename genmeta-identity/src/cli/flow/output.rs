use crossterm::style::Stylize;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SavedIdentityAction {
    Created,
    Applied,
    Renewed,
}

impl SavedIdentityAction {
    fn verb(self) -> &'static str {
        match self {
            Self::Created => "Created",
            Self::Applied => "Applied",
            Self::Renewed => "Renewed",
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
    let mut label = format!("{name} [{}]", status.label());
    if is_default {
        label.push_str(" (default identity)");
    }
    label
}

pub(crate) fn status_line_style(status: &LocalIdentityStatus) -> LineStyle {
    match status {
        LocalIdentityStatus::Invalid { .. } | LocalIdentityStatus::Incomplete { .. } => {
            LineStyle::Dim
        }
        LocalIdentityStatus::Ready { .. } | LocalIdentityStatus::Expired { .. } => LineStyle::Plain,
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

pub(crate) fn render_choice_label(choice: &InteractiveInventoryChoice, ansi: bool) -> String {
    match choice {
        InteractiveInventoryChoice::Saved(summary) => {
            let prefix = if matches!(summary.target.level(), IdentityLevel::SubIdentity) {
                "  "
            } else {
                ""
            };
            render_line(
                format!("{prefix}{}", compact_identity_label(summary)),
                summary_line_style(summary),
                ansi,
            )
        }
        InteractiveInventoryChoice::Organization { target } => render_line(
            format!("{} (not saved here)", target.short_name()),
            LineStyle::Dim,
            ansi,
        ),
    }
}

pub(crate) fn format_default_identity_sentence(block: &DefaultIdentityBlock) -> String {
    match block {
        DefaultIdentityBlock::None => "No default identity is set here".to_string(),
        DefaultIdentityBlock::NewlySet { name } => format!("Default identity set to {name}"),
        DefaultIdentityBlock::Unchanged { name } => format!("Default identity remains {name}"),
        DefaultIdentityBlock::Changed { old, new } => {
            format!("Default identity changed from {old} to {new}")
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

pub(crate) fn format_saved_identity_result(
    action: SavedIdentityAction,
    summary: &LocalIdentitySummary,
    ansi: bool,
) -> String {
    let mut lines = Vec::new();
    lines.push(render_line(
        format!(
            "{} identity {}",
            action.verb(),
            compact_identity_label(summary)
        ),
        summary_line_style(summary),
        ansi,
    ));
    lines.extend(detail_lines(summary));
    lines.join("\n")
}

pub(crate) fn format_info(summary: &LocalIdentitySummary, ansi: bool) -> String {
    let mut lines = Vec::new();
    lines.push(render_line(
        compact_identity_label(summary),
        summary_line_style(summary),
        ansi,
    ));
    lines.extend(detail_lines(summary));
    lines.join("\n")
}

pub(crate) fn format_default_summary(summary: &LocalIdentitySummary, ansi: bool) -> String {
    format_info(summary, ansi)
}

fn detail_lines(summary: &LocalIdentitySummary) -> Vec<String> {
    let mut lines = Vec::new();
    match (&summary.status, summary.certificate_chain.as_deref()) {
        (LocalIdentityStatus::Ready { .. }, Some(chain))
        | (LocalIdentityStatus::Expired { .. }, Some(chain)) => {
            lines.push(format!("  uses certificate chain {chain}"));
        }
        (LocalIdentityStatus::Incomplete { detail }, _)
        | (LocalIdentityStatus::Invalid { detail }, _) => {
            lines.push(format!("  {detail}"));
        }
        _ => {}
    }
    lines.push(format!("  saved at {}", summary.saved_at.display()));
    lines
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
            format!("{} (not saved here)", target.short_name())
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        DefaultIdentityBlock, LineStyle, SavedIdentityAction, compact_identity_label,
        format_current_default_suffix, format_default_identity_sentence, format_default_summary,
        format_info, format_saved_identity_result, render_choice_label, render_inventory,
        summary_line_style,
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

        let expected = "phone.alice.smith [ready] (default identity)\n  uses certificate chain secondary:2\n  saved at /tmp/phone.alice.smith";

        assert_eq!(format_info(&profile, false), expected);
        assert_eq!(format_default_summary(&profile, false), expected);
    }

    #[test]
    fn formats_created_identity_result() {
        let profile = summary(
            "alice.smith",
            false,
            LocalIdentityStatus::Ready {
                expires_at: EXPIRES_AT,
            },
            Some("primary:0"),
        );

        let expected = "Created identity alice.smith [ready]\n  uses certificate chain primary:0\n  saved at /tmp/alice.smith";

        assert_eq!(
            format_saved_identity_result(SavedIdentityAction::Created, &profile, false),
            expected,
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
    fn compact_label_uses_square_bracket_status_without_chain_id() {
        let profile = summary(
            "alice.smith",
            false,
            LocalIdentityStatus::Ready {
                expires_at: EXPIRES_AT,
            },
            Some("primary:0"),
        );

        assert_eq!(compact_identity_label(&profile), "alice.smith [ready]");
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
    fn formats_invalid_identity_without_field_labels() {
        let profile = summary(
            "alice.smith",
            false,
            LocalIdentityStatus::Invalid {
                detail: "certificate chain metadata is invalid".to_string(),
            },
            None,
        );

        let expected = "alice.smith [invalid]\n  certificate chain metadata is invalid\n  saved at /tmp/alice.smith";

        assert_eq!(format_info(&profile, false), expected);
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
    fn formats_default_identity_sentences() {
        assert_eq!(
            format_default_identity_sentence(&DefaultIdentityBlock::NewlySet {
                name: "alice.smith".to_string(),
            }),
            "Default identity set to alice.smith"
        );
        assert_eq!(
            format_default_identity_sentence(&DefaultIdentityBlock::Changed {
                old: "meng.lin".to_string(),
                new: "alice.smith".to_string(),
            }),
            "Default identity changed from meng.lin to alice.smith"
        );
        assert_eq!(
            format_default_identity_sentence(&DefaultIdentityBlock::Unchanged {
                name: "alice.smith".to_string(),
            }),
            "Default identity remains alice.smith"
        );
        assert_eq!(
            format_default_identity_sentence(&DefaultIdentityBlock::None),
            "No default identity is set here"
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
reimu.scarlet (not saved here)\n\
└─ tablet.reimu.scarlet                   expired     secondary:1";

        assert_eq!(render_inventory(&inventory, false), expected);
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
                "  shanghai.alice.ma [ready]".to_string(),
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
                "alice.smith [ready] (default identity)".to_string(),
                "reimu.scarlet (not saved here)".to_string(),
                "  tablet.reimu.scarlet [ready]".to_string(),
            ]
        );
    }
}
