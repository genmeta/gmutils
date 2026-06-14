#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApprovalHelperAction {
    Apply,
    Reapply,
    Renew,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalDirectLocal {
    pub(crate) short_name: String,
    pub(crate) auth_domain: String,
}

impl ApprovalDirectLocal {
    pub(crate) fn new(
        short_name: impl Into<String>,
        auth_domain: impl Into<String>,
    ) -> Self {
        Self {
            short_name: short_name.into(),
            auth_domain: auth_domain.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocalApprovalCandidate {
    Ready {
        short_name: String,
        auth_domain: String,
    },
    Expired {
        short_name: String,
        auth_domain: String,
        can_renew: bool,
        can_reapply: bool,
    },
    Incomplete {
        short_name: String,
        auth_domain: String,
        detail: String,
    },
    Invalid {
        short_name: String,
        auth_domain: String,
        detail: String,
    },
    Missing {
        short_name: String,
        auth_domain: String,
    },
}

impl LocalApprovalCandidate {
    pub(crate) fn ready(
        short_name: impl Into<String>,
        auth_domain: impl Into<String>,
    ) -> Self {
        Self::Ready {
            short_name: short_name.into(),
            auth_domain: auth_domain.into(),
        }
    }

    pub(crate) fn expired(
        short_name: impl Into<String>,
        auth_domain: impl Into<String>,
        can_renew: bool,
        can_reapply: bool,
    ) -> Self {
        Self::Expired {
            short_name: short_name.into(),
            auth_domain: auth_domain.into(),
            can_renew,
            can_reapply,
        }
    }

    pub(crate) fn incomplete(
        short_name: impl Into<String>,
        auth_domain: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::Incomplete {
            short_name: short_name.into(),
            auth_domain: auth_domain.into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn invalid(
        short_name: impl Into<String>,
        auth_domain: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::Invalid {
            short_name: short_name.into(),
            auth_domain: auth_domain.into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn missing(
        short_name: impl Into<String>,
        auth_domain: impl Into<String>,
    ) -> Self {
        Self::Missing {
            short_name: short_name.into(),
            auth_domain: auth_domain.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalHelperOption {
    pub(crate) action: ApprovalHelperAction,
    pub(crate) short_name: String,
    pub(crate) auth_domain: String,
    pub(crate) detail: Option<String>,
}

impl ApprovalHelperOption {
    #[cfg(test)]
    pub(crate) fn apply(short_name: impl Into<String>) -> Self {
        let short_name = short_name.into();
        Self::apply_for(short_name.clone(), short_name)
    }

    pub(crate) fn apply_for(
        short_name: impl Into<String>,
        auth_domain: impl Into<String>,
    ) -> Self {
        Self {
            action: ApprovalHelperAction::Apply,
            auth_domain: auth_domain.into(),
            short_name: short_name.into(),
            detail: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn reapply(
        short_name: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let short_name = short_name.into();
        Self::reapply_for(short_name.clone(), short_name, detail)
    }

    pub(crate) fn reapply_for(
        short_name: impl Into<String>,
        auth_domain: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            action: ApprovalHelperAction::Reapply,
            auth_domain: auth_domain.into(),
            short_name: short_name.into(),
            detail: Some(detail.into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn renew(short_name: impl Into<String>) -> Self {
        let short_name = short_name.into();
        Self::renew_for(short_name.clone(), short_name)
    }

    pub(crate) fn renew_for(
        short_name: impl Into<String>,
        auth_domain: impl Into<String>,
    ) -> Self {
        Self {
            action: ApprovalHelperAction::Renew,
            auth_domain: auth_domain.into(),
            short_name: short_name.into(),
            detail: None,
        }
    }

    pub(crate) fn label(&self) -> String {
        match self.action {
            ApprovalHelperAction::Apply => format!(
                "Apply {} to this device, then verify with {}",
                self.short_name, self.short_name
            ),
            ApprovalHelperAction::Reapply => format!(
                "Re-apply {} to this device, then verify with {}",
                self.short_name, self.short_name
            ),
            ApprovalHelperAction::Renew => format!(
                "Renew {} on this device, then verify with {}",
                self.short_name, self.short_name
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApprovalMenuOption {
    DirectLocal(ApprovalDirectLocal),
    Email { label: String },
    Helper(ApprovalHelperOption),
}

impl ApprovalMenuOption {
    pub(crate) fn label(&self) -> String {
        match self {
            Self::DirectLocal(option) => {
                format!("Verify with {} on local device", option.short_name)
            }
            Self::Email { label } => label.clone(),
            Self::Helper(option) => option.label(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalMenuSpec {
    pub(crate) email_label: String,
    pub(crate) direct_local: Vec<ApprovalDirectLocal>,
    pub(crate) helpers: Vec<ApprovalHelperOption>,
}

pub(crate) fn build_approval_options(spec: ApprovalMenuSpec) -> Vec<ApprovalMenuOption> {
    let mut options = spec
        .direct_local
        .into_iter()
        .map(ApprovalMenuOption::DirectLocal)
        .collect::<Vec<_>>();
    options.push(ApprovalMenuOption::Email {
        label: spec.email_label,
    });

    if options
        .iter()
        .any(|option| matches!(option, ApprovalMenuOption::DirectLocal(_)))
    {
        return options;
    }

    let mut helpers = spec.helpers;
    helpers.sort_by_key(|helper| match helper.action {
        ApprovalHelperAction::Renew => 0,
        ApprovalHelperAction::Reapply => 1,
        ApprovalHelperAction::Apply => 2,
    });
    options.extend(helpers.into_iter().map(ApprovalMenuOption::Helper));
    options
}

pub(crate) fn build_options_for_candidate(
    email_label: impl Into<String>,
    candidate: Option<LocalApprovalCandidate>,
) -> Vec<ApprovalMenuOption> {
    let mut direct_local = Vec::new();
    let mut helpers = Vec::new();

    match candidate {
        Some(LocalApprovalCandidate::Ready {
            short_name,
            auth_domain,
        }) => {
            direct_local.push(ApprovalDirectLocal::new(short_name, auth_domain));
        }
        Some(LocalApprovalCandidate::Expired {
            short_name,
            auth_domain,
            can_renew,
            can_reapply,
        }) => {
            if can_renew {
                helpers.push(ApprovalHelperOption::renew_for(
                    short_name.clone(),
                    auth_domain.clone(),
                ));
            }
            if can_reapply {
                helpers.push(ApprovalHelperOption::reapply_for(
                    short_name,
                    auth_domain,
                    "expired local identity",
                ));
            }
        }
        Some(LocalApprovalCandidate::Incomplete {
            short_name,
            auth_domain,
            detail,
        })
        | Some(LocalApprovalCandidate::Invalid {
            short_name,
            auth_domain,
            detail,
        }) => {
            helpers.push(ApprovalHelperOption::reapply_for(
                short_name,
                auth_domain,
                detail,
            ));
        }
        Some(LocalApprovalCandidate::Missing {
            short_name,
            auth_domain,
        }) => {
            helpers.push(ApprovalHelperOption::apply_for(short_name, auth_domain));
        }
        None => {}
    }

    build_approval_options(ApprovalMenuSpec {
        email_label: email_label.into(),
        direct_local,
        helpers,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalDirectLocal, ApprovalHelperOption, ApprovalMenuOption, ApprovalMenuSpec,
        build_approval_options,
    };

    #[test]
    fn direct_local_hides_helper_options() {
        let options = build_approval_options(ApprovalMenuSpec {
            email_label: "Verify with email".to_string(),
            direct_local: vec![ApprovalDirectLocal::new("alice.smith", "alice.smith")],
            helpers: vec![ApprovalHelperOption::apply("alice.smith")],
        });

        assert_eq!(
            options.iter().map(ApprovalMenuOption::label).collect::<Vec<_>>(),
            vec![
                "Verify with alice.smith on local device".to_string(),
                "Verify with email".to_string(),
            ]
        );
    }

    #[test]
    fn expired_identity_sorts_renew_before_reapply() {
        let options = build_approval_options(ApprovalMenuSpec {
            email_label: "Verify with email".to_string(),
            direct_local: vec![],
            helpers: vec![
                ApprovalHelperOption::reapply("alice.smith", "expired local identity"),
                ApprovalHelperOption::renew("alice.smith"),
            ],
        });

        assert_eq!(
            options.iter().map(ApprovalMenuOption::label).collect::<Vec<_>>(),
            vec![
                "Verify with email".to_string(),
                "Renew alice.smith on this device, then verify with alice.smith".to_string(),
                "Re-apply alice.smith to this device, then verify with alice.smith".to_string(),
            ]
        );
    }

    #[test]
    fn missing_local_identity_uses_apply_copy() {
        let option = ApprovalHelperOption::apply("alice.smith");

        assert_eq!(
            option.label(),
            "Apply alice.smith to this device, then verify with alice.smith"
        );
    }
}
