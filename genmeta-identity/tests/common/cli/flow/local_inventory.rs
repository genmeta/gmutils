use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InteractiveInventoryChoice {
    Saved(LocalIdentitySummary),
    Organization { target: IdentityTarget },
}

pub(crate) fn build_renew_inventory_choices(
    inventory: &LocalInventory,
) -> Vec<InteractiveInventoryChoice> {
    let mut choices = Vec::new();
    for group in &inventory.groups {
        match &group.root {
            LocalInventoryRoot::Saved(summary) => {
                choices.push(InteractiveInventoryChoice::Saved(summary.clone()));
            }
            LocalInventoryRoot::Organization { target } => {
                choices.push(InteractiveInventoryChoice::Organization {
                    target: target.clone(),
                });
            }
        }
        choices.extend(
            group
                .children
                .iter()
                .cloned()
                .map(InteractiveInventoryChoice::Saved),
        );
    }
    choices
}

pub(crate) fn build_default_inventory_choices(
    inventory: &LocalInventory,
) -> Vec<InteractiveInventoryChoice> {
    let mut choices = Vec::new();
    for group in &inventory.groups {
        match &group.root {
            LocalInventoryRoot::Saved(summary) => {
                choices.push(InteractiveInventoryChoice::Saved(summary.clone()));
            }
            LocalInventoryRoot::Organization { target } => {
                choices.push(InteractiveInventoryChoice::Organization {
                    target: target.clone(),
                });
            }
        }
        choices.extend(
            group
                .children
                .iter()
                .cloned()
                .map(InteractiveInventoryChoice::Saved),
        );
    }
    choices
}
