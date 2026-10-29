use super::IdentityKind;

#[test]
fn parses_primary_and_secondary() {
    assert_eq!(
        "primary".parse::<IdentityKind>().unwrap(),
        IdentityKind::Primary
    );
    assert_eq!(
        "secondary".parse::<IdentityKind>().unwrap(),
        IdentityKind::Secondary
    );
}

#[test]
fn keeps_wire_labels_separate_from_user_facing_usage_copy() {
    assert_eq!(IdentityKind::Primary.to_string(), "primary");
    assert_eq!(IdentityKind::Secondary.to_string(), "secondary");
    assert_eq!(IdentityKind::Primary.ski_flag(), "0");
    assert_eq!(IdentityKind::Secondary.ski_flag(), "1");
    assert_eq!(
        IdentityKind::from_ski_flag("0"),
        Some(IdentityKind::Primary)
    );
    assert_eq!(
        IdentityKind::from_ski_flag("1"),
        Some(IdentityKind::Secondary)
    );
    assert_eq!(IdentityKind::from_ski_flag("2"), None);
}
