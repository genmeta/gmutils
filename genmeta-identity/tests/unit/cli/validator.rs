use super::*;

#[test]
fn given_name_accepts_dns_label() {
    assert_eq!(validate_dhttp_label("alice"), Ok(()));
    assert_eq!(validate_dhttp_label("alice-1"), Ok(()));
}

#[test]
fn given_name_rejects_empty_or_dot() {
    assert!(validate_dhttp_label("").is_err());
    assert!(validate_dhttp_label("alice.smith").is_err());
}

#[test]
fn kind_accepts_primary_secondary() {
    assert_eq!(validate_kind("primary"), Ok(()));
    assert_eq!(validate_kind("secondary"), Ok(()));
    assert!(validate_kind("device").is_err());
}

#[test]
fn email_validation_matches_the_certserver_boundary() {
    for valid in [
        "alice@example.com",
        "Alice@Example.COM",
        "alice.example+billing@example.com",
        "  alice@example.com  ",
    ] {
        assert!(is_valid_email(valid), "expected valid email: {valid}");
    }

    let too_long_local = format!("{}@example.com", "a".repeat(65));
    let too_long_address = format!("{}@example.com", "a".repeat(243));
    for invalid in [
        "".to_string(),
        "alice".to_string(),
        "@example.com".to_string(),
        "alice@".to_string(),
        "alice@example@com".to_string(),
        ".alice@example.com".to_string(),
        "alice.@example.com".to_string(),
        "alice..billing@example.com".to_string(),
        "luffy.a@b".to_string(),
        "alice@.example.com".to_string(),
        "alice@-example.com".to_string(),
        "alice@example-.com".to_string(),
        "alice@bad_domain.com".to_string(),
        "alice@example..com".to_string(),
        too_long_local,
        too_long_address,
    ] {
        assert!(
            !is_valid_email(&invalid),
            "expected invalid email: {invalid}"
        );
    }
}

#[test]
fn invalid_email_uses_the_approved_actionable_copy() {
    assert_eq!(
        EmailValidator.validate("luffy.a@b").unwrap(),
        Validation::Invalid(inquire::validator::ErrorMessage::from(
            "Invalid email address. Please enter a valid email address."
        ))
    );
}
