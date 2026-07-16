use inquire::validator::{StringValidator, Validation};

pub(crate) fn validation_failed(message: impl ToString) -> Validation {
    Validation::Invalid(inquire::validator::ErrorMessage::from(message))
}

pub fn validate_dhttp_label(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("label cannot be empty".to_string());
    }
    if trimmed.contains('.') {
        return Err("label must not contain dots".to_string());
    }
    if trimmed.starts_with('-') || trimmed.ends_with('-') {
        return Err("label must not start or end with '-'".to_string());
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err("label must contain only lowercase ascii letters, digits, or '-'".to_string());
    }
    Ok(())
}

pub fn validate_kind(value: &str) -> Result<(), String> {
    match value {
        "primary" | "secondary" => Ok(()),
        _ => Err("kind must be primary or secondary".to_string()),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KindValidator;

impl StringValidator for KindValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::CustomUserError> {
        Ok(match validate_kind(input) {
            Ok(()) => Validation::Valid,
            Err(message) => validation_failed(message),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EmailValidator;

pub(crate) fn is_valid_email(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.len() > 254 {
        return false;
    }

    let Some((local, domain)) = trimmed.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.len() > 64 {
        return false;
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    if domain.contains('@') {
        return false;
    }

    is_valid_email_domain(&domain.to_ascii_lowercase())
}

fn is_valid_email_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    let mut label_count = 0;
    for label in domain.split('.') {
        label_count += 1;
        let len = label.len();
        if !(1..=63).contains(&len)
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'-')
        {
            return false;
        }
    }

    label_count >= 2
}

impl StringValidator for EmailValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::CustomUserError> {
        if is_valid_email(input) {
            Ok(Validation::Valid)
        } else {
            Ok(validation_failed(
                "Invalid email address. Please enter a valid email address.",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
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
}
