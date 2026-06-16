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

impl StringValidator for EmailValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::CustomUserError> {
        if input.contains('@') && input.contains('.') {
            Ok(Validation::Valid)
        } else {
            Ok(validation_failed("Invalid email format."))
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
}
