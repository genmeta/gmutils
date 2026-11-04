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
#[path = "../../tests/unit/cli/validator.rs"]
mod tests;
