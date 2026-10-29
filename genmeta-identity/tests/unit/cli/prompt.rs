use inquire::validator::{StringValidator, Validation};

use super::{
    MoreOptionsFriendlyValidator, email_prompt_message, enable_server_prompt_message,
    identity_name_help_message, identity_name_prompt_message, local_replacement_prompt_message,
    more_options_help_message, verify_code_prompt_message,
};

#[test]
fn prompt_copy_matches_the_approved_transcript() {
    assert_eq!(identity_name_prompt_message(), "Enter your name:");
    assert_eq!(
        identity_name_help_message(),
        "Name format: [handle.]your.name"
    );
    assert_eq!(email_prompt_message(), "Enter your email:");
    assert_eq!(verify_code_prompt_message(), "Enter verification code:");
    assert_eq!(more_options_help_message(), "Type ? for more options.");
    assert_eq!(
        enable_server_prompt_message(),
        "Enable server for this name?"
    );
    assert_eq!(
        local_replacement_prompt_message(),
        "This identity already exists locally. Continue and replace it?"
    );
}

#[test]
fn question_mark_bypasses_inner_validation() {
    #[derive(Clone)]
    struct RejectAll;

    impl StringValidator for RejectAll {
        fn validate(&self, _input: &str) -> Result<Validation, inquire::CustomUserError> {
            Ok(Validation::Invalid(inquire::validator::ErrorMessage::from(
                "always invalid",
            )))
        }
    }

    let validator = MoreOptionsFriendlyValidator::new(RejectAll);

    assert_eq!(validator.validate("?").unwrap(), Validation::Valid);
    assert_eq!(
        validator.validate("value").unwrap(),
        Validation::Invalid(inquire::validator::ErrorMessage::from("always invalid"))
    );
}
