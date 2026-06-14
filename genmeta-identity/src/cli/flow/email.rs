#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EmailVerificationAction {
    ReuseProvidedCode(String),
    SendAndPrompt,
}

impl EmailVerificationAction {
    pub(crate) fn from_verify_code(verify_code: Option<String>) -> Self {
        match verify_code {
            Some(code) => Self::ReuseProvidedCode(code),
            None => Self::SendAndPrompt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EmailVerificationAction;

    #[test]
    fn provided_verify_code_reuses_existing_code() {
        assert_eq!(
            EmailVerificationAction::from_verify_code(Some("000000".to_string())),
            EmailVerificationAction::ReuseProvidedCode("000000".to_string()),
        );
    }

    #[test]
    fn missing_verify_code_requires_send_and_prompt() {
        assert_eq!(
            EmailVerificationAction::from_verify_code(None),
            EmailVerificationAction::SendAndPrompt,
        );
    }
}
