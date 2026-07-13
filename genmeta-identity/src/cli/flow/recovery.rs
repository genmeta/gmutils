#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerificationRecovery {
    RetryCode { message: String },
    OfferResend { message: String },
    ChangeEmail { message: String },
    Stop,
}

pub(crate) fn classify_verify_submit_error(
    error: &crate::cert_server::Error,
) -> VerificationRecovery {
    match error {
        crate::cert_server::Error::Api {
            status,
            code,
            message,
        } => match (*status, code.as_str()) {
            (reqwest::StatusCode::UNAUTHORIZED, "verify_code_invalid") => {
                VerificationRecovery::RetryCode {
                    message: message.clone(),
                }
            }
            (reqwest::StatusCode::UNAUTHORIZED, "verify_code_expired") => {
                VerificationRecovery::OfferResend {
                    message: message.clone(),
                }
            }
            (reqwest::StatusCode::UNAUTHORIZED, "domain_email_not_matched") => {
                VerificationRecovery::ChangeEmail {
                    message: message.clone(),
                }
            }
            (
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                "verify_code_too_frequent"
                | "verify_code_attempt_exceeded"
                | "verify_code_rate_limited",
            )
            | (reqwest::StatusCode::FORBIDDEN, "user_blocked") => VerificationRecovery::Stop,
            _ => VerificationRecovery::Stop,
        },
        crate::cert_server::Error::Request { .. }
        | crate::cert_server::Error::DhttpEndpoint { .. }
        | crate::cert_server::Error::DhttpRequest { .. }
        | crate::cert_server::Error::DhttpRead { .. }
        | crate::cert_server::Error::IdentityFallbackUnavailable
        | crate::cert_server::Error::Json { .. }
        | crate::cert_server::Error::Whatever { .. } => VerificationRecovery::Stop,
    }
}

#[cfg(test)]
mod tests {
    use super::{VerificationRecovery, classify_verify_submit_error};

    fn api(status: reqwest::StatusCode, code: &str, message: &str) -> crate::cert_server::Error {
        crate::cert_server::Error::Api {
            status,
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    #[test]
    fn only_invalid_expired_and_email_mismatch_are_recoverable() {
        assert_eq!(
            classify_verify_submit_error(&api(
                reqwest::StatusCode::UNAUTHORIZED,
                "verify_code_invalid",
                "verification code is incorrect",
            )),
            VerificationRecovery::RetryCode {
                message: "verification code is incorrect".to_string(),
            }
        );
        assert_eq!(
            classify_verify_submit_error(&api(
                reqwest::StatusCode::UNAUTHORIZED,
                "verify_code_expired",
                "verification code expired",
            )),
            VerificationRecovery::OfferResend {
                message: "verification code expired".to_string(),
            }
        );
        assert_eq!(
            classify_verify_submit_error(&api(
                reqwest::StatusCode::UNAUTHORIZED,
                "domain_email_not_matched",
                "email does not match this identity",
            )),
            VerificationRecovery::ChangeEmail {
                message: "email does not match this identity".to_string(),
            }
        );
    }

    #[test]
    fn limits_blocks_server_and_unknown_errors_stop() {
        for error in [
            api(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                "verify_code_too_frequent",
                "try later",
            ),
            api(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                "verify_code_attempt_exceeded",
                "try later",
            ),
            api(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                "verify_code_rate_limited",
                "try later",
            ),
            api(
                reqwest::StatusCode::FORBIDDEN,
                "user_blocked",
                "user is blocked",
            ),
            api(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "boom",
            ),
            api(
                reqwest::StatusCode::CONFLICT,
                "future_code",
                "future problem",
            ),
        ] {
            assert_eq!(
                classify_verify_submit_error(&error),
                VerificationRecovery::Stop
            );
        }
    }
}
