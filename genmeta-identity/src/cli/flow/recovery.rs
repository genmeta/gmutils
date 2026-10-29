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
    let crate::cert_server::Error::Api { status, .. } = error else {
        return VerificationRecovery::Stop;
    };
    let message = error.to_string();
    match (*status, error.api_code()) {
        (reqwest::StatusCode::UNAUTHORIZED, Some("verify_code_invalid")) => {
            VerificationRecovery::RetryCode { message }
        }
        (reqwest::StatusCode::UNAUTHORIZED, Some("verify_code_expired")) => {
            VerificationRecovery::OfferResend { message }
        }
        (reqwest::StatusCode::UNAUTHORIZED, Some("domain_email_not_matched")) => {
            VerificationRecovery::ChangeEmail { message }
        }
        (
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            Some(
                "verify_code_too_frequent"
                | "verify_code_attempt_exceeded"
                | "verify_code_rate_limited",
            ),
        )
        | (reqwest::StatusCode::FORBIDDEN, Some("user_blocked")) => VerificationRecovery::Stop,
        _ => VerificationRecovery::Stop,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/recovery.rs"]
mod tests;
