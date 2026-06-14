#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerificationRecovery {
    StayCurrentStep { message: &'static str },
    BackToEmail { message: &'static str },
    Abort,
}

pub(crate) fn classify_resend_error(error: &crate::cert_server::Error) -> VerificationRecovery {
    match error {
        crate::cert_server::Error::Api { status, code, .. }
            if *status == reqwest::StatusCode::TOO_MANY_REQUESTS
                && code == "verify_code_too_frequent" =>
        {
            VerificationRecovery::StayCurrentStep {
                message: "The verification code was sent too recently. To continue, wait a moment and enter the existing code, or retry resend later.",
            }
        }
        crate::cert_server::Error::Request { .. }
        | crate::cert_server::Error::DhttpEndpoint { .. }
        | crate::cert_server::Error::DhttpRequest { .. }
        | crate::cert_server::Error::DhttpRead { .. } => VerificationRecovery::StayCurrentStep {
            message: "Failed to resend the verification code. To continue, check the network and try again.",
        },
        crate::cert_server::Error::Api { status, .. } if status.is_server_error() => {
            VerificationRecovery::Abort
        }
        _ => VerificationRecovery::BackToEmail {
            message: "The current verification session can no longer be used. To continue, enter your email again.",
        },
    }
}

pub(crate) fn classify_verify_submit_error(
    error: &crate::cert_server::Error,
) -> VerificationRecovery {
    match error {
        crate::cert_server::Error::Api { status, code, .. }
            if *status == reqwest::StatusCode::UNAUTHORIZED
                && matches!(code.as_str(), "verify_code_invalid" | "verify_code_expired") =>
        {
            VerificationRecovery::StayCurrentStep {
                message: "The verification code could not be used. To continue, enter the code again or choose another option.",
            }
        }
        crate::cert_server::Error::Api { status, code, .. }
            if *status == reqwest::StatusCode::TOO_MANY_REQUESTS
                && code == "verify_code_too_frequent" =>
        {
            VerificationRecovery::StayCurrentStep {
                message: "The verification code was sent too recently. To continue, wait a moment and enter the existing code, or retry resend later.",
            }
        }
        crate::cert_server::Error::Api { status, .. } if status.is_server_error() => {
            VerificationRecovery::Abort
        }
        _ => VerificationRecovery::BackToEmail {
            message: "The verification code session needs to be restarted. To continue, enter your email again.",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{VerificationRecovery, classify_resend_error, classify_verify_submit_error};

    #[test]
    fn resend_rate_limit_stays_on_current_step() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::TOO_MANY_REQUESTS,
            code: "verify_code_too_frequent".to_string(),
            message: "email code sent too frequently".to_string(),
        };

        assert_eq!(
            classify_resend_error(&error),
            VerificationRecovery::StayCurrentStep {
                message: "The verification code was sent too recently. To continue, wait a moment and enter the existing code, or retry resend later.",
            }
        );
    }

    #[test]
    fn verify_server_error_aborts() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error".to_string(),
            message: "boom".to_string(),
        };

        assert_eq!(
            classify_verify_submit_error(&error),
            VerificationRecovery::Abort
        );
    }
}
