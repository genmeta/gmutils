#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerificationRecovery {
    StayCurrentStep { message: String },
    OfferResend { message: String },
    BackToEmail { message: String },
    Abort,
}

pub(crate) fn format_resend_offer(message: &str) -> String {
    format!("{message}\n")
}

pub(crate) fn classify_resend_error(error: &crate::cert_server::Error) -> VerificationRecovery {
    match error {
        crate::cert_server::Error::Api {
            status,
            code,
            message,
        }
            if *status == reqwest::StatusCode::TOO_MANY_REQUESTS
                && matches!(
                    code.as_str(),
                    "verify_code_too_frequent"
                        | "verify_code_attempt_exceeded"
                        | "verify_code_rate_limited"
                ) =>
        {
            VerificationRecovery::StayCurrentStep {
                message: message.clone(),
            }
        }
        crate::cert_server::Error::Request { .. }
        | crate::cert_server::Error::DhttpEndpoint { .. }
        | crate::cert_server::Error::DhttpRequest { .. }
        | crate::cert_server::Error::DhttpRead { .. } => VerificationRecovery::StayCurrentStep {
            message: "Failed to resend the verification code. To continue, check the network and try again.".to_string(),
        },
        crate::cert_server::Error::Api { status, .. } if status.is_server_error() => {
            VerificationRecovery::Abort
        }
        crate::cert_server::Error::Api { message, .. } => VerificationRecovery::BackToEmail {
            message: message.clone(),
        },
        _ => VerificationRecovery::BackToEmail {
            message: "The current verification session can no longer be used. To continue, enter your email again.".to_string(),
        },
    }
}

pub(crate) fn classify_verify_submit_error(
    error: &crate::cert_server::Error,
) -> VerificationRecovery {
    match error {
        crate::cert_server::Error::Api {
            status,
            code,
            message,
        } if *status == reqwest::StatusCode::UNAUTHORIZED && code == "verify_code_expired" =>
        {
            VerificationRecovery::OfferResend {
                message: message.clone(),
            }
        }
        crate::cert_server::Error::Api {
            status,
            code,
            message,
        }
            if *status == reqwest::StatusCode::UNAUTHORIZED && code == "verify_code_invalid" =>
        {
            VerificationRecovery::StayCurrentStep {
                message: message.clone(),
            }
        }
        crate::cert_server::Error::Api {
            status,
            code,
            message,
        }
            if *status == reqwest::StatusCode::TOO_MANY_REQUESTS
                && code == "verify_code_too_frequent" =>
        {
            VerificationRecovery::StayCurrentStep {
                message: message.clone(),
            }
        }
        crate::cert_server::Error::Api { status, code, message }
            if *status == reqwest::StatusCode::UNAUTHORIZED
                && code == "domain_email_not_matched" =>
        {
            VerificationRecovery::BackToEmail {
                message: message.clone(),
            }
        }
        crate::cert_server::Error::Api {
            status,
            code,
            message,
        } if *status == reqwest::StatusCode::TOO_MANY_REQUESTS
            && code == "verify_code_attempt_exceeded" =>
        {
            VerificationRecovery::StayCurrentStep {
                message: message.clone(),
            }
        }
        crate::cert_server::Error::Api { status, code, .. }
            if *status == reqwest::StatusCode::FORBIDDEN && code == "user_blocked" =>
        {
            VerificationRecovery::Abort
        }
        crate::cert_server::Error::Api { status, .. } if status.is_server_error() => {
            VerificationRecovery::Abort
        }
        crate::cert_server::Error::Api { message, .. } => VerificationRecovery::BackToEmail {
            message: message.clone(),
        },
        _ => VerificationRecovery::BackToEmail {
            message: "The verification code session needs to be restarted. To continue, enter your email again.".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        VerificationRecovery, classify_resend_error, classify_verify_submit_error,
        format_resend_offer,
    };

    #[test]
    fn resend_offer_leaves_one_blank_line_before_the_confirm_prompt() {
        assert_eq!(
            format_resend_offer("verification code expired"),
            "verification code expired\n"
        );
    }

    #[test]
    fn resend_rate_limits_stay_on_current_step() {
        for code in [
            "verify_code_too_frequent",
            "verify_code_attempt_exceeded",
            "verify_code_rate_limited",
        ] {
            let error = crate::cert_server::Error::Api {
                status: reqwest::StatusCode::TOO_MANY_REQUESTS,
                code: code.to_string(),
                message: "email verification is temporarily rate limited".to_string(),
            };

            assert_eq!(
                classify_resend_error(&error),
                VerificationRecovery::StayCurrentStep {
                    message: "email verification is temporarily rate limited".to_string(),
                }
            );
        }
    }

    #[test]
    fn invalid_code_keeps_the_certserver_problem_message() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::UNAUTHORIZED,
            code: "verify_code_invalid".to_string(),
            message: "Your verification code is incorrect. Please try again.".to_string(),
        };

        assert_eq!(
            classify_verify_submit_error(&error),
            VerificationRecovery::StayCurrentStep {
                message: "Your verification code is incorrect. Please try again.".to_string(),
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

    #[test]
    fn blocked_user_aborts_verification() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::FORBIDDEN,
            code: "user_blocked".to_string(),
            message: "user is blocked".to_string(),
        };

        assert_eq!(
            classify_verify_submit_error(&error),
            VerificationRecovery::Abort
        );
    }

    #[test]
    fn verification_attempt_limit_stays_at_code_input() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::TOO_MANY_REQUESTS,
            code: "verify_code_attempt_exceeded".to_string(),
            message: "too many failed verification attempts, try again later".to_string(),
        };

        assert_eq!(
            classify_verify_submit_error(&error),
            VerificationRecovery::StayCurrentStep {
                message: "too many failed verification attempts, try again later".to_string(),
            }
        );
    }

    #[test]
    fn expired_code_offers_resend_with_server_message() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::UNAUTHORIZED,
            code: "verify_code_expired".to_string(),
            message: "verification code expired".to_string(),
        };

        assert_eq!(
            classify_verify_submit_error(&error),
            VerificationRecovery::OfferResend {
                message: "verification code expired".to_string(),
            }
        );
    }

    #[test]
    fn verify_domain_email_mismatch_goes_back_to_email() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::UNAUTHORIZED,
            code: "domain_email_not_matched".to_string(),
            message: "email does not match the current owner of the domain".to_string(),
        };

        assert_eq!(
            classify_verify_submit_error(&error),
            VerificationRecovery::BackToEmail {
                message: "email does not match the current owner of the domain".to_string(),
            }
        );
    }

    #[test]
    fn verify_other_client_errors_go_back_to_email() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::NOT_FOUND,
            code: "domain_not_found".to_string(),
            message: "domain not found".to_string(),
        };

        assert_eq!(
            classify_verify_submit_error(&error),
            VerificationRecovery::BackToEmail {
                message: "domain not found".to_string(),
            }
        );
    }

    #[test]
    fn resend_business_error_keeps_the_certserver_problem_message() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::UNAUTHORIZED,
            code: "verify_session_invalid".to_string(),
            message: "verification session is no longer valid".to_string(),
        };

        assert_eq!(
            classify_resend_error(&error),
            VerificationRecovery::BackToEmail {
                message: "verification session is no longer valid".to_string(),
            }
        );
    }
}
