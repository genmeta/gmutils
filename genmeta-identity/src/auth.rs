#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthAttemptDisposition {
    TryNext,
    ReplanMissingTarget,
    Terminal,
}

pub(crate) fn classify_identity_attempt(
    error: &crate::cert_server::Error,
) -> AuthAttemptDisposition {
    match error {
        crate::cert_server::Error::Api { code, .. } => match code.as_str() {
            "unauthorized" | "domain_forbidden" => AuthAttemptDisposition::TryNext,
            "domain_not_found" => AuthAttemptDisposition::ReplanMissingTarget,
            _ => AuthAttemptDisposition::Terminal,
        },
        crate::cert_server::Error::Request { .. }
        | crate::cert_server::Error::DhttpEndpoint { .. }
        | crate::cert_server::Error::DhttpRequest { .. }
        | crate::cert_server::Error::DhttpRead { .. }
        | crate::cert_server::Error::IdentityFallbackUnavailable
        | crate::cert_server::Error::Json { .. }
        | crate::cert_server::Error::Whatever { .. } => AuthAttemptDisposition::Terminal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(status: reqwest::StatusCode, code: &str) -> crate::cert_server::Error {
        crate::cert_server::Error::Api {
            status,
            code: code.to_string(),
            message: code.to_string(),
        }
    }

    #[test]
    fn only_explicit_auth_rejection_can_try_the_next_proof() {
        assert_eq!(
            classify_identity_attempt(&api(reqwest::StatusCode::UNAUTHORIZED, "unauthorized")),
            AuthAttemptDisposition::TryNext
        );
        assert_eq!(
            classify_identity_attempt(&api(reqwest::StatusCode::FORBIDDEN, "domain_forbidden")),
            AuthAttemptDisposition::TryNext
        );
        assert_eq!(
            classify_identity_attempt(&api(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error"
            )),
            AuthAttemptDisposition::Terminal
        );
        assert_eq!(
            classify_identity_attempt(&api(reqwest::StatusCode::CONFLICT, "future_code")),
            AuthAttemptDisposition::Terminal
        );
    }

    #[test]
    fn missing_apply_target_is_replanned_separately() {
        assert_eq!(
            classify_identity_attempt(&api(reqwest::StatusCode::NOT_FOUND, "domain_not_found")),
            AuthAttemptDisposition::ReplanMissingTarget
        );
        assert_eq!(
            classify_identity_attempt(&api(
                reqwest::StatusCode::NOT_FOUND,
                "cert_sequence_not_found"
            )),
            AuthAttemptDisposition::Terminal
        );
    }
}
