#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthAttemptDisposition {
    TryNext,
    ReplanMissingTarget,
    Terminal,
}

pub(crate) fn classify_identity_attempt(
    error: &crate::cert_server::Error,
) -> AuthAttemptDisposition {
    if let crate::cert_server::Error::Api { status, .. } = error {
        return match (*status, error.api_code()) {
            (reqwest::StatusCode::UNAUTHORIZED, Some("unauthorized"))
            | (reqwest::StatusCode::FORBIDDEN, Some("domain_forbidden")) => {
                AuthAttemptDisposition::TryNext
            }
            (reqwest::StatusCode::NOT_FOUND, Some("domain_not_found")) => {
                AuthAttemptDisposition::ReplanMissingTarget
            }
            _ => AuthAttemptDisposition::Terminal,
        };
    }

    match error {
        crate::cert_server::Error::DhttpEndpointFromProfile {
            source: dhttp::endpoint::LoadEndpointFromPathError::LoadIdentity { .. },
        } => AuthAttemptDisposition::TryNext,
        crate::cert_server::Error::Request { .. }
        | crate::cert_server::Error::DhttpEndpoint { .. }
        | crate::cert_server::Error::DhttpRequest { .. }
        | crate::cert_server::Error::DhttpRead { .. }
        | crate::cert_server::Error::IdentityFallbackUnavailable
        | crate::cert_server::Error::Json { .. }
        | crate::cert_server::Error::Whatever { .. }
        | crate::cert_server::Error::DhttpEndpointFromProfile { .. } => {
            AuthAttemptDisposition::Terminal
        }
        crate::cert_server::Error::Api { .. } => {
            unreachable!("API errors returned from the branch above")
        }
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
            classify_identity_attempt(&api(reqwest::StatusCode::UNAUTHORIZED, "1002")),
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
        assert_eq!(
            classify_identity_attempt(&api(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "unauthorized"
            )),
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
            classify_identity_attempt(&api(reqwest::StatusCode::NOT_FOUND, "1202")),
            AuthAttemptDisposition::ReplanMissingTarget
        );
        assert_eq!(
            classify_identity_attempt(&api(
                reqwest::StatusCode::NOT_FOUND,
                "cert_sequence_not_found"
            )),
            AuthAttemptDisposition::Terminal
        );
        assert_eq!(
            classify_identity_attempt(&api(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "domain_not_found"
            )),
            AuthAttemptDisposition::Terminal
        );
    }

    #[tokio::test]
    async fn selected_profile_load_failure_can_try_the_next_proof() {
        let missing = std::env::temp_dir().join(format!(
            "genmeta-auth-missing-profile-{}",
            std::process::id()
        ));
        let source = match dhttp::endpoint::Endpoint::load_from(missing).await {
            Ok(_) => panic!("missing identity profile unexpectedly loaded"),
            Err(source) => source,
        };
        let error = crate::cert_server::Error::DhttpEndpointFromProfile { source };

        assert_eq!(
            classify_identity_attempt(&error),
            AuthAttemptDisposition::TryNext
        );
    }
}
