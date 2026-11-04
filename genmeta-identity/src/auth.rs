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
            source: dhttp::Error::Home { .. } | dhttp::Error::Credentials { .. },
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
#[path = "../tests/unit/auth.rs"]
mod tests;
