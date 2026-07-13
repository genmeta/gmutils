use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthMethod {
    Identity,
    Email,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailureKind {
    MissingIdentity,
    MtlsRejected,
    DomainForbidden,
    TransportUnavailable,
    CsrInvalid,
    SequenceInvalid,
    KindInvalid,
    ChainNotFound,
    SubscriptionInactive,
    PaymentRequired,
    ServerError,
}

/// Returns whether an automatic flow may use email after a stable
/// authentication failure.
///
/// The caller must already have established that the server permits email as
/// an alternate proof. Transport and server failures never change proof.
pub fn should_fallback_to_email(
    method: Option<AuthMethod>,
    can_get_email_credentials: bool,
    failure: AuthFailureKind,
) -> bool {
    method.is_none() && can_get_email_credentials && is_email_fallback_failure(failure)
}

pub fn is_email_fallback_failure(failure: AuthFailureKind) -> bool {
    matches!(
        failure,
        AuthFailureKind::MissingIdentity
            | AuthFailureKind::MtlsRejected
            | AuthFailureKind::DomainForbidden
    )
}

pub fn classify_api_error(error: &crate::cert_server::Error) -> AuthFailureKind {
    match error {
        crate::cert_server::Error::Api { status, code, .. } => match code.as_str() {
            "unauthorized" => AuthFailureKind::MtlsRejected,
            "domain_forbidden" => AuthFailureKind::DomainForbidden,
            "csr_invalid" => AuthFailureKind::CsrInvalid,
            "sequence_invalid" => AuthFailureKind::SequenceInvalid,
            "kind_invalid" => AuthFailureKind::KindInvalid,
            "cert_sequence_not_found" => AuthFailureKind::ChainNotFound,
            "domain_not_found" => AuthFailureKind::SubscriptionInactive,
            "payment_required" => AuthFailureKind::PaymentRequired,
            _ if status.is_server_error() => AuthFailureKind::ServerError,
            _ => AuthFailureKind::ServerError,
        },
        crate::cert_server::Error::Request { .. }
        | crate::cert_server::Error::DhttpEndpoint { .. }
        | crate::cert_server::Error::DhttpRequest { .. }
        | crate::cert_server::Error::DhttpRead { .. } => AuthFailureKind::TransportUnavailable,
        crate::cert_server::Error::IdentityFallbackUnavailable
        | crate::cert_server::Error::Json { .. }
        | crate::cert_server::Error::Whatever { .. } => AuthFailureKind::ServerError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_interactive_falls_back_for_credential_failures() {
        assert!(should_fallback_to_email(
            None,
            true,
            AuthFailureKind::MissingIdentity
        ));
        assert!(should_fallback_to_email(
            None,
            true,
            AuthFailureKind::MtlsRejected
        ));
        assert!(should_fallback_to_email(
            None,
            true,
            AuthFailureKind::DomainForbidden
        ));
    }

    #[test]
    fn transport_unavailability_does_not_fallback() {
        assert!(!should_fallback_to_email(
            None,
            true,
            AuthFailureKind::TransportUnavailable
        ));
    }

    #[test]
    fn auto_does_not_fallback_for_business_failures() {
        for failure in [
            AuthFailureKind::CsrInvalid,
            AuthFailureKind::SequenceInvalid,
            AuthFailureKind::KindInvalid,
            AuthFailureKind::ChainNotFound,
            AuthFailureKind::SubscriptionInactive,
            AuthFailureKind::PaymentRequired,
            AuthFailureKind::ServerError,
        ] {
            assert!(!should_fallback_to_email(None, true, failure));
        }
    }

    #[test]
    fn identity_and_email_policy_never_auto_fallback() {
        assert!(!should_fallback_to_email(
            Some(AuthMethod::Identity),
            true,
            AuthFailureKind::MissingIdentity
        ));
        assert!(!should_fallback_to_email(
            Some(AuthMethod::Email),
            true,
            AuthFailureKind::MissingIdentity
        ));
    }

    #[test]
    fn non_interactive_auto_does_not_prompt_fallback() {
        assert!(!should_fallback_to_email(
            None,
            false,
            AuthFailureKind::MissingIdentity
        ));
    }

    #[test]
    fn classifier_keeps_business_errors_out_of_auth_fallback() {
        let error = crate::cert_server::Error::Api {
            status: reqwest::StatusCode::NOT_FOUND,
            code: "cert_sequence_not_found".to_string(),
            message: "certificate sequence not found".to_string(),
        };

        assert_eq!(classify_api_error(&error), AuthFailureKind::ChainNotFound);
        assert!(!should_fallback_to_email(
            None,
            true,
            classify_api_error(&error)
        ));
    }

    #[test]
    fn classifier_keeps_server_and_unknown_client_errors_terminal() {
        for error in [
            crate::cert_server::Error::Api {
                status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                code: "internal_error".to_string(),
                message: "internal error".to_string(),
            },
            crate::cert_server::Error::Api {
                status: reqwest::StatusCode::CONFLICT,
                code: "future_conflict".to_string(),
                message: "future conflict".to_string(),
            },
        ] {
            let failure = classify_api_error(&error);
            assert_eq!(failure, AuthFailureKind::ServerError);
            assert!(!should_fallback_to_email(None, true, failure));
        }
    }
}
