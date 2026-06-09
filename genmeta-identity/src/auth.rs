use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthPolicy {
    Auto,
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

pub fn should_fallback_to_email(
    policy: AuthPolicy,
    interactive: bool,
    failure: AuthFailureKind,
) -> bool {
    matches!(policy, AuthPolicy::Auto)
        && interactive
        && matches!(
            failure,
            AuthFailureKind::MissingIdentity
                | AuthFailureKind::MtlsRejected
                | AuthFailureKind::DomainForbidden
                | AuthFailureKind::TransportUnavailable
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_interactive_falls_back_for_auth_only_failures() {
        assert!(should_fallback_to_email(
            AuthPolicy::Auto,
            true,
            AuthFailureKind::MissingIdentity
        ));
        assert!(should_fallback_to_email(
            AuthPolicy::Auto,
            true,
            AuthFailureKind::MtlsRejected
        ));
        assert!(should_fallback_to_email(
            AuthPolicy::Auto,
            true,
            AuthFailureKind::DomainForbidden
        ));
        assert!(should_fallback_to_email(
            AuthPolicy::Auto,
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
            assert!(!should_fallback_to_email(AuthPolicy::Auto, true, failure));
        }
    }

    #[test]
    fn identity_and_email_policy_never_auto_fallback() {
        assert!(!should_fallback_to_email(
            AuthPolicy::Identity,
            true,
            AuthFailureKind::MissingIdentity
        ));
        assert!(!should_fallback_to_email(
            AuthPolicy::Email,
            true,
            AuthFailureKind::MissingIdentity
        ));
    }

    #[test]
    fn non_interactive_auto_does_not_prompt_fallback() {
        assert!(!should_fallback_to_email(
            AuthPolicy::Auto,
            false,
            AuthFailureKind::MissingIdentity
        ));
    }
}
