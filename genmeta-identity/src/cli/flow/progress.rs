use std::{
    future::Future,
    io::{self, IsTerminal},
};

use tracing::info_span;
use tracing_indicatif::span_ext::IndicatifSpanExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletionPolicy {
    Clear,
    RetainOnTty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProgressCopy {
    pub(crate) running: &'static str,
    success: &'static str,
    completion: CompletionPolicy,
}

impl ProgressCopy {
    const fn clear(running: &'static str) -> Self {
        Self {
            running,
            success: "",
            completion: CompletionPolicy::Clear,
        }
    }

    const fn retain_on_tty(running: &'static str, success: &'static str) -> Self {
        Self {
            running,
            success,
            completion: CompletionPolicy::RetainOnTty,
        }
    }

    fn completion_message(self, is_terminal: bool) -> Option<&'static str> {
        if !is_terminal {
            return None;
        }
        match self.completion {
            CompletionPolicy::Clear => None,
            CompletionPolicy::RetainOnTty => Some(self.success),
        }
    }
}

pub(crate) const CHECK_NAME: ProgressCopy =
    ProgressCopy::clear("Checking the validity of this name...");
pub(crate) const SEND_CODE: ProgressCopy = ProgressCopy::clear("Sending verification code...");
pub(crate) const VERIFY_EMAIL: ProgressCopy = ProgressCopy::clear("Verifying with email...");
pub(crate) const GENERATE_KEY: ProgressCopy = ProgressCopy::retain_on_tty(
    "Generating secp384r1 ECC key pair locally...",
    "Generated secp384r1 ECC key pair locally.",
);
pub(crate) const REQUEST_CERT: ProgressCopy = ProgressCopy::retain_on_tty(
    "Generating CSR and requesting certificate...",
    "Generated CSR and requested certificate.",
);
pub(crate) const WAIT_FOR_PAYMENT: ProgressCopy =
    ProgressCopy::clear("Waiting for payment completion...");
pub(crate) const RENEW_IDENTITY: ProgressCopy = ProgressCopy::clear("Renewing identity...");
pub(crate) const SAVE_DEFAULT: ProgressCopy = ProgressCopy::clear("Saving default identity...");

pub(crate) async fn run<T, E>(
    copy: ProgressCopy,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let span = info_span!("cli_progress", indicatif.pb_show = tracing::field::Empty);
    span.pb_set_message(copy.running);
    span.pb_start();
    let result = future.await;
    if result.is_ok()
        && let Some(success) = copy.completion_message(io::stderr().is_terminal())
    {
        span.pb_set_finish_message(success);
    }
    drop(span);
    result
}

pub(crate) fn run_sync<T, E>(
    copy: ProgressCopy,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let span = info_span!("cli_progress", indicatif.pb_show = tracing::field::Empty);
    span.pb_set_message(copy.running);
    span.pb_start();
    let result = operation();
    if result.is_ok()
        && let Some(success) = copy.completion_message(io::stderr().is_terminal())
    {
        span.pb_set_finish_message(success);
    }
    drop(span);
    result
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tracing::Subscriber;
    use tracing_indicatif::filter::IndicatifFilter;
    use tracing_subscriber::{Layer, layer::SubscriberExt, registry::LookupSpan};

    use super::{
        CHECK_NAME, GENERATE_KEY, RENEW_IDENTITY, REQUEST_CERT, SAVE_DEFAULT, SEND_CODE,
        VERIFY_EMAIL, WAIT_FOR_PAYMENT, run, run_sync,
    };

    #[test]
    fn only_key_and_certificate_request_retain_success_on_tty() {
        assert_eq!(
            GENERATE_KEY.completion_message(true),
            Some("Generated secp384r1 ECC key pair locally.")
        );
        assert_eq!(
            REQUEST_CERT.completion_message(true),
            Some("Generated CSR and requested certificate.")
        );

        for copy in [
            CHECK_NAME,
            SEND_CODE,
            VERIFY_EMAIL,
            WAIT_FOR_PAYMENT,
            RENEW_IDENTITY,
            SAVE_DEFAULT,
        ] {
            assert_eq!(copy.completion_message(true), None, "copy: {copy:?}");
        }
    }

    #[test]
    fn non_tty_progress_has_no_completion_copy() {
        for copy in [
            CHECK_NAME,
            SEND_CODE,
            VERIFY_EMAIL,
            GENERATE_KEY,
            REQUEST_CERT,
            WAIT_FOR_PAYMENT,
            RENEW_IDENTITY,
            SAVE_DEFAULT,
        ] {
            assert_eq!(copy.completion_message(false), None, "copy: {copy:?}");
        }
    }

    #[derive(Clone, Default)]
    struct CountLayer(Arc<AtomicUsize>);

    impl<S> Layer<S> for CountLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            _attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn indicatif_filter_only_enables_marked_cli_progress_spans() {
        let layer = CountLayer::default();
        let seen = layer.0.clone();
        let subscriber =
            tracing_subscriber::registry().with(layer.with_filter(IndicatifFilter::new(false)));

        tracing::subscriber::with_default(subscriber, || {
            let _ordinary = tracing::info_span!("ordinary_background_span");
            assert_eq!(seen.load(Ordering::SeqCst), 0);
        });

        let layer = CountLayer::default();
        let seen = layer.0.clone();
        let subscriber =
            tracing_subscriber::registry().with(layer.with_filter(IndicatifFilter::new(false)));
        let _guard = tracing::subscriber::set_default(subscriber);
        run(SEND_CODE, async { Ok::<_, std::io::Error>(()) })
            .await
            .unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn operations_do_not_inherit_the_ui_progress_span() {
        let subscriber = tracing_subscriber::registry()
            .with(CountLayer::default().with_filter(IndicatifFilter::new(false)));
        let _guard = tracing::subscriber::set_default(subscriber);

        let async_parent = run(SEND_CODE, async {
            Ok::<_, std::io::Error>(tracing::Span::current().metadata().map(|meta| meta.name()))
        })
        .await
        .unwrap();
        assert_ne!(async_parent, Some("cli_progress"));

        let sync_parent = run_sync(SEND_CODE, || {
            Ok::<_, std::io::Error>(tracing::Span::current().metadata().map(|meta| meta.name()))
        })
        .unwrap();
        assert_ne!(sync_parent, Some("cli_progress"));
    }
}
