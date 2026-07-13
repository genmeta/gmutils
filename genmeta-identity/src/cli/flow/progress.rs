use std::{
    future::Future,
    io::{self, IsTerminal},
};

use tracing::{Instrument, info_span};
use tracing_indicatif::span_ext::IndicatifSpanExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProgressCopy {
    pub(crate) running: &'static str,
    pub(crate) success: &'static str,
}

impl ProgressCopy {
    pub(crate) const fn new(running: &'static str, success: &'static str) -> Self {
        Self { running, success }
    }
}

pub(crate) const CHECK_NAME: ProgressCopy = ProgressCopy::new(
    "Checking the validity of this name...",
    "Checked the validity of this name.",
);
pub(crate) const SEND_CODE: ProgressCopy =
    ProgressCopy::new("Sending verification code...", "Sent verification code.");
pub(crate) const VERIFY_EMAIL: ProgressCopy =
    ProgressCopy::new("Verifying with email...", "Verified with email.");
pub(crate) const GENERATE_KEY: ProgressCopy = ProgressCopy::new(
    "Generating secp384r1 ECC key pair locally...",
    "Generated secp384r1 ECC key pair locally.",
);
pub(crate) const REQUEST_CERT: ProgressCopy = ProgressCopy::new(
    "Generating CSR and requesting certificate...",
    "Generated CSR and requested certificate.",
);
pub(crate) const WAIT_FOR_PAYMENT: ProgressCopy =
    ProgressCopy::new("Waiting for payment completion...", "Payment completed.");
pub(crate) const RENEW_IDENTITY: ProgressCopy =
    ProgressCopy::new("Renewing identity...", "Renewed identity.");
pub(crate) const SAVE_DEFAULT: ProgressCopy =
    ProgressCopy::new("Saving default identity...", "Saved default identity.");

pub(crate) async fn run<T, E>(
    copy: ProgressCopy,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let span = info_span!("cli_progress", indicatif.pb_show = tracing::field::Empty);
    span.pb_set_message(copy.running);
    span.pb_start();
    let result = future.instrument(span.clone()).await;
    if result.is_ok() {
        retain_success(&span, copy.success);
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
    let result = {
        let _entered = span.enter();
        operation()
    };
    if result.is_ok() {
        retain_success(&span, copy.success);
    }
    drop(span);
    result
}

fn retain_success(span: &tracing::Span, success: &'static str) {
    if io::stderr().is_terminal() {
        span.pb_set_finish_message(success);
    } else {
        super::transcript::print_line(success);
    }
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
        CHECK_NAME, GENERATE_KEY, ProgressCopy, RENEW_IDENTITY, REQUEST_CERT, SAVE_DEFAULT,
        SEND_CODE, VERIFY_EMAIL, WAIT_FOR_PAYMENT, run,
    };

    #[test]
    fn progress_pairs_are_stable() {
        assert_eq!(
            CHECK_NAME,
            ProgressCopy::new(
                "Checking the validity of this name...",
                "Checked the validity of this name.",
            )
        );
        assert_eq!(SEND_CODE.success, "Sent verification code.");
        assert_eq!(VERIFY_EMAIL.success, "Verified with email.");
        assert_eq!(
            GENERATE_KEY.success,
            "Generated secp384r1 ECC key pair locally."
        );
        assert_eq!(
            REQUEST_CERT.success,
            "Generated CSR and requested certificate."
        );
        assert_eq!(WAIT_FOR_PAYMENT.success, "Payment completed.");
        assert_eq!(RENEW_IDENTITY.success, "Renewed identity.");
        assert_eq!(SAVE_DEFAULT.success, "Saved default identity.");
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
}
