use std::future::Future;

use tracing::info_span;
use tracing_indicatif::span_ext::IndicatifSpanExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletionPolicy {
    Clear,
    Retain,
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

    const fn retain(running: &'static str, success: &'static str) -> Self {
        Self {
            running,
            success,
            completion: CompletionPolicy::Retain,
        }
    }

    fn completion_message(self) -> Option<&'static str> {
        match self.completion {
            CompletionPolicy::Clear => None,
            CompletionPolicy::Retain => Some(self.success),
        }
    }
}

const KEY_GENERATED: &str = "✔ Generate secp384r1 ECC key pair locally.";
const CERTIFICATE_REQUESTED: &str = "✔ Generate CSR locally and request certificate.";

pub(crate) const CHECK_NAME: ProgressCopy =
    ProgressCopy::clear("Checking the validity of this name...");
pub(crate) const SEND_CODE: ProgressCopy = ProgressCopy::clear("Sending verification code...");
pub(crate) const VERIFY_EMAIL: ProgressCopy = ProgressCopy::clear("Verifying with email...");
pub(crate) const GENERATE_KEY: ProgressCopy = ProgressCopy::retain(
    "Generating secp384r1 ECC key pair locally...",
    KEY_GENERATED,
);
pub(crate) const REQUEST_CERT: ProgressCopy = ProgressCopy::retain(
    "Generating CSR locally and requesting certificate...",
    CERTIFICATE_REQUESTED,
);
pub(crate) const WAIT_FOR_PAYMENT: ProgressCopy =
    ProgressCopy::clear("Waiting for payment completion...");
pub(crate) const RENEW_IDENTITY: ProgressCopy =
    ProgressCopy::retain("Renewing identity...", CERTIFICATE_REQUESTED);
pub(crate) const SAVE_DEFAULT: ProgressCopy = ProgressCopy::clear("Saving default identity...");

fn finish_success(copy: ProgressCopy) {
    let Some(success) = copy.completion_message() else {
        return;
    };

    // Do not rely on `pb_set_finish_message` to keep the completed line: a finished
    // progress bar can still be erased by later terminal redraws. Print the
    // completion as a permanent transcript line instead; the progress bar itself
    // is cleared when the span is dropped.
    super::transcript::print_line(success);
}

pub(crate) async fn run<T, E>(
    copy: ProgressCopy,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let span = info_span!("cli_progress", indicatif.pb_show = tracing::field::Empty);
    span.pb_set_message(copy.running);
    span.pb_start();
    let result = future.await;
    if result.is_ok() {
        finish_success(copy);
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
    if result.is_ok() {
        finish_success(copy);
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
    fn key_and_certificate_completions_are_stable() {
        assert_eq!(
            GENERATE_KEY.completion_message(),
            Some("✔ Generate secp384r1 ECC key pair locally.")
        );
        assert_eq!(
            REQUEST_CERT.completion_message(),
            Some("✔ Generate CSR locally and request certificate.")
        );
        assert_eq!(
            RENEW_IDENTITY.completion_message(),
            Some("✔ Generate CSR locally and request certificate.")
        );

        assert_eq!(
            REQUEST_CERT.running,
            "Generating CSR locally and requesting certificate..."
        );
        assert_eq!(RENEW_IDENTITY.running, "Renewing identity...");
    }

    #[test]
    fn transient_progress_has_no_completion_copy() {
        for copy in [
            CHECK_NAME,
            SEND_CODE,
            VERIFY_EMAIL,
            WAIT_FOR_PAYMENT,
            SAVE_DEFAULT,
        ] {
            assert_eq!(copy.completion_message(), None, "copy: {copy:?}");
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
