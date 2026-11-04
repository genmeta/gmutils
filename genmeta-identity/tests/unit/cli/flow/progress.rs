use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tracing::Subscriber;
use tracing_indicatif::filter::IndicatifFilter;
use tracing_subscriber::{Layer, layer::SubscriberExt, registry::LookupSpan};

use super::{
    CHECK_NAME, GENERATE_KEY, RENEW_IDENTITY, REQUEST_CERT, SAVE_DEFAULT, SEND_CODE, VERIFY_EMAIL,
    WAIT_FOR_PAYMENT, run, run_sync,
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
