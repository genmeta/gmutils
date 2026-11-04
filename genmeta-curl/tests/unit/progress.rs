use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tracing::Subscriber;
use tracing_indicatif::filter::IndicatifFilter;
use tracing_subscriber::{Layer, layer::SubscriberExt, registry::LookupSpan};

use super::{ProgressMode, progress_bar};

#[test]
fn silent_disables_progress() {
    assert_eq!(
        ProgressMode::from_flags(true, false, true),
        ProgressMode::Disabled
    );
}

#[test]
fn non_terminal_disables_progress() {
    assert_eq!(
        ProgressMode::from_flags(false, false, false),
        ProgressMode::Disabled
    );
}

#[test]
fn terminal_without_silent_enables_progress() {
    assert_eq!(
        ProgressMode::from_flags(false, false, true),
        ProgressMode::Enabled
    );
}

#[test]
fn silent_verbose_keeps_progress_disabled() {
    assert_eq!(
        ProgressMode::from_flags(true, true, true),
        ProgressMode::Disabled
    );
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

#[test]
fn indicatif_filter_only_enables_marked_progress_spans() {
    let layer = CountLayer::default();
    let seen = layer.0.clone();
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::sink)
                .with_filter(tracing_subscriber::filter::LevelFilter::OFF),
        )
        .with(layer.with_filter(IndicatifFilter::new(false)));

    tracing::subscriber::with_default(subscriber, || {
        let _ordinary = tracing::info_span!("ordinary_background_span");
        assert_eq!(seen.load(Ordering::SeqCst), 0);

        let _progress =
            progress_bar(ProgressMode::Enabled, None, "Downloading").expect("progress enabled");
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    });
}
