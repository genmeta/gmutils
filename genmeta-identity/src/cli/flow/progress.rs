use std::future::Future;

use tracing::{Instrument, Span, info_span};
use tracing_indicatif::span_ext::IndicatifSpanExt;

pub(crate) fn save_identity_span() -> Span {
    info_span!("save_identity", indicatif.pb_show = tracing::field::Empty)
}

pub(crate) async fn run_with_spinner<T, E, Fut>(message: &str, future: Fut) -> Result<T, E>
where
    Fut: Future<Output = Result<T, E>>,
{
    let span = info_span!("cli_progress", indicatif.pb_show = tracing::field::Empty);
    span.pb_set_message(message);
    span.pb_start();
    let result = future.instrument(span.clone()).await;
    drop(span);
    result
}

pub(crate) fn run_with_retained_progress<T, E>(
    message: &str,
    finish_message: &str,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let span = info_span!("cli_progress", indicatif.pb_show = tracing::field::Empty);
    span.pb_set_message(message);
    span.pb_set_finish_message(finish_message);
    span.pb_start();
    let result = {
        let _entered = span.enter();
        operation()
    };
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

    use super::{run_with_retained_progress, run_with_spinner};

    #[tokio::test]
    async fn run_with_spinner_returns_inner_result() {
        let value = run_with_spinner("Sending verification code...", async {
            Ok::<_, std::io::Error>("ok")
        })
        .await
        .unwrap();

        assert_eq!(value, "ok");
    }

    #[test]
    fn retained_progress_returns_inner_result() {
        let value = run_with_retained_progress(
            "Generating secp384r1 ECC key pair locally...",
            "Generated secp384r1 ECC key pair locally.",
            || Ok::<_, std::io::Error>("ok"),
        )
        .unwrap();

        assert_eq!(value, "ok");
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
        run_with_spinner("Sending verification code...", async {
            Ok::<_, std::io::Error>(())
        })
        .await
        .unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }
}
