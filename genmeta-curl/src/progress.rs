use std::io::IsTerminal;

use indicatif::ProgressStyle;
use tracing::Span;
use tracing_indicatif::{
    IndicatifLayer,
    filter::{IndicatifFilter, hide_indicatif_span_fields},
    span_ext::IndicatifSpanExt,
};
use tracing_subscriber::{fmt::format::DefaultFields, prelude::*, util::SubscriberInitExt};

use crate::cli::Options;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgressMode {
    Disabled,
    Enabled,
}

impl ProgressMode {
    pub(crate) fn from_flags(silent: bool, _verbose: bool, stderr_is_terminal: bool) -> Self {
        if silent || !stderr_is_terminal {
            Self::Disabled
        } else {
            Self::Enabled
        }
    }
}

pub(crate) struct ConsoleGuard {
    _appender_guard: tracing_appender::non_blocking::WorkerGuard,
}

pub(crate) fn init_console(options: &Options) -> ConsoleGuard {
    let indicatif_layer = IndicatifLayer::new()
        .with_span_field_formatter(hide_indicatif_span_fields(DefaultFields::new()));
    let (stderr, guard) = tracing_appender::non_blocking(indicatif_layer.get_stderr_writer());
    let level = if options.silent && !options.show_error && std::env::var_os("RUST_LOG").is_none() {
        tracing_subscriber::filter::LevelFilter::OFF
    } else {
        tracing_subscriber::filter::LevelFilter::INFO
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(level.into())
                .from_env_lossy()
                .add_directive(
                    "netlink_packet_route=error"
                        .parse()
                        .expect("static tracing directive is valid"),
                ),
        )
        .with(indicatif_layer.with_filter(IndicatifFilter::new(false)))
        .init();
    ConsoleGuard {
        _appender_guard: guard,
    }
}

pub(crate) struct TransferProgress {
    span: Span,
    has_length: bool,
}

impl TransferProgress {
    pub(crate) fn inc(&self, delta: u64) {
        if self.has_length {
            self.span.pb_inc(delta);
        } else {
            self.span.pb_tick();
        }
    }

    pub(crate) fn finish(self) {}
}

pub(crate) fn progress_bar(
    mode: ProgressMode,
    len: Option<u64>,
    message: &'static str,
) -> Option<TransferProgress> {
    if mode == ProgressMode::Disabled {
        return None;
    }
    let style = if len.is_some() {
        ProgressStyle::with_template("{msg} {bytes}/{total_bytes} [{bar:40.cyan/blue}] {percent}%")
            .expect("progress template is valid")
    } else {
        ProgressStyle::with_template("{spinner} {msg}").expect("spinner template is valid")
    };
    let span = tracing::info_span!(
        "transfer_progress",
        indicatif.pb_show = tracing::field::Empty
    );
    span.pb_set_style(&style);
    span.pb_set_message(message);
    if let Some(len) = len {
        span.pb_set_length(len);
    }
    span.pb_start();
    Some(TransferProgress {
        span,
        has_length: len.is_some(),
    })
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
        let subscriber =
            tracing_subscriber::registry().with(layer.with_filter(IndicatifFilter::new(false)));

        tracing::subscriber::with_default(subscriber, || {
            let _ordinary = tracing::info_span!("ordinary_background_span");
            assert_eq!(seen.load(Ordering::SeqCst), 0);

            let _progress =
                progress_bar(ProgressMode::Enabled, None, "Downloading").expect("progress enabled");
            assert_eq!(seen.load(Ordering::SeqCst), 1);
        });
    }
}
