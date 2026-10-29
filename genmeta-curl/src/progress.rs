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
    let filter = if options.verb {
        tracing_subscriber::filter::LevelFilter::DEBUG
    } else {
        tracing_subscriber::filter::LevelFilter::OFF
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr)
                .with_filter(filter),
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
#[path = "../tests/unit/progress.rs"]
mod tests;
