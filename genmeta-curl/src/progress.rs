use std::io::IsTerminal;

use indicatif::{ProgressBar, ProgressStyle};
use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::{prelude::*, util::SubscriberInitExt};

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
    let indicatif_layer = IndicatifLayer::new();
    let (stderr, guard) = tracing_appender::non_blocking(indicatif_layer.get_stderr_writer());
    let level = if options.silent && !options.show_error && std::env::var_os("RUST_LOG").is_none()
    {
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
        .with(indicatif_layer)
        .init();
    ConsoleGuard {
        _appender_guard: guard,
    }
}

#[allow(dead_code)]
pub(crate) fn progress_bar(
    mode: ProgressMode,
    len: Option<u64>,
    message: &'static str,
) -> Option<ProgressBar> {
    if mode == ProgressMode::Disabled {
        return None;
    }
    let pb = len
        .map(ProgressBar::new)
        .unwrap_or_else(ProgressBar::new_spinner);
    let style = if len.is_some() {
        ProgressStyle::with_template("{msg} {bytes}/{total_bytes} [{bar:40.cyan/blue}] {percent}%")
            .expect("progress template is valid")
    } else {
        ProgressStyle::with_template("{spinner} {msg} {bytes}")
            .expect("spinner template is valid")
    };
    pb.set_style(style);
    pb.set_message(message);
    Some(pb)
}

#[cfg(test)]
mod tests {
    use super::ProgressMode;

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
}
