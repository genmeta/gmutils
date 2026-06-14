use std::future::Future;

use tracing::{Instrument, info_span};
use tracing_indicatif::span_ext::IndicatifSpanExt;

pub(crate) async fn run_with_spinner<T, E, Fut>(
    message: &str,
    future: Fut,
) -> Result<T, E>
where
    Fut: Future<Output = Result<T, E>>,
{
    let span = info_span!("cli_progress");
    span.pb_set_message(message);
    span.pb_start();
    let result = future.instrument(span.clone()).await;
    drop(span);
    result
}

#[cfg(test)]
mod tests {
    use super::run_with_spinner;

    #[tokio::test]
    async fn run_with_spinner_returns_inner_result() {
        let value = run_with_spinner("Sending verification code...", async {
            Ok::<_, std::io::Error>("ok")
        })
        .await
        .unwrap();

        assert_eq!(value, "ok");
    }
}
