use std::{
    io::Cursor,
    sync::{Arc, Mutex},
};

use clap::Parser;
use tokio::io::BufReader;
use tracing_subscriber::layer::SubscriberExt;

use super::{StdoutOutput, decompress_copy, fail_on_http_error, stdout_output_for_response_body};
use crate::{
    cli::Options,
    error::Error,
    progress::ProgressMode,
    verbose::{CurlVerbose, LineWriter},
};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

impl LineWriter for Capture {
    fn write_line(&self, line: &str) -> std::io::Result<()> {
        self.0.lock().unwrap().push(line.to_string());
        Ok(())
    }
}

impl Capture {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn decompressed_response_emits_verbose_data_marker() {
    let writer = Capture::default();
    let verbose = CurlVerbose::enabled(writer.clone());
    let reader = BufReader::new(Cursor::new(b"hello".to_vec()));
    let mut output = Vec::new();

    let n = decompress_copy(reader, &mut output, "", &verbose, ProgressMode::Disabled)
        .await
        .unwrap();

    assert_eq!(n, 5);
    assert_eq!(output, b"hello");
    assert_eq!(writer.lines(), vec!["{ [5 bytes data]"]);
}

#[test]
fn fail_option_rejects_http_error_status() {
    let options =
        Options::try_parse_from(["genmeta-curl", "--fail", "https://example.com/"]).unwrap();
    let error = fail_on_http_error(&options, http::StatusCode::NOT_FOUND).unwrap_err();

    assert!(matches!(error, Error::HttpErrorStatus { .. }));
}

#[test]
fn fail_option_accepts_success_status() {
    let options =
        Options::try_parse_from(["genmeta-curl", "--fail", "https://example.com/"]).unwrap();

    fail_on_http_error(&options, http::StatusCode::OK).unwrap();
}

#[test]
fn response_body_stdout_uses_indicatif_writer_when_available() {
    let indicatif_layer = tracing_indicatif::IndicatifLayer::new();
    let subscriber = tracing_subscriber::registry().with(indicatif_layer);

    tracing::subscriber::with_default(subscriber, || {
        assert!(stdout_output_for_response_body().is_indicatif());
    });
}

impl StdoutOutput {
    fn is_indicatif(&self) -> bool {
        matches!(self, Self::Indicatif(_))
    }
}
