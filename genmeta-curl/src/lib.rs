use std::{io::IsTerminal, path::PathBuf, pin::pin};

use async_compression::tokio::bufread::{DeflateDecoder, GzipDecoder, ZstdDecoder};
use dhttp::h3x::dhttp::message::MessageReader;
use http::{Method, StatusCode, Uri};
use snafu::ResultExt;
use tokio::{fs, io::{self, AsyncRead, AsyncWrite, AsyncWriteExt}};
use tracing_subscriber::prelude::*;

mod cli;
mod client;
mod error;
mod redirect;
mod request;
mod timing;
mod verbose;
mod write_out;

pub use cli::Options;
pub use curl_error::Error;

use error as curl_error;
use timing::Timing;
use request::RequestPlan;
use write_out::{WriteOutContext, expand_write_out};

/// Copy `reader` into `writer`, returning the number of bytes written.
async fn copy_all<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<u64> {
    io::copy(reader, writer).await
}

/// Copy `reader` into `writer`, decompressing based on Content-Encoding.
/// Falls back to pass-through for unknown or identity encoding.
async fn decompress_copy<R, W>(
    reader: R,
    writer: &mut W,
    content_encoding: &str,
) -> Result<u64, Error>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match content_encoding {
        "gzip" | "x-gzip" => {
            let mut dec = GzipDecoder::new(reader);
            copy_all(&mut dec, writer)
                .await
                .context(curl_error::ReadResponseSnafu)
        }
        "deflate" => {
            let mut dec = DeflateDecoder::new(reader);
            copy_all(&mut dec, writer)
                .await
                .context(curl_error::ReadResponseSnafu)
        }
        "zstd" => {
            let mut dec = ZstdDecoder::new(reader);
            copy_all(&mut dec, writer)
                .await
                .context(curl_error::ReadResponseSnafu)
        }
        _ => {
            // identity or unknown encoding — pass through
            let mut r = reader;
            copy_all(&mut r, writer)
                .await
                .context(curl_error::ReadResponseSnafu)
        }
    }
}

/// Initialize tracing subscriber based on CLI verbosity flags.
fn init_tracing(options: &Options) -> tracing_appender::non_blocking::WorkerGuard {
    // -s:   suppress all tracing output.
    // -s -S: show errors only (INFO level) but not progress.
    // We approximate -s -S by keeping INFO but note that progress is not
    // separately implemented — tracing output itself is the only stderr content.
    let (stderr, guard) = tracing_appender::non_blocking(std::io::stderr());
    let level = if options.silent && !options.show_error {
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
                        .expect("BUG: static tracing directive is valid"),
                ),
        )
        .init();
    guard
}

/// Stream the response body to a file or stdout, optionally decompressing.
async fn stream_response_body(
    mut response_stream: MessageReader,
    decompress: bool,
    content_encoding: &str,
    output: Option<&PathBuf>,
) -> Result<u64, Error> {
    if let Some(output_path) = output {
        tracing::debug!("dumping output to {}", output_path.display());
        let mut file = fs::File::create(output_path)
            .await
            .context(curl_error::CreateOutputFileSnafu)?;

        let n = if decompress {
            let body_reader = pin!(response_stream.as_reader());
            decompress_copy(body_reader, &mut file, content_encoding).await?
        } else {
            let mut body_reader = pin!(response_stream.as_reader());
            copy_all(&mut body_reader, &mut file)
                .await
                .context(curl_error::ReadResponseSnafu)?
        };
        file.flush().await.context(curl_error::FlushOutputSnafu)?;
        Ok(n)
    } else {
        tracing::debug!("dumping output to stdout");
        let mut stdout = io::stdout();

        let n = if decompress {
            let body_reader = pin!(response_stream.as_reader());
            decompress_copy(body_reader, &mut stdout, content_encoding).await?
        } else {
            let mut body_reader = pin!(response_stream.as_reader());
            copy_all(&mut body_reader, &mut stdout)
                .await
                .context(curl_error::ReadResponseSnafu)?
        };
        stdout.flush().await.context(curl_error::FlushOutputSnafu)?;
        Ok(n)
    }
}

/// Process the final response: stream body and optionally print `--write-out`.
#[allow(clippy::too_many_arguments)]
async fn process_final_response(
    response_stream: MessageReader,
    response_headers: &http::HeaderMap,
    options: &Options,
    status: StatusCode,
    http_version: http::Version,
    current_uri: &Uri,
    current_method: &Method,
    timing: &Timing,
) -> Result<(), Error> {
    let content_encoding = response_headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let decompress = options.compressed && !options.raw;

    let size_download = stream_response_body(
        response_stream,
        decompress,
        &content_encoding,
        options.output.as_ref(),
    )
    .await?;

    // --write-out: print format string after body, to stdout, no trailing newline
    if let Some(ref fmt) = options.write_out {
        let ctx = WriteOutContext {
            status: status.as_u16(),
            uri: current_uri,
            method: current_method,
            http_version,
            timing,
            size_download,
            response_headers,
        };
        let expanded = expand_write_out(fmt, &ctx);
        print!("{expanded}");
        io::stdout()
            .flush()
            .await
            .context(curl_error::FlushOutputSnafu)?;
    }

    Ok(())
}

/// Print verbose response details to stderr.
fn print_verbose_response(response: &http::response::Parts) {
    let formatted = format!("< received response: {response:#?}")
        .lines()
        .collect::<Vec<_>>()
        .join("\n< ");
    eprintln!("{formatted}");
}

/// Receive the response head, record first-byte timing, and optionally print
/// verbose details.
async fn receive_response_head(
    response_stream: &mut MessageReader,
    timing: &mut Timing,
    verbose: bool,
) -> Result<http::response::Parts, Error> {
    let response = response_stream
        .read_hyper_response_parts()
        .await
        .context(curl_error::ReceiveResponseSnafu)?;

    timing.mark_first_byte();

    if verbose {
        print_verbose_response(&response);
    }

    Ok(response)
}

pub async fn run(mut options: Options) -> Result<(), Error> {
    let _guard = init_tracing(&options);
    let session = client::setup_client(&mut options).await?;

    let mut plan = RequestPlan::initial(&options);
    let mut redirect_count: u32 = 0;

    loop {
        let mut timing = Timing::new();

        let (mut response_stream, mut request_stream) =
            client::connect_and_open_streams(&session, &plan.uri, &mut timing).await?;

        let _bytes_uploaded = request::send_request_body(&plan, &mut request_stream).await?;

        let response =
            receive_response_head(&mut response_stream, &mut timing, options.verbose).await?;

        let status = response.status;
        let response_headers = response.headers.clone();
        let http_version = response.version;

        if options.location && status.is_redirection() && status != StatusCode::NOT_MODIFIED {
            if redirect_count >= options.max_redirs {
                return curl_error::TooManyRedirectsSnafu.fail();
            }
            if let Some(target) =
                redirect::resolve_redirect(status, &response.headers, &plan.uri, &plan.method)?
            {
                let mut body_reader = pin!(response_stream.as_reader());
                io::copy(&mut body_reader, &mut io::sink()).await.ok();
                plan = plan.for_redirect(target);
                redirect_count += 1;
                continue;
            }
        }

        process_final_response(
            response_stream,
            &response_headers,
            &options,
            status,
            http_version,
            &plan.uri,
            &plan.method,
            &timing,
        )
        .await?;

        break;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;

    
    use super::*;

    #[test]
    fn connect_timeout_zero_disables_timeout() {
        assert_eq!(client::connect_timeout_from_secs(0), Duration::MAX);
    }

    #[test]
    fn connect_timeout_uses_seconds() {
        assert_eq!(client::connect_timeout_from_secs(5), Duration::from_secs(5));
    }

    #[test]
    fn normalize_cli_uri_expands_bare_authority_to_https_root() {
        let uri = "reimu.pilot~".parse::<http::Uri>().unwrap();

        let normalized = client::normalize_cli_uri(uri, None).unwrap();

        assert_eq!(normalized.to_string(), "https://reimu.pilot.dhttp.net/");
    }

    #[test]
    fn options_accept_global_flag() {
        let options =
            Options::try_parse_from(["genmeta-curl", "--global", "https://example.com/"]).unwrap();

        assert_eq!(options.home_scope(), dhttp::home::HomeScope::Global);
    }
}
