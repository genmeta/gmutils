use std::{io::IsTerminal, path::PathBuf, pin::pin};

use async_compression::tokio::bufread::{DeflateDecoder, GzipDecoder, ZstdDecoder};
use dhttp::h3x::{dhttp::message::MessageReader, quic::GetStreamIdExt};
use http::{Method, StatusCode, Uri};
use snafu::ResultExt;
use tokio::{fs, io::{self, AsyncRead, AsyncWrite, AsyncWriteExt}};

mod cli;
mod client;
mod error;
mod progress;
mod redirect;
mod request;
mod timing;
mod verbose;
mod write_out;

pub use cli::Options;
pub use curl_error::Error;

use error as curl_error;
use timing::Timing;
use progress::{ProgressMode, init_console};
use request::RequestPlan;
use verbose::{CurlVerbose, StreamId};
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

/// Receive the response head and record first-byte timing.
async fn receive_response_head(
    response_stream: &mut MessageReader,
    timing: &mut Timing,
) -> Result<http::response::Parts, Error> {
    let response = response_stream
        .read_hyper_response_parts()
        .await
        .context(curl_error::ReceiveResponseSnafu)?;

    timing.mark_first_byte();

    Ok(response)
}

pub async fn run(mut options: Options) -> Result<(), Error> {
    let _guard = init_console(&options);
    let _progress_mode = ProgressMode::from_flags(
        options.silent,
        options.verbose,
        std::io::stderr().is_terminal(),
    );
    let session = client::setup_client(&mut options).await?;
    let verbose = CurlVerbose::stderr(options.verbose);

    let mut plan = RequestPlan::initial(&options);
    let mut redirect_count: u32 = 0;

    loop {
        let mut timing = Timing::new();

        let (mut response_stream, mut request_stream) =
            client::connect_and_open_streams(&session, &plan.uri, &mut timing).await?;
        let stream_id = request_stream
            .stream_id()
            .await
            .context(curl_error::GetStreamIdSnafu)?;
        let stream_id = StreamId::from(stream_id);
        verbose
            .request(stream_id, &plan)
            .context(curl_error::WriteVerboseSnafu)?;

        let _bytes_uploaded = request::send_request_body(&plan, &mut request_stream).await?;
        verbose
            .request_sent()
            .context(curl_error::WriteVerboseSnafu)?;

        let response = receive_response_head(&mut response_stream, &mut timing).await?;
        verbose
            .response(response.status, &response.headers)
            .context(curl_error::WriteVerboseSnafu)?;

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
