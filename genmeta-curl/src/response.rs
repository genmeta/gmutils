use std::{path::PathBuf, pin::pin};

use async_compression::tokio::bufread::{DeflateDecoder, GzipDecoder, ZstdDecoder};
use dhttp::h3x::dhttp::message::MessageReader;
use snafu::ResultExt;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    cli::Options,
    error::{self, Error},
    progress::{self, ProgressMode},
    timing::Timing,
    verbose::{CurlVerbose, LineWriter},
    write_out::{WriteOutContext, expand_write_out},
};

pub(crate) struct ResponseContext<'a, W> {
    pub(crate) options: &'a Options,
    pub(crate) status: http::StatusCode,
    pub(crate) http_version: http::Version,
    pub(crate) current_uri: &'a http::Uri,
    pub(crate) current_method: &'a http::Method,
    pub(crate) timing: &'a Timing,
    pub(crate) response_headers: &'a http::HeaderMap,
    pub(crate) verbose: &'a CurlVerbose<W>,
    pub(crate) progress_mode: ProgressMode,
}

async fn copy_all<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<u64> {
    io::copy(reader, writer).await
}

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
                .context(error::ReadResponseSnafu)
        }
        "deflate" => {
            let mut dec = DeflateDecoder::new(reader);
            copy_all(&mut dec, writer)
                .await
                .context(error::ReadResponseSnafu)
        }
        "zstd" => {
            let mut dec = ZstdDecoder::new(reader);
            copy_all(&mut dec, writer)
                .await
                .context(error::ReadResponseSnafu)
        }
        _ => {
            let mut r = reader;
            copy_all(&mut r, writer)
                .await
                .context(error::ReadResponseSnafu)
        }
    }
}

async fn copy_response_data<W, O>(
    response_stream: &mut MessageReader,
    writer: &mut O,
    verbose: &CurlVerbose<W>,
    progress_mode: ProgressMode,
    response_headers: &http::HeaderMap,
) -> Result<u64, Error>
where
    W: LineWriter,
    O: AsyncWrite + Unpin,
{
    let content_length = response_headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let progress = progress::progress_bar(progress_mode, content_length, "Downloading");
    let mut emitted_marker = false;
    let mut total = 0_u64;

    loop {
        let chunk = response_stream
            .read_data_chunk()
            .await
            .context(error::ReceiveResponseSnafu)?;
        let Some(bytes) = chunk else { break };
        if !emitted_marker && !bytes.is_empty() {
            verbose
                .download_chunk(bytes.len())
                .context(error::WriteVerboseSnafu)?;
            emitted_marker = true;
        }
        if let Some(pb) = progress.as_ref() {
            pb.inc(bytes.len() as u64);
        }
        writer
            .write_all(&bytes)
            .await
            .context(error::ReadResponseSnafu)?;
        total += bytes.len() as u64;
    }

    if let Some(pb) = progress {
        pb.finish();
    }
    Ok(total)
}

async fn stream_response_body<W>(
    mut response_stream: MessageReader,
    decompress: bool,
    content_encoding: &str,
    output: Option<&PathBuf>,
    ctx: &ResponseContext<'_, W>,
) -> Result<u64, Error>
where
    W: LineWriter,
{
    if let Some(output_path) = output {
        tracing::debug!("dumping output to {}", output_path.display());
        let mut file = tokio::fs::File::create(output_path)
            .await
            .context(error::CreateOutputFileSnafu)?;

        let n = if decompress {
            let body_reader = pin!(response_stream.as_reader());
            decompress_copy(body_reader, &mut file, content_encoding).await?
        } else {
            copy_response_data(
                &mut response_stream,
                &mut file,
                ctx.verbose,
                ctx.progress_mode,
                ctx.response_headers,
            )
            .await?
        };
        file.flush().await.context(error::FlushOutputSnafu)?;
        Ok(n)
    } else {
        tracing::debug!("dumping output to stdout");
        let mut stdout = io::stdout();

        let n = if decompress {
            let body_reader = pin!(response_stream.as_reader());
            decompress_copy(body_reader, &mut stdout, content_encoding).await?
        } else {
            copy_response_data(
                &mut response_stream,
                &mut stdout,
                ctx.verbose,
                ctx.progress_mode,
                ctx.response_headers,
            )
            .await?
        };
        stdout.flush().await.context(error::FlushOutputSnafu)?;
        Ok(n)
    }
}

pub(crate) async fn process_final_response<W>(
    response_stream: MessageReader,
    ctx: ResponseContext<'_, W>,
) -> Result<(), Error>
where
    W: LineWriter,
{
    let content_encoding = ctx
        .response_headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let decompress = ctx.options.compressed && !ctx.options.raw;

    let size_download = stream_response_body(
        response_stream,
        decompress,
        &content_encoding,
        ctx.options.output.as_ref(),
        &ctx,
    )
    .await?;

    if let Some(ref fmt) = ctx.options.write_out {
        let write_out_ctx = WriteOutContext {
            status: ctx.status.as_u16(),
            uri: ctx.current_uri,
            method: ctx.current_method,
            http_version: ctx.http_version,
            timing: ctx.timing,
            size_download,
            response_headers: ctx.response_headers,
        };
        let expanded = expand_write_out(fmt, &write_out_ctx);
        let mut stdout = io::stdout();
        stdout
            .write_all(expanded.as_bytes())
            .await
            .context(error::FlushOutputSnafu)?;
        stdout.flush().await.context(error::FlushOutputSnafu)?;
    }

    if let Some(authority) = ctx.current_uri.authority() {
        ctx.verbose
            .connection_left_intact(authority.as_str())
            .context(error::WriteVerboseSnafu)?;
    }

    Ok(())
}
