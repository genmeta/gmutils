use std::{path::PathBuf, pin::pin};

use async_compression::tokio::bufread::{DeflateDecoder, GzipDecoder, ZstdDecoder};
use dhttp::h3x::dhttp::message::MessageReader;
use snafu::ResultExt;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    cli::Options,
    error::{self, Error},
    progress::{self, ProgressMode},
    timing::Timing,
    verbose::{CurlVerbose, LineWriter},
    write_out::{WriteOutContext, expand_write_out},
};

const DOWNLOAD_BUFFER_SIZE: usize = 16 * 1024;

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

async fn copy_decoded<R, O, W>(
    reader: &mut R,
    writer: &mut O,
    verbose: &CurlVerbose<W>,
    progress: Option<&progress::TransferProgress>,
) -> Result<u64, Error>
where
    R: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    W: LineWriter,
{
    let mut buf = [0_u8; DOWNLOAD_BUFFER_SIZE];
    let mut total = 0_u64;
    let mut emitted_marker = false;

    loop {
        let n = reader
            .read(&mut buf)
            .await
            .context(error::ReadResponseSnafu)?;
        if n == 0 {
            break;
        }
        if !emitted_marker {
            verbose
                .download_chunk(n)
                .context(error::WriteVerboseSnafu)?;
            emitted_marker = true;
        }
        writer
            .write_all(&buf[..n])
            .await
            .context(error::ReadResponseSnafu)?;
        if let Some(pb) = progress {
            pb.inc(n as u64);
        }
        total += n as u64;
    }

    Ok(total)
}

async fn decompress_copy<R, O, W>(
    reader: R,
    writer: &mut O,
    content_encoding: &str,
    verbose: &CurlVerbose<W>,
    progress_mode: ProgressMode,
) -> Result<u64, Error>
where
    R: tokio::io::AsyncBufRead + Unpin,
    O: AsyncWrite + Unpin,
    W: LineWriter,
{
    let progress = progress::progress_bar(progress_mode, None, "Downloading");
    let result = match content_encoding {
        "gzip" | "x-gzip" => {
            let mut dec = GzipDecoder::new(reader);
            copy_decoded(&mut dec, writer, verbose, progress.as_ref()).await
        }
        "deflate" => {
            let mut dec = DeflateDecoder::new(reader);
            copy_decoded(&mut dec, writer, verbose, progress.as_ref()).await
        }
        "zstd" => {
            let mut dec = ZstdDecoder::new(reader);
            copy_decoded(&mut dec, writer, verbose, progress.as_ref()).await
        }
        _ => {
            let mut r = reader;
            copy_decoded(&mut r, writer, verbose, progress.as_ref()).await
        }
    };
    if let Some(pb) = progress {
        pb.finish();
    }
    result
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
            decompress_copy(
                body_reader,
                &mut file,
                content_encoding,
                ctx.verbose,
                ctx.progress_mode,
            )
            .await?
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
            decompress_copy(
                body_reader,
                &mut stdout,
                content_encoding,
                ctx.verbose,
                ctx.progress_mode,
            )
            .await?
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

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        sync::{Arc, Mutex},
    };

    use tokio::io::BufReader;

    use super::decompress_copy;
    use crate::{
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
}
