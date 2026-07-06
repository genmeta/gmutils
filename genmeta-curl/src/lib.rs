use std::{io::IsTerminal, path::PathBuf, pin::pin, sync::Arc, time::Duration};

use async_compression::tokio::bufread::{DeflateDecoder, GzipDecoder, ZstdDecoder};
use dhttp::{
    endpoint::Endpoint,
    h3x::{
        dhttp::message::{MessageReader, MessageWriter},
    },
    home::{DhttpHome, identity::IdentityProfile},
    message::IntoUri,
};
use http::{Method, StatusCode, Uri};
use snafu::{IntoError, ResultExt, ensure};
use tokio::{fs, io::{self, AsyncRead, AsyncWrite, AsyncWriteExt}};
use tracing_subscriber::prelude::*;

mod cli;
mod error;
mod request;
mod timing;
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

async fn load_identity_profile(options: &Options) -> Result<Option<IdentityProfile>, Error> {
    if options.anonymous {
        return Ok(None);
    }

    let home = match DhttpHome::load(options.home_scope()) {
        Ok(home) => home,
        Err(source) if options.id.is_none() => {
            tracing::warn!(
                error = %snafu::Report::from_error(&source),
                "failed to load dhttp home, using anonymous endpoint"
            );
            return Ok(None);
        }
        Err(source) => return Err(curl_error::LoadDhttpHomeSnafu.into_error(source)),
    };

    if let Some(name) = &options.id {
        tracing::debug!(%name, "trying to load command line identity");
        return home
            .resolve_identity_profile(name.clone())
            .await
            .context(curl_error::LoadExplicitIdentitySnafu { name: name.clone() })
            .map(Some);
    }

    match home.resolve_default_identity_profile().await {
        Ok(identity) => {
            tracing::debug!(name = %identity.name(), "using default identity");
            Ok(Some(identity))
        }
        Err(source) => {
            tracing::debug!(
                error = %snafu::Report::from_error(&source),
                "failed to load default identity, using anonymous endpoint"
            );
            Ok(None)
        }
    }
}

fn normalize_cli_uri(
    uri: Uri,
    self_name: Option<&dhttp::name::DhttpName<'_>>,
) -> Result<Uri, Error> {
    let uri = uri.into_uri(self_name).context(curl_error::NormalizeUriSnafu)?;

    let mut parts = uri.into_parts();
    if parts.scheme.is_none() && parts.authority.is_some() && parts.path_and_query.is_none() {
        parts.scheme = Some(http::uri::Scheme::HTTPS);
        parts.path_and_query = Some(http::uri::PathAndQuery::from_static("/"));
    }

    Uri::from_parts(parts).context(curl_error::ConstructRequestUriSnafu)
}

/// Load identity, expand the URI, and construct the DHTTP endpoint.
async fn setup_client(
    options: &mut Options,
) -> Result<(Arc<Endpoint>, Option<IdentityProfile>, Duration), Error> {
    let identity_profile = load_identity_profile(options).await?;

    // Normalize DHTTP shorthand in URI using loaded identity (--id > default identity).
    options.uri = normalize_cli_uri(
        options.uri.clone(),
        identity_profile.as_ref().map(|id| id.name()),
    )?;
    ensure!(
        options.uri.authority().is_some(),
        curl_error::MissingAuthoritySnafu
    );

    // TODO(-4/-6): the previous address-family filter here (applied post-
    // expansion on `BindUri`s) was a no-op in practice — it restricted the
    // watcher's "initial known set" but not the actual bindings, and it
    // silently rejected all `iface://` URIs because the predicate only
    // considered `inet://` addresses. Reintroduce this feature at the
    // `Bind` pattern level (e.g. drop binds whose explicit family tag
    // mismatches the requested `-4`/`-6`) rather than post-expansion when
    // it's needed again.
    let identity = match &identity_profile {
        Some(profile) => Some(Arc::new(
            profile
                .load_identity()
                .await
                .context(curl_error::LoadIdentitySslSnafu)?,
        )),
        None => None,
    };

    let mut builder = Endpoint::builder()
        .bind(Arc::new(options.binds.clone()))
        .maybe_identity(identity);
    for scheme in options.dns.iter().copied() {
        builder = builder.dns(scheme);
    }
    let endpoint = Arc::new(builder.build().await.context(curl_error::BuildEndpointSnafu)?);

    let connect_timeout = connect_timeout_from_secs(options.connect_timeout);

    Ok((endpoint, identity_profile, connect_timeout))
}

fn connect_timeout_from_secs(seconds: u64) -> Duration {
    if seconds == 0 {
        Duration::MAX
    } else {
        Duration::from_secs(seconds)
    }
}

/// Check whether a response is a redirect and resolve the new target.
///
/// Returns `Some((new_uri, new_method))` when the caller should follow the
/// redirect, or `None` when the response is final.
fn resolve_redirect(
    status: StatusCode,
    headers: &http::HeaderMap,
    current_uri: &Uri,
    current_method: &Method,
) -> Result<Option<(Uri, Method)>, Error> {
    let location = match headers.get(http::header::LOCATION) {
        Some(loc) => loc,
        None => return Ok(None),
    };

    let location_str = location.to_str().unwrap_or("");

    // Use url::Url::join() for RFC 3986 compliant relative reference resolution
    let base_url =
        url::Url::parse(&current_uri.to_string()).context(curl_error::ParseRedirectUrlSnafu {
            url: current_uri.to_string(),
        })?;
    let resolved = base_url
        .join(location_str)
        .context(curl_error::ParseRedirectUrlSnafu {
            url: location_str.to_string(),
        })?;
    let new_uri: Uri = resolved
        .as_str()
        .parse()
        .context(curl_error::InvalidRedirectLocationSnafu)?;

    // 301/302/303 → switch to GET; 307/308 → keep method
    let new_method = match status {
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => Method::GET,
        _ => current_method.clone(),
    };

    tracing::debug!(location = location_str, "following redirect");

    Ok(Some((new_uri, new_method)))
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

/// Connect to the server (with timeout) and open the initial message streams.
async fn connect_and_open_streams(
    client: &Endpoint,
    uri: &Uri,
    connect_timeout: Duration,
    timing: &mut Timing,
) -> Result<(MessageReader, MessageWriter), Error> {
    let connect_fut = async {
        client
            .connect(
                uri.authority()
                    .expect("BUG: URI authority already validated")
                    .clone(),
            )
            .await
            .context(curl_error::ConnectSnafu)
    };
    let connection = match tokio::time::timeout(connect_timeout, connect_fut).await {
        Ok(result) => result?,
        Err(_) => return curl_error::TimedoutSnafu.fail(),
    };
    timing.mark_connected();
    connection
        .initial_message_stream()
        .await
        .context(curl_error::InitialMessageStreamSnafu)
}

/// Check whether a response is a redirect; if so, drain the response body and
/// return the new target URI and method.
async fn check_redirect(
    options: &Options,
    status: StatusCode,
    headers: &http::HeaderMap,
    current_uri: &Uri,
    current_method: &Method,
    redirect_count: u32,
    response_stream: &mut MessageReader,
) -> Result<Option<(Uri, Method)>, Error> {
    if !options.location || !status.is_redirection() || status == StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    if redirect_count >= options.max_redirs {
        return curl_error::TooManyRedirectsSnafu.fail();
    }
    let result = resolve_redirect(status, headers, current_uri, current_method)?;
    if result.is_some() {
        // Drain response body so the QUIC stream is cleanly closed
        let mut body_reader = pin!(response_stream.as_reader());
        io::copy(&mut body_reader, &mut io::sink()).await.ok();
    }
    Ok(result)
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
    let (client, _id, connect_timeout) = setup_client(&mut options).await?;

    let mut plan = RequestPlan::initial(&options);
    let mut redirect_count: u32 = 0;

    loop {
        let mut timing = Timing::new();

        let (mut response_stream, mut request_stream) =
            connect_and_open_streams(&client, &plan.uri, connect_timeout, &mut timing).await?;

        let _bytes_uploaded = request::send_request_body(&plan, &mut request_stream).await?;

        let response =
            receive_response_head(&mut response_stream, &mut timing, options.verbose).await?;

        let status = response.status;
        let response_headers = response.headers.clone();
        let http_version = response.version;

        if let Some((new_uri, new_method)) = check_redirect(
            &options,
            status,
            &response.headers,
            &plan.uri,
            &plan.method,
            redirect_count,
            &mut response_stream,
        )
        .await?
        {
            plan.uri = new_uri;
            plan.method = new_method;
            redirect_count += 1;
            continue;
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
        assert_eq!(connect_timeout_from_secs(0), Duration::MAX);
    }

    #[test]
    fn connect_timeout_uses_seconds() {
        assert_eq!(connect_timeout_from_secs(5), Duration::from_secs(5));
    }

    #[test]
    fn normalize_cli_uri_expands_bare_authority_to_https_root() {
        let uri = "reimu.pilot~".parse::<http::Uri>().unwrap();

        let normalized = normalize_cli_uri(uri, None).unwrap();

        assert_eq!(normalized.to_string(), "https://reimu.pilot.dhttp.net/");
    }

    #[test]
    fn options_accept_global_flag() {
        let options =
            Options::try_parse_from(["genmeta-curl", "--global", "https://example.com/"]).unwrap();

        assert_eq!(options.home_scope(), dhttp::home::HomeScope::Global);
    }
}
