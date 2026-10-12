use std::io::IsTerminal;

use http::StatusCode;
use snafu::ResultExt;

mod cli;
mod client;
mod error;
mod progress;
mod redirect;
mod request;
mod response;
mod timing;
mod verbose;
mod write_out;

pub use cli::Options;
pub use curl_error::Error;
use error as curl_error;
use progress::{ProgressMode, init_console};
use request::RequestPlan;
use timing::Timing;
use verbose::{CurlVerbose, StreamId};

pub async fn run(mut options: Options) -> Result<(), Error> {
    let _guard = init_console(&options);
    let progress_mode = ProgressMode::from_flags(
        options.silent,
        options.verbose,
        std::io::stderr().is_terminal(),
    );
    let session = client::setup_client(&mut options).await?;
    let verbose = CurlVerbose::stderr(options.verbose);
    let mut plan = RequestPlan::initial(&options);
    let mut redirect_count = 0;

    loop {
        let mut timing = Timing::new();
        let request = plan
            .request_builder()
            .body(dhttp::WndBuf::new(64 * 1024))
            .context(curl_error::BuildRequestSnafu)?;
        let (mut writer, response) = match tokio::time::timeout(
            session.connect_timeout,
            match &session.endpoint {
                Some(endpoint) => endpoint.from_request(request),
                None => dhttp::Anonymous.from_request(request),
            },
        )
        .await
        {
            Ok(result) => result.context(curl_error::ConnectSnafu)?,
            Err(_) => return curl_error::TimedoutSnafu.fail(),
        };
        timing.mark_connected();
        verbose
            .request(StreamId::UNAVAILABLE, &plan)
            .context(curl_error::WriteVerboseSnafu)?;
        let upload = async {
            request::send_request_body(&plan, &mut writer, &verbose, progress_mode).await?;
            verbose
                .request_sent()
                .context(curl_error::WriteVerboseSnafu)
        };
        let receive = async {
            let response = response.await.context(curl_error::ConnectSnafu)?;
            timing.mark_first_byte();
            let (parts, body) = response.into_parts();
            verbose
                .response(parts.status, &parts.headers)
                .context(curl_error::WriteVerboseSnafu)?;
            if options.location
                && parts.status.is_redirection()
                && parts.status != StatusCode::NOT_MODIFIED
            {
                if redirect_count >= options.max_redirs {
                    return curl_error::TooManyRedirectsSnafu.fail();
                }
                if let Some(target) = redirect::resolve_redirect(
                    parts.status,
                    &parts.headers,
                    &plan.uri,
                    &plan.method,
                )? {
                    drop(body);
                    return Ok(Some(target));
                }
            }
            response::fail_on_http_error(&options, parts.status)?;
            response::process_final_response(
                body,
                response::ResponseContext {
                    options: &options,
                    status: parts.status,
                    http_version: parts.version,
                    current_uri: &plan.uri,
                    current_method: &plan.method,
                    timing: &timing,
                    response_headers: &parts.headers,
                    verbose: &verbose,
                    progress_mode,
                },
            )
            .await?;
            Ok(None)
        };
        let target = transfer(upload, receive).await?;
        // A server may finish its response before the upload; dropping the writer cancels it.
        drop(writer);
        let Some(target) = target else { break };
        verbose
            .redirect_to(&target.uri)
            .context(curl_error::WriteVerboseSnafu)?;
        if target.switched_to_get {
            verbose
                .switch_to_get()
                .context(curl_error::WriteVerboseSnafu)?;
        }
        plan = plan.for_redirect(target);
        redirect_count += 1;
    }
    Ok(())
}

/// Poll upload and response consumption together; a completed response ends uploading.
/// Receiving has priority so an early HTTP rejection remains visible to the caller.
async fn transfer<U, R, T, E>(upload: U, receive: R) -> Result<T, E>
where
    U: std::future::Future<Output = Result<(), E>>,
    R: std::future::Future<Output = Result<T, E>>,
{
    tokio::pin!(upload, receive);
    tokio::select! {
        biased;
        response = &mut receive => response,
        uploaded = &mut upload => { uploaded?; receive.await },
    }
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

        assert_eq!(options.home_scope(), dhttp_home::HomeScope::Global);
    }

    #[test]
    fn options_accept_curl_fail_silent_show_error_location_cluster() {
        let options =
            Options::try_parse_from(["genmeta-curl", "-fsSL", "https://example.com/"]).unwrap();

        assert!(options.fail);
        assert!(options.silent);
        assert!(options.show_error);
        assert!(options.location);
    }

    #[test]
    fn invalid_custom_header_is_rejected_by_cli_parser() {
        let result =
            Options::try_parse_from(["genmeta-curl", "-H", ": value", "https://example.com/"]);

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod transfer_tests {
    use std::io;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::transfer;
    #[tokio::test]
    async fn transfer_drains_duplex_response_during_large_upload() {
        let (mut upload_client, mut upload_server) = tokio::io::duplex(64);
        let (mut response_server, mut response_client) = tokio::io::duplex(64);
        let server = tokio::spawn(async move {
            tokio::io::copy(&mut upload_server, &mut response_server)
                .await
                .unwrap();
        });
        let payload = vec![42u8; 256 * 1024];
        let upload = async {
            upload_client.write_all(&payload).await?;
            upload_client.shutdown().await
        };
        let receive = async {
            let mut body = Vec::new();
            response_client.read_to_end(&mut body).await?;
            Ok::<_, io::Error>(body)
        };
        let body =
            tokio::time::timeout(std::time::Duration::from_secs(5), transfer(upload, receive))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(body, payload);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn early_rejection_does_not_wait_for_a_blocked_upload() {
        let uploading = std::future::pending::<Result<(), io::Error>>();
        let response = async { Ok::<_, io::Error>(http::StatusCode::PAYLOAD_TOO_LARGE) };
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            transfer(uploading, response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(status, http::StatusCode::PAYLOAD_TOO_LARGE);
    }
}
