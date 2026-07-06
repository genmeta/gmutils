use std::{io::IsTerminal, pin::pin};

use dhttp::h3x::{dhttp::message::MessageReader, quic::GetStreamIdExt};
use http::StatusCode;
use snafu::ResultExt;
use tokio::io;

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
use timing::Timing;
use progress::{ProgressMode, init_console};
use request::RequestPlan;
use verbose::{CurlVerbose, StreamId};

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
    let progress_mode = ProgressMode::from_flags(
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

        let _bytes_uploaded =
            request::send_request_body(&plan, &mut request_stream, &verbose, progress_mode).await?;
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
                verbose
                    .redirect_to(&target.uri)
                    .context(curl_error::WriteVerboseSnafu)?;
                if target.switched_to_get {
                    verbose
                        .switch_to_get()
                        .context(curl_error::WriteVerboseSnafu)?;
                }
                if matches!(plan.body, request::RequestBody::UploadFile(_)) && !target.switched_to_get {
                    verbose
                        .cannot_rewind_upload()
                        .context(curl_error::WriteVerboseSnafu)?;
                }
                plan = plan.for_redirect(target);
                redirect_count += 1;
                continue;
            }
        }

        response::process_final_response(
            response_stream,
            response::ResponseContext {
                options: &options,
                status,
                http_version,
                current_uri: &plan.uri,
                current_method: &plan.method,
                timing: &timing,
                response_headers: &response_headers,
                verbose: &verbose,
                progress_mode,
            },
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
