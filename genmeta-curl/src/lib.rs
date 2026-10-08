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
            session.endpoint.from_request(request),
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
        let target = genmeta_network::transfer(upload, receive).await?;
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

        assert_eq!(
            options.home_scope(),
            genmeta_network::home::HomeScope::Global
        );
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
