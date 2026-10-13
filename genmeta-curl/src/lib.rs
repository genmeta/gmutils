use std::io::{self, IsTerminal};

use futures::{StreamExt, stream::FusedStream};
use http::StatusCode;
use snafu::ResultExt;

mod cli;
mod client;
mod error;
mod progress;
#[cfg(test)]
mod readiness_tests;
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
        let (mut writer, response) = match tokio::time::timeout(session.connect_timeout, async {
            let resolver = dhttp::resolve::Resolver::get();
            let uri = dhttp::expand_uri_with_base(
                session
                    .identity_profile
                    .as_ref()
                    .map(|profile| profile.name()),
                plan.uri.clone(),
            )?;
            let name = lookup_name(&uri)?;
            let records = resolver
                .lookup(&name, "", None)
                .await
                .map_err(dhttp::Error::from)?;
            wait_for_path(qprotocol::AddressBook::global(), records)
                .await
                .map_err(dhttp::Error::from)?;
            match &session.endpoint {
                Some(endpoint) => endpoint.from_request(request).await,
                None => dhttp::Anonymous.from_request(request).await,
            }
        })
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

// Derive the same DNS name as DHTTP routing: a DHTTP :sequence is not a port.
fn lookup_name(uri: &http::Uri) -> dhttp::Result<String> {
    if uri
        .scheme_str()
        .is_some_and(|scheme| !matches!(scheme, "http" | "https" | "dhttp" | "ws" | "wss"))
    {
        return Err(dhttp::Error::InvalidRequest {
            message: "unsupported URI scheme".into(),
        });
    }
    let host = uri.host().ok_or_else(|| dhttp::Error::InvalidRequest {
        message: "URI has no remote authority".into(),
    })?;
    if host.contains('_')
        || !matches!(
            qtls::ServerName::try_from(host),
            Ok(qtls::ServerName::DnsName(_))
        )
    {
        return Err(dhttp::Error::InvalidName {
            name: host.to_owned(),
        });
    }
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.ends_with(dhttp_home::DHTTP_SUFFIX) {
        return Ok(host);
    }
    let target = uri
        .authority()
        .expect("a host has an authority")
        .as_str()
        .rsplit('@')
        .next()
        .unwrap();
    match target.rsplit_once(':') {
        Some((_, port)) => {
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| dhttp::Error::InvalidRequest {
                    message: "URI port must be between 1 and 65535".into(),
                })?;
            Ok(format!("{host}:{port}"))
        }
        None => Ok(host),
    }
}

// Network initialization starts STUN asynchronously. A short-lived command must
// wait for a local path matching its resolved target before initiating QUIC.
// This preflight and connection establishment share the caller's timeout.
async fn wait_for_path(
    addresses: &qprotocol::AddressBook,
    records: dhttp::resolve::RecordStream,
) -> io::Result<()> {
    let mut updates = addresses.subscribe_ddns();
    let mut records = records.fuse();
    let mut mediated = Vec::new();
    let ready = |source: &dhttp::resolve::Source, peer| {
        addresses.pathways_to(peer, source).into_iter().any(|path| {
            let Some(socket) = qprotocol::QuicProtocol::global().find_socket(path.local()) else {
                return false;
            };
            let Ok(bound) = socket.local_addr() else {
                return false;
            };
            qprotocol::Dock::global()
                .find_socket(bound)
                .is_some_and(|registered| std::sync::Arc::ptr_eq(&registered, &socket))
        })
    };
    while !records.is_terminated() || !mediated.is_empty() {
        tokio::select! {
            record = records.next(), if !records.is_terminated() => {
                if let Some((source, peer)) = record {
                    if ready(&source, peer) {
                        return Ok(());
                    }
                    if matches!(peer, dhttp::resolve::EndpointAddr::Mediate { .. })
                        && peer.is_usable()
                        && !mediated.contains(&(source.clone(), peer))
                    {
                        mediated.push((source, peer));
                    }
                }
            }
            changed = updates.changed(), if !mediated.is_empty() => {
                changed.map_err(io::Error::other)?;
                updates.borrow_and_update();
                if mediated.iter().any(|(source, peer)| ready(source, *peer)) {
                    return Ok(());
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotConnected,
        "DNS lookup did not yield an available local path",
    ))
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
