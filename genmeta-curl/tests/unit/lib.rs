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
    let result = Options::try_parse_from(["genmeta-curl", "-H", ": value", "https://example.com/"]);

    assert!(result.is_err());
}
