use http::{HeaderMap, Method, StatusCode, Uri, header::LOCATION};

use crate::redirect::resolve_redirect;

#[test]
fn see_other_switches_to_get() {
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, "/next".parse().unwrap());
    let current: Uri = "https://example.dhttp.net/start".parse().unwrap();
    let redirect = resolve_redirect(StatusCode::SEE_OTHER, &headers, &current, &Method::POST)
        .unwrap()
        .unwrap();
    assert_eq!(redirect.uri.to_string(), "https://example.dhttp.net/next");
    assert_eq!(redirect.method, Method::GET);
}

#[test]
fn temporary_redirect_keeps_method() {
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, "/next".parse().unwrap());
    let current: Uri = "https://example.dhttp.net/start".parse().unwrap();
    let redirect = resolve_redirect(
        StatusCode::TEMPORARY_REDIRECT,
        &headers,
        &current,
        &Method::PUT,
    )
    .unwrap()
    .unwrap();
    assert_eq!(redirect.method, Method::PUT);
}

#[test]
fn invalid_location_header_is_an_error() {
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, http::HeaderValue::from_bytes(b"\xff").unwrap());
    let current: Uri = "https://example.dhttp.net/start".parse().unwrap();
    let error = resolve_redirect(StatusCode::FOUND, &headers, &current, &Method::GET).unwrap_err();

    assert!(matches!(
        error,
        crate::error::Error::InvalidRedirectLocationHeader { .. }
    ));
}

#[test]
fn unsupported_redirect_scheme_is_an_error() {
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, "mailto:admin@example.dhttp.net".parse().unwrap());
    let current: Uri = "https://example.dhttp.net/start".parse().unwrap();
    let error = resolve_redirect(StatusCode::FOUND, &headers, &current, &Method::GET).unwrap_err();

    assert!(matches!(
        error,
        crate::error::Error::UnsupportedRedirectScheme { .. }
    ));
}
