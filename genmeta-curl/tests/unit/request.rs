use std::path::PathBuf;

use http::{Method, Uri};

use super::{RequestBody, RequestPlan};
use crate::redirect::RedirectTarget;

#[test]
fn request_target_defaults_to_root() {
    let uri: Uri = "https://example.dhttp.net".parse().unwrap();
    assert_eq!(RequestPlan::request_target(&uri), "/");
}

#[test]
fn request_target_keeps_path_and_query() {
    let uri: Uri = "https://example.dhttp.net/a?b=1".parse().unwrap();
    assert_eq!(RequestPlan::request_target(&uri), "/a?b=1");
}

#[test]
fn method_defaults_to_get_without_body() {
    assert_eq!(
        RequestPlan::effective_method(None, &RequestBody::Empty),
        Method::GET
    );
}

#[test]
fn data_body_defaults_to_post() {
    assert_eq!(
        RequestPlan::effective_method(None, &RequestBody::Data("abc".to_string())),
        Method::POST
    );
}

#[test]
fn upload_body_defaults_to_put() {
    assert_eq!(
        RequestPlan::effective_method(None, &RequestBody::UploadFile(PathBuf::from("a.txt"))),
        Method::PUT
    );
}

#[test]
fn explicit_method_overrides_body_default() {
    assert_eq!(
        RequestPlan::effective_method(Some(Method::PATCH), &RequestBody::Data("abc".to_string())),
        Method::PATCH
    );
}

#[test]
fn redirect_to_get_drops_request_body() {
    let plan = RequestPlan {
        uri: "https://example.dhttp.net/start".parse().unwrap(),
        method: Method::POST,
        headers: Default::default(),
        body: RequestBody::Data("abc".to_string()),
    };
    let redirected = plan.for_redirect(RedirectTarget {
        uri: "https://example.dhttp.net/next".parse().unwrap(),
        method: Method::GET,
        switched_to_get: true,
    });

    assert_eq!(redirected.method, Method::GET);
    assert_eq!(redirected.body, RequestBody::Empty);
}

#[test]
fn redirect_that_keeps_method_keeps_upload_file_body() {
    let path = PathBuf::from("payload.bin");
    let plan = RequestPlan {
        uri: "https://example.dhttp.net/start".parse().unwrap(),
        method: Method::PUT,
        headers: Default::default(),
        body: RequestBody::UploadFile(path.clone()),
    };
    let redirected = plan.for_redirect(RedirectTarget {
        uri: "https://example.dhttp.net/next".parse().unwrap(),
        method: Method::PUT,
        switched_to_get: false,
    });

    assert_eq!(redirected.method, Method::PUT);
    assert_eq!(redirected.body, RequestBody::UploadFile(path));
}
