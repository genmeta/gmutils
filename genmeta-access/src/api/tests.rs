use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use access_control::{AccessService, AuthResult, Headers, SubjectId, Visitor};
use clap::Parser;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

use super::*;
use crate::Options;

const OWNER: &str = "alice.pilot.dhttp.net";

struct Call {
    method: http::Method,
    uri: Uri,
    body: Option<Value>,
}
struct Server {
    router: axum::Router,
    service: Arc<AccessService>,
    visitor: Visitor,
    calls: Mutex<Vec<Call>>,
}
impl Server {
    async fn new() -> Self {
        let subject = SubjectId::new(b"owner hash".to_vec()).unwrap();
        let service = Arc::new(
            AccessService::load_from_db("sqlite::memory:", OWNER, &subject)
                .await
                .unwrap(),
        );
        Self {
            router: access_control::management_router(service.clone()),
            service,
            visitor: Visitor::new(OWNER, subject),
            calls: Mutex::new(Vec::new()),
        }
    }
}
impl Transport for Server {
    async fn send(&self, mut request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Error> {
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(
            request.uri().authority().unwrap().as_str(),
            self.visitor.name()
        );
        assert_eq!(request.headers()[http::header::ACCEPT], "application/json");
        let body = if request.body().is_empty() {
            None
        } else {
            assert_eq!(
                request.headers()[http::header::CONTENT_TYPE],
                "application/json"
            );
            Some(serde_json::from_slice(request.body()).unwrap())
        };
        self.calls.lock().unwrap().push(Call {
            method: request.method().clone(),
            uri: request.uri().clone(),
            body,
        });
        let headers = Headers {
            method: request.method().clone(),
            path: request.uri().path().to_owned(),
            fields: request.headers().clone(),
        };
        let auth = self
            .service
            .auth(
                headers,
                Some(self.visitor.name()),
                Some(self.visitor.subject_id()),
            )
            .await
            .unwrap();
        if !matches!(auth, AuthResult::Allowed) {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(b"access denied".to_vec())
                .unwrap());
        }
        request.extensions_mut().insert(self.visitor.clone());
        let response = self
            .router
            .clone()
            .oneshot(request.map(axum::body::Body::from))
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            body.collect().await.unwrap().to_bytes().to_vec(),
        ))
    }
}
async fn run(transport: &impl Transport, args: &[&str]) -> Result<String, Error> {
    let options =
        Options::try_parse_from(std::iter::once("access").chain(args.iter().copied())).unwrap();
    let (_, command) = options.into_parts()?;
    execute(transport, &OWNER.parse().unwrap(), command).await
}

#[tokio::test]
async fn authenticated_api_crud_updates_service_and_json_contract() {
    let server = Server::new().await;
    run(&server, &["/api/", "allow", "*?", "--method", "GET"])
        .await
        .unwrap();
    let output = run(&server, &["/api", "list"]).await.unwrap();
    assert!(output.contains("/api\tGET\tallow *?"), "{output}");
    let headers = Headers {
        method: http::Method::GET,
        path: "/api/item".into(),
        fields: http::HeaderMap::new(),
    };
    assert!(matches!(
        server
            .service
            .auth(headers.clone(), None, None)
            .await
            .unwrap(),
        AuthResult::Allowed
    ));
    run(&server, &["/api", "deny", "*?", "--method", "GET"])
        .await
        .unwrap();
    assert!(matches!(
        server.service.auth(headers, None, None).await.unwrap(),
        AuthResult::Denied
    ));
    assert_eq!(
        run(&server, &["/api", "list"])
            .await
            .unwrap()
            .lines()
            .count(),
        1
    );
    run(&server, &["/api", "remove", "*?", "--method", "GET"])
        .await
        .unwrap();
    assert!(run(&server, &["list", "--wide"]).await.unwrap().is_empty());
    let calls = server.calls.lock().unwrap();
    assert_eq!(calls[0].method, http::Method::POST);
    assert_eq!(calls[0].uri.path(), "/std/acl/access/api");
    assert_eq!(
        calls[0].body,
        Some(json!({"method":"GET", "effect":"allow", "grantee":"*?"}))
    );
    let delete = calls
        .iter()
        .find(|call| call.method == http::Method::DELETE)
        .unwrap();
    assert_eq!(delete.uri.path(), "/std/acl/allow/%2A%3F");
    assert_eq!(delete.body, Some(json!({"method":"GET", "api":"/api"})));
}

#[tokio::test]
async fn method_filtering_and_clear_use_api_reads_then_exact_deletes() {
    let server = Server::new().await;
    for method in ["GET", "POST"] {
        run(&server, &["/api", "allow", "*?", "--method", method])
            .await
            .unwrap();
    }
    run(&server, &["/api", "review", "staff@example.com"])
        .await
        .unwrap();
    let output = run(&server, &["--method", "POST", "/api", "list"])
        .await
        .unwrap();
    assert!(output.contains("POST"));
    assert!(!output.contains("GET"));
    run(&server, &["/api", "remove", "--all", "--method", "GET"])
        .await
        .unwrap();
    let output = run(&server, &["list", "--wide"]).await.unwrap();
    assert!(!output.contains("GET"));
    assert!(output.contains("POST"));
    assert!(output.contains("review staff@example.com"));
    run(&server, &["remove", "/api"]).await.unwrap();
    assert!(run(&server, &["list"]).await.unwrap().is_empty());
}

#[tokio::test]
async fn root_and_nested_api_paths_round_trip_through_router() {
    let server = Server::new().await;
    for path in ["/", "/api/users", "/api/literal%2Fsegment"] {
        run(&server, &[path, "review", "**"]).await.unwrap();
        let output = run(&server, &[path, "list"]).await.unwrap();
        assert!(
            output.contains(&format!("{path}\t*\treview **")),
            "{output}"
        );
        run(&server, &[path, "clear"]).await.unwrap();
    }
    assert!(run(&server, &["list", "--wide"]).await.unwrap().is_empty());
    let calls = server.calls.lock().unwrap();
    assert_eq!(calls[0].uri.path(), "/std/acl/access/%2F");
    assert!(
        calls
            .iter()
            .any(|call| call.uri.path() == "/std/acl/access/api%2Fusers")
    );
}

#[tokio::test]
async fn named_contacts_and_management_protection_are_enforced_by_server() {
    let server = Server::new().await;
    run(&server, &["/api", "allow", "Alice.Pilot~"])
        .await
        .unwrap();
    assert!(
        run(&server, &["/api", "list"])
            .await
            .unwrap()
            .contains(OWNER)
    );
    let error = run(&server, &["/api", "allow", "alice.pilot"])
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Api {
            status: StatusCode::BAD_REQUEST,
            ..
        }
    ));
    assert!(
        error
            .to_string()
            .contains("contact \"alice.pilot\" does not exist")
    );
    let error = run(&server, &["/std/acl", "deny", "alice.pilot~"])
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Api {
            status: StatusCode::BAD_REQUEST,
            ..
        }
    ));
    assert!(error.to_string().contains("administrator"));
    assert!(
        run(&server, &["/std/acl", "list"])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn explicit_removal_defaults_to_wildcard_method_and_is_idempotent() {
    let server = Server::new().await;
    run(&server, &["/api", "allow", "**"]).await.unwrap();
    run(&server, &["/api", "deny", "?", "--method", "POST"])
        .await
        .unwrap();
    run(&server, &["/api", "remove", "**"]).await.unwrap();
    run(&server, &["/api", "remove", "**"]).await.unwrap();
    assert!(
        run(&server, &["/api", "list"])
            .await
            .unwrap()
            .contains("POST\tdeny ?")
    );
    let calls = server.calls.lock().unwrap();
    assert!(
        calls
            .iter()
            .filter(|call| call.method == http::Method::DELETE)
            .all(|call| call.body == Some(json!({"method":"*", "api":"/api"})))
    );
}

#[tokio::test]
async fn grouped_grantees_and_global_method_filters_round_trip() {
    let server = Server::new().await;
    run(
        &server,
        &["--method", "GET", "/team", "review", "staff@EXAMPLE.COM"],
    )
    .await
    .unwrap();
    run(&server, &["/other", "allow", "?"]).await.unwrap();
    assert_eq!(
        run(&server, &["--method", "GET", "list"])
            .await
            .unwrap()
            .trim(),
        "/team"
    );
    assert!(
        run(&server, &["list", "--wide"])
            .await
            .unwrap()
            .contains("review staff@example.com")
    );
    run(
        &server,
        &["/team", "remove", "staff@example.com", "--method", "GET"],
    )
    .await
    .unwrap();
    assert!(run(&server, &["/team", "list"]).await.unwrap().is_empty());
}

struct Script(Mutex<VecDeque<Response<Vec<u8>>>>);
impl Transport for Script {
    async fn send(&self, _: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Error> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected management request"))
    }
}
fn scripted(status: StatusCode, body: &str) -> Script {
    Script(Mutex::new(VecDeque::from([Response::builder()
        .status(status)
        .body(body.as_bytes().to_vec())
        .unwrap()])))
}

#[tokio::test]
async fn forbidden_and_pending_responses_never_report_success_or_retry() {
    for (status, body) in [
        (StatusCode::FORBIDDEN, "no permission"),
        (
            StatusCode::ACCEPTED,
            r#"{"status_url":"/std/acl/review/12/status"}"#,
        ),
    ] {
        let script = scripted(status, body);
        let error = run(&script, &["/api", "allow", "*?"]).await.unwrap_err();
        assert!(matches!(error, Error::Api { status: actual, .. } if actual == status));
        assert!(error.to_string().contains(body));
        if status == StatusCode::ACCEPTED {
            assert!(error.to_string().contains("has not completed"));
        }
    }
}

#[tokio::test]
async fn malformed_json_and_unexpected_statuses_are_errors() {
    let error = run(&scripted(StatusCode::OK, "not JSON"), &["list"])
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Json { .. }));
    let error = run(&scripted(StatusCode::NO_CONTENT, ""), &["/api", "list"])
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Api {
            status: StatusCode::NO_CONTENT,
            ..
        }
    ));
}
