use super::*;

fn release(author: &str, name: &str, _kind: &str, version: &str) -> Value {
    let collection = "packages";
    let value = json!({
        "id": format!("{author}/{name}"), "author": author, "name": name,
        "version": version, "status": "published", "size": 4096,
        "package_sha256": "a".repeat(64), "author_owner_hash": "b".repeat(64),
        "download_path": format!("/store/v1/{collection}/{author}/{name}/versions/{version}/package.waz"),
        "title": "Package", "description": "Description", "changelog": "Initial release", "dependencies": [],
    });
    value
}

fn catalog(items: Vec<Value>, page: u64, total: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({"packages": items, "page": page, "page_size": 100, "total": total}))
        .unwrap()
}

fn report(error: Whatever) -> String {
    snafu::Report::from_error(error).to_string()
}

#[test]
fn input_accepts_only_store_names_and_exact_versions() {
    for name in ["workspace", "dev.dhttp.net/workspace", "dev.dhttp.net/chat"] {
        assert!(validate_input(name, Some("0.2.0")).is_ok());
    }
    for name in [
        "",
        ".",
        "..",
        "./workspace",
        "../workspace",
        "/workspace",
        "~/workspace",
        "C:\\workspace",
        "workspace.waz",
        "dev/workspace",
        "dev.dhttp.net/a/b",
        "https://github.com/a/b",
        "file:///tmp/a",
        "Workspace",
        "workspace@0.2.0",
        "dev.dhttp.net/Workspace",
    ] {
        assert!(validate_input(name, None).is_err(), "{name}");
    }
    for version in [
        "",
        "1.0",
        "1.0.0.0",
        "01.0.0",
        "1.00.0",
        "-1.0.0",
        "1.0.0-beta",
        "1.0.0+build",
        "latest",
        "18446744073709551616.0.0",
    ] {
        assert!(!valid_version(version), "{version}");
    }
    assert!(valid_version("18446744073709551615.0.0"));
}

#[tokio::test]
async fn invalid_input_makes_no_requests() {
    assert!(
        resolve("./workspace", None, |_| async {
            panic!("no network or file fallback")
        })
        .await
        .is_err()
    );
}

#[tokio::test]
async fn unique_short_name_filters_fuzzy_matches_and_reads_latest_detail() {
    let target = release("dev.dhttp.net", "workspace", "app", "0.2.0");
    let mut similar = release("other.dhttp.net", "workspace-extra", "app", "10.0.0");
    similar["title"] = json!("workspace");
    let mut requests = Vec::new();
    let result = resolve("workspace", None, |path| {
        requests.push(path.clone());
        let bytes = if path.contains('?') {
            catalog(vec![similar.clone(), target.clone()], 1, 2)
        } else {
            serde_json::to_vec(&target).unwrap()
        };
        async { Ok(bytes) }
    })
    .await
    .unwrap();
    assert_eq!(result["id"], "dev.dhttp.net/workspace");
    assert_eq!(
        requests,
        [
            "/store/v1/packages?q=workspace&page=1&page_size=100",
            "/store/v1/packages/dev.dhttp.net/workspace"
        ]
    );
}

#[tokio::test]
async fn ambiguity_on_later_page_lists_full_ids_and_never_installs() {
    let mut first = vec![release("first.dhttp.net", "workspace", "app", "0.2.0")];
    first.extend(
        (1..100).map(|i| release("dev.dhttp.net", &format!("similar-{i}"), "app", "1.0.0")),
    );
    let second = vec![release("second.dhttp.net", "workspace", "app", "0.2.0")];
    let mut calls = 0;
    let error = resolve("workspace", None, |_| {
        calls += 1;
        let bytes = if calls == 1 {
            catalog(first.clone(), 1, 101)
        } else {
            catalog(second.clone(), 2, 101)
        };
        async { Ok(bytes) }
    })
    .await
    .unwrap_err();
    let message = report(error);
    assert!(message.contains("first~/workspace") && message.contains("second~/workspace"));
    assert_eq!(calls, 2);
}

#[tokio::test]
async fn full_id_and_explicit_lib_version_use_only_exact_endpoint() {
    let target = release("dev.dhttp.net", "chat", "lib", "0.2.0");
    let result = resolve("dev.dhttp.net/chat", Some("0.2.0"), |path| {
        assert_eq!(path, "/store/v1/packages/dev.dhttp.net/chat/versions/0.2.0");
        let bytes = serde_json::to_vec(&target).unwrap();
        async { Ok(bytes) }
    })
    .await
    .unwrap();
    assert_eq!(
        install_body(&result),
        json!({"author":"dev.dhttp.net","name":"chat", "version":"0.2.0"})
    );
}

#[tokio::test]
async fn missing_legal_name_is_a_store_error_without_file_fallback() {
    let mut calls = 0;
    let error = resolve("workspace", None, |_| {
        calls += 1;
        async { Ok(catalog(vec![], 1, 0)) }
    })
    .await
    .unwrap_err();
    assert!(report(error).contains("No published package"));
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn invalid_pagination_and_budgets_fail_closed() {
    for value in [
        json!({"apps":[], "page":0,"page_size":100,"total":0}),
        json!({"apps":[], "page":1,"page_size":101,"total":0}),
        json!({"apps":[], "page":1,"page_size":100,"total":10001}),
        json!({"apps":[], "page":1,"page_size":100,"total":1}),
        json!({"apps":[], "page":1,"page_size":100,"total":-1}),
        json!({"libs":[], "page":1,"page_size":100,"total":0}),
    ] {
        assert!(
            resolve("workspace", None, |_| {
                let bytes = serde_json::to_vec(&value).unwrap();
                async { Ok(bytes) }
            })
            .await
            .is_err(),
            "{value}"
        );
    }
    let mut remaining = 2;
    assert!(decode_resolution(b"null", &mut remaining).is_err());
    assert!(decode_resolution(&vec![b' '; JSON_LIMIT + 1], &mut RESOLUTION_BYTES.clone()).is_err());
}

#[tokio::test]
async fn failed_or_changed_later_page_does_not_establish_uniqueness() {
    let first: Vec<_> = (0..100)
        .map(|i| {
            release(
                "dev.dhttp.net",
                if i == 0 { "workspace" } else { "similar" },
                "app",
                "0.2.0",
            )
        })
        .enumerate()
        .map(|(i, value)| {
            if i < 2 {
                value
            } else {
                release("dev.dhttp.net", &format!("similar-{i}"), "app", "0.2.0")
            }
        })
        .collect();
    for total in [100, 102] {
        let mut calls = 0;
        let error = resolve("workspace", None, |_| {
            calls += 1;
            let bytes = if calls == 1 {
                catalog(first.clone(), 1, 101)
            } else {
                catalog(vec![], 2, total)
            };
            async { Ok(bytes) }
        })
        .await
        .unwrap_err();
        assert!(report(error).contains("total changed"));
        assert_eq!(calls, 2);
    }
    let mut calls = 0;
    let result = resolve("workspace", None, |_| {
        calls += 1;
        let bytes = catalog(first.clone(), 1, 101);
        async move {
            if calls == 1 {
                Ok(bytes)
            } else {
                whatever!("page unavailable")
            }
        }
    })
    .await;
    assert!(report(result.unwrap_err()).contains("resolution incomplete"));
}

#[test]
fn release_validation_rejects_withdrawn_and_mismatched_proofs() {
    let base = release("dev.dhttp.net", "workspace", "app", "0.2.0");
    for (key, value) in [
        ("id", json!("other.dhttp.net/workspace")),
        ("kind", json!("lib")),
        ("version", json!("0.3.0")),
        ("status", json!("yanked")),
        ("size", json!(0)),
        ("size", json!(64 * 1024 * 1024 + 1)),
        ("package_sha256", json!("bad")),
        ("author_owner_hash", json!("A".repeat(64))),
        ("download_path", json!("https://example.com/app.waz")),
    ] {
        let mut value_to_check = base.clone();
        value_to_check[key] = value;
        assert!(
            validate_release(
                &value_to_check,
                Some("dev.dhttp.net/workspace"),
                Some("0.2.0")
            )
            .is_err(),
            "{key}"
        );
    }
    let mut legacy = base.clone();
    legacy.as_object_mut().unwrap().remove("title");
    legacy["openapi"] = json!({"info":{"title":"Legacy"}});
    assert!(validate_detail(&legacy).is_err());
    let mut legacy = base;
    legacy["openapi"] = json!({});
    assert!(validate_detail(&legacy).is_err());
}

#[test]
fn success_requires_matching_identity_version_and_saved_entry() {
    for (author, displayed_id) in [
        ("dev.dhttp.net", "dev~/workspace"),
        ("std.dhttp.net", "std/workspace"),
    ] {
        let release = release(author, "workspace", "app", "0.2.0");
        let mut installed = release.clone();
        installed["has_app"] = true.into();
        installed["entry"] = "/".into();
        assert_eq!(
            display::package_output(success(&installed, &release, "alice.dhttp.net").unwrap()),
            json!({"id":displayed_id,"version":"0.2.0","identity":"alice~","entry_url":"https://alice~/app/workspace/"})
        );
        assert_eq!(
            install_body(&release),
            json!({"author":author,"name":"workspace","version":"0.2.0"})
        );
        for key in ["id", "version", "entry"] {
            let mut changed = installed.clone();
            changed[key] = "wrong".into();
            assert!(success(&changed, &release, "alice.dhttp.net").is_err());
        }
        let backend = release.clone();
        assert!(
            display::package_output(success(&backend, &release, "alice.dhttp.net").unwrap())
                .get("entry_url")
                .is_none()
        );
    }
}

#[test]
fn service_errors_preserve_approval_and_partial_install_semantics() {
    for status in [
        StatusCode::ACCEPTED,
        StatusCode::FORBIDDEN,
        StatusCode::CONFLICT,
        StatusCode::NOT_FOUND,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let text = report(install_status(status, b"server diagnostic").unwrap_err());
        assert!(text.contains("server diagnostic"));
        if status == StatusCode::CONFLICT {
            assert!(text.contains("retained"));
        }
        if status == StatusCode::NOT_FOUND {
            assert!(text.contains("Start or enable"));
        }
        if status == StatusCode::ACCEPTED {
            assert!(text.contains("has not completed"));
        }
    }
}

#[tokio::test]
async fn identity_resolution_never_picks_the_first_directory_or_falls_back_to_anonymous() {
    let directory = tempfile::tempdir().unwrap();
    let home = DhttpHome::new(directory.path().to_owned());
    let profile_path = home.join_identity_name("first.dhttp.net").unwrap();
    std::fs::create_dir(&profile_path).unwrap();
    let error = identity(&home, None).await.unwrap_err();
    assert!(report(error).contains("No default identity"));
    let explicit = identity(&home, Some("first".into())).await.unwrap();
    assert_eq!(explicit.name(), "first.dhttp.net");
    assert_eq!(explicit.path(), profile_path);
    assert!(identity(&home, Some("missing".into())).await.is_err());
    let mut settings = home.new_settings();
    settings
        .settings_mut()
        .set_default_identity_name("first".parse().unwrap());
    settings.save().await.unwrap();
    assert_eq!(
        identity(&home, None).await.unwrap().name(),
        "first.dhttp.net"
    );
    // Resolving a directory is not enough to create an authenticated Endpoint.
    assert!(dhttp::Endpoint::load_from(explicit.path()).await.is_err());
    assert!(!profile_path.join("config.db").exists());
    assert!(!profile_path.join("app").exists());
    assert!(!profile_path.join("lib").exists());
}

#[test]
fn package_cli_is_top_level_and_has_no_app_or_lib_selection() {
    use clap::Parser;

    use crate::{Options, PackageCommand};
    assert!(matches!(
        Options::try_parse_from(["genmeta", "install", "workspace"]).unwrap(),
        Options::Package(PackageCommand::Install {
            target: Some(_),
            ..
        })
    ));
    for operation in ["install", "update", "uninstall"] {
        assert!(
            Options::try_parse_from(["genmeta", operation, "alice/message", "--id", "alice"])
                .is_ok()
        );
        for removed in ["--app", "--lib"] {
            assert!(Options::try_parse_from(["genmeta", operation, "workspace", removed]).is_err());
        }
    }
    assert!(Options::try_parse_from(["genmeta", "install", "--list"]).is_ok());
    assert!(Options::try_parse_from(["genmeta", "install", "--info", "workspace"]).is_ok());
    for args in [
        vec!["genmeta", "package", "install", "workspace"],
        vec!["genmeta", "install"],
        vec!["genmeta", "install", "workspace", "--file", "workspace.waz"],
        vec!["genmeta", "uninstall", "workspace", "--version", "1.0.0"],
    ] {
        assert!(Options::try_parse_from(args).is_err());
    }
    let help = Options::try_parse_from(["genmeta", "install", "--help"])
        .unwrap_err()
        .to_string();
    assert!(help.contains("--id") && !help.contains("--lib") && !help.contains("--app"));
}

#[test]
fn installed_identity_and_update_preconditions() {
    let current = json!({"id":"alice.dhttp.net/message","version":"1.0.0"});
    assert!(validate_installed(&current, Some("message")).is_ok());
    assert!(validate_installed(&current, Some("std.dhttp.net/message")).is_err());
    assert!(validate_installed(&current, Some("message")).is_ok());
    assert_eq!(
        choose_release_target("update", "message", Some(&current)).unwrap(),
        "alice.dhttp.net/message"
    );
    assert!(choose_release_target("update", "message", None).is_err());
    assert!(check_install_version("install", Some(&current), &current).unwrap());
    let mut next = current.clone();
    next["version"] = "2.0.0".into();
    assert!(check_install_version("install", Some(&current), &next).is_err());
    assert!(!check_install_version("update", Some(&current), &next).unwrap());
    next["id"] = "std.dhttp.net/message".into();
    assert!(check_install_version("update", Some(&current), &next).is_err());
}

#[test]
fn both_store_and_service_require_the_expected_name_and_owner() {
    let certificates = rustls_pemfile::certs(
        &mut include_bytes!("../../../genmeta-identity/tests/fixtures/install/chain.pem")
            .as_slice(),
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let owner = dhttp_home::certificate::extract_dhttp_subject_key_identifier(&certificates)
        .unwrap()
        .owner_hash()
        .clone();
    assert!(
        verify_peer(
            "alice.smith.dhttp.net",
            &certificates,
            "alice.smith.dhttp.net",
            &owner
        )
        .is_ok()
    );
    assert!(
        verify_peer(
            "wrong.dhttp.net",
            &certificates,
            "alice.smith.dhttp.net",
            &owner
        )
        .is_err()
    );
    let wrong_owner = OwnerHash::try_from("f".repeat(64).as_str()).unwrap();
    assert!(
        verify_peer(
            "alice.smith.dhttp.net",
            &certificates,
            "alice.smith.dhttp.net",
            &wrong_owner
        )
        .is_err()
    );
    let store_owner = OwnerHash::try_from(STORE_OWNER).unwrap();
    assert!(verify_peer(STORE, &certificates, STORE, &store_owner).is_err());
    assert!(verify_peer(STORE, &[], STORE, &store_owner).is_err());
    let response = Response::new(
        http_body_util::Empty::<bytes::Bytes>::new()
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    assert!(verify_remote(&response, STORE, &store_owner).is_err());
}

#[tokio::test]
async fn response_body_is_bounded_and_preserves_plain_text_service_errors() {
    let response = Response::new(
        http_body_util::Full::new(bytes::Bytes::from_static(b"access denied"))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    assert!(require_json(&response).is_err());
    assert_eq!(read_body(response).await.unwrap(), b"access denied");
    let response = Response::new(
        http_body_util::Full::new(bytes::Bytes::from(vec![b' '; JSON_LIMIT + 1]))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    assert!(report(read_body(response).await.unwrap_err()).contains("2 MiB"));
    let response = Response::new(
        http_body_util::StreamBody::new(futures::stream::iter([
            Ok::<_, dhttp::BoxError>(http_body::Frame::data(bytes::Bytes::from_static(b"{}"))),
            Err(std::io::Error::other("stream reset").into()),
        ]))
        .boxed_unsync(),
    );
    assert!(report(read_body(response).await.unwrap_err()).contains("interrupted"));
    for status in [StatusCode::REQUEST_TIMEOUT, StatusCode::GATEWAY_TIMEOUT] {
        assert!(
            report(install_status(status, b"deadline").unwrap_err()).contains("outcome is unknown")
        );
    }
}

#[tokio::test(start_paused = true)]
async fn resolution_deadline_covers_all_pages_instead_of_resetting_per_request() {
    let mut calls = 0;
    let start = tokio::time::Instant::now();
    let error = resolve_with_deadline("workspace", None, |_| {
        calls += 1;
        let page = calls;
        async move {
            tokio::time::sleep(Duration::from_secs(70)).await;
            let items = (0..100)
                .map(|i| release("dev.dhttp.net", &format!("name-{i}"), "app", "0.2.0"))
                .collect();
            Ok(catalog(items, page, 101))
        }
    })
    .await
    .unwrap_err();
    assert!(report(error).contains("120-second deadline"));
    assert_eq!(calls, 2);
    assert_eq!(start.elapsed(), RESOLUTION_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn installation_timeout_is_unknown_and_never_retries_the_write() {
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let start = tokio::time::Instant::now();
    let error = wait_for_install(async {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::pending::<Result<Value, Whatever>>().await
    })
    .await
    .unwrap_err();
    let message = report(error);
    assert!(
        message.contains("outcome is unknown") && message.contains("not guarantee cancellation")
    );
    assert_eq!(start.elapsed(), INSTALL_TIMEOUT);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

use crate::test_credentials as host_credentials;

#[derive(Debug)]
struct HostResolver(dhttp::resolve::EndpointAddr);
impl std::fmt::Display for HostResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("host API loopback fixture")
    }
}
impl dhttp::resolve::Resolve for HostResolver {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        _: &'a str,
        _: Option<dhttp::resolve::Family>,
    ) -> dhttp::resolve::ResolveFuture<'a> {
        use futures::{FutureExt, StreamExt};
        async move {
            assert_eq!(name, "alice.dhttp.net");
            Ok(futures::stream::iter([(dhttp::resolve::Source::System, self.0)]).boxed())
        }
        .boxed()
    }
}

#[tokio::test]
#[ignore = "run alone; owns TLS roots and local QUIC sockets; requires OpenSSL 3"]
async fn host_api_commands_authenticate_and_preserve_methods_bodies_and_errors() {
    use std::sync::{Arc, Mutex};

    use qprotocol::{Dock, UdpSocket};
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join(".dhttp");
    host_credentials::generate(&home, &[("alice", "alice.dhttp.net", &"a".repeat(64))]);
    let peer = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    Dock::global().add(peer.clone()).unwrap().unwrap();
    dhttp::DhttpNetwork::init().await.unwrap();
    let ca = std::fs::read(home.join("ca.crt")).unwrap();
    qtls::RootCerts::set(
        rustls_pemfile::certs(&mut ca.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap();
    dhttp::resolve::Resolver::add(Arc::new(HostResolver(
        dhttp::resolve::EndpointAddr::direct(peer.local_addr().unwrap()),
    )));
    let profile = IdentityProfile::try_from(home.join("alice")).unwrap();
    let endpoint = dhttp::Endpoint::new(
        qbase::endpoint::Endpoint::new(
            "alice.dhttp.net",
            profile.load_certs().await.unwrap(),
            profile.load_key().await.unwrap(),
            profile.load_ocsp().await.unwrap(),
        )
        .unwrap(),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let listening = endpoint
        .listen(
            dhttp::Scope::Loopback.into(),
            tower::service_fn({
                let requests = requests.clone();
                move |request: http::Request<dhttp::Body>| {
                    let requests = requests.clone();
                    async move {
                        let peer = request
                            .extensions()
                            .get::<dhttp::HandshakeSummary>()
                            .unwrap()
                            .remote
                            .as_ref()
                            .unwrap();
                        assert_eq!(peer.name(), "alice.dhttp.net");
                        let method = request.method().clone();
                        let path = request.uri().path_and_query().unwrap().to_string();
                        if path == "/std/sys/pkg/install" {
                            assert_eq!(method, http::Method::POST);
                            assert_eq!(request.headers()[header::CONTENT_TYPE], "application/json");
                        }
                        if path == "/std/sys/pkg?name=demo" && method == http::Method::DELETE {
                            assert_eq!(request.headers()["expected-package-id"], "alice.dhttp.net/demo");
                        }
                        let bytes = request.into_body().collect().await?.to_bytes();
                        requests
                            .lock()
                            .unwrap()
                            .push((method.clone(), path.clone(), bytes.to_vec()));
                        let (status, value) = if path == "/std/sys/pkg/install" && serde_json::from_slice::<Value>(&bytes).unwrap()["name"] == "demo" {
                            (
                                StatusCode::OK,
                                json!({"has_app":true,"id":"alice.dhttp.net/demo","version":"1.0.0","entry":"/"}),
                            )
                        } else if path == "/std/sys/pkg/install" {
                            (
                                StatusCode::BAD_REQUEST,
                                json!({"error":"invalid signature"}),
                            )
                        } else if path == "/std/sys/pkg?name=demo" {
                            assert!(bytes.is_empty());
                            if method == http::Method::DELETE {
                                (StatusCode::NO_CONTENT, Value::Null)
                            } else if requests.lock().unwrap().iter().any(|(method, path, _)| method == http::Method::DELETE && path == "/std/sys/pkg?name=demo") {
                                (StatusCode::NOT_FOUND, Value::Null)
                            } else {
                                (StatusCode::OK, json!({"has_app":true,"id":"alice.dhttp.net/demo","name":"demo","version":"1.0.0","entry":"/"}))
                            }
                        } else if path.starts_with("/std/sys/mount?") {
                            assert_eq!(method, http::Method::DELETE);
                            assert!(bytes.is_empty());
                            (StatusCode::NO_CONTENT, Value::Null)
                        } else {
                            assert_eq!(path, "/std/sys/mount");
                            (StatusCode::OK, json!([]))
                        };
                        let body = http_body_util::Full::new(bytes::Bytes::from(
                            if status == StatusCode::NO_CONTENT { Vec::new() } else { serde_json::to_vec(&value).unwrap() },
                        ))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                        Ok::<_, dhttp::BoxError>(
                            http::Response::builder()
                                .status(status)
                                .header(header::CONTENT_TYPE, "application/json")
                                .header("package-id", "alice.dhttp.net/demo")
                                .body(body)
                                .unwrap(),
                        )
                    }
                }
            }),
        )
        .await
        .unwrap();
    let authority = endpoint.local_authority().unwrap();
    let owner =
        dhttp_home::certificate::extract_dhttp_subject_key_identifier(authority.certificates())
            .unwrap()
            .owner_hash()
            .clone();
    let app = release("alice.dhttp.net", "demo", "app", "1.0.0");
    let result = install(&endpoint, &owner, &app).await.unwrap();
    assert!(result.get("kind").is_none());
    let lib = release("alice.dhttp.net", "broken", "lib", "1.0.0");
    let error = install(&endpoint, &owner, &lib).await.unwrap_err();
    assert!(report(error).contains("invalid signature"));
    assert_eq!(
        requests.lock().unwrap()[0],
        (
            http::Method::POST,
            "/std/sys/pkg/install".into(),
            br#"{"author":"alice.dhttp.net","name":"demo","version":"1.0.0"}"#.to_vec()
        )
    );
    assert_eq!(
        host_exchange(
            &endpoint,
            &owner,
            http::Method::PATCH,
            "/std/sys/mount",
            br#"{"location":"/api","proxy_pass":"127.0.0.1:8080"}"#.to_vec(),
            "application/json"
        )
        .await
        .unwrap(),
        json!([])
    );
    assert_eq!(requests.lock().unwrap()[2].0, http::Method::PATCH);
    host_exchange(
        &endpoint,
        &owner,
        http::Method::GET,
        "/std/sys/mount",
        Vec::new(),
        "application/json",
    )
    .await
    .unwrap();
    let unmount = "/std/sys/mount?location=%3D%20%2Fapi&proxy_pass=http%3A%2F%2F127.0.0.1%3A8080";
    assert_eq!(
        host_exchange(
            &endpoint,
            &owner,
            http::Method::DELETE,
            unmount,
            Vec::new(),
            "application/json"
        )
        .await
        .unwrap(),
        Value::Null
    );
    {
        let calls = requests.lock().unwrap();
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[2].1, "/std/sys/mount");
        assert_eq!(
            serde_json::from_slice::<Value>(&calls[2].2).unwrap(),
            json!({"location":"/api", "proxy_pass":"127.0.0.1:8080"})
        );
        assert_eq!(
            calls[3],
            (http::Method::GET, "/std/sys/mount".into(), Vec::new())
        );
        assert_eq!(calls[4], (http::Method::DELETE, unmount.into(), Vec::new()));
    }
    let saved = super::catalog(&endpoint, &owner, Some("alice.dhttp.net/demo"), true)
        .await
        .unwrap()
        .unwrap();
    assert!(check_install_version("update", Some(&saved), &app).unwrap());
    assert_eq!(
        display::package_output(success(&saved, &app, endpoint.name()).unwrap())["entry_url"],
        "https://alice~/app/demo/"
    );
    let removed = display::package_output(remove(&endpoint, &owner, &saved).await.unwrap());
    assert_eq!(removed["id"], "alice~/demo");
    assert_eq!(removed["identity"], "alice~");
    assert_eq!(removed["removed"], true);
    assert_eq!(removed["data_retained"], true);
    assert!(
        super::catalog(&endpoint, &owner, Some("alice.dhttp.net/demo"), false)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(requests.lock().unwrap().len(), 8);
    drop(listening);
}

#[test]
fn abbreviated_authors_expand_without_changing_installed_bare_names() {
    assert_eq!(
        normalize_target("workspace", true),
        "std.dhttp.net/workspace"
    );
    assert_eq!(normalize_target("message", false), "message");
    assert_eq!(
        normalize_target("alice/message", true),
        "alice.dhttp.net/message"
    );
    assert_eq!(
        normalize_target("alice.smith/message", false),
        "alice.smith.dhttp.net/message"
    );
    assert_eq!(
        normalize_target("alice.dhttp.net/message", true),
        "alice.dhttp.net/message"
    );
    for id in ["std.dhttp.net/workspace", "alice.smith.dhttp.net/message"] {
        assert_eq!(normalize_target(&display::package_id(id), true), id);
        assert_eq!(normalize_target(&display::package_id(id), false), id);
    }
    assert!(!valid_target(&normalize_target("@alice/message", true)));
}
