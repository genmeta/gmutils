use super::*;

fn release(publisher: &str, name: &str, kind: &str, version: &str) -> Value {
    let collection = if kind == "app" { "apps" } else { "libs" };
    let mut value = json!({
        "id": format!("{publisher}/{name}"), "publisher": publisher, "name": name,
        "kind": kind, "version": version, "status": "published", "size": 4096,
        "package_sha256": "a".repeat(64), "publisher_owner_hash": "b".repeat(64),
        "download_path": format!("/store/v1/{collection}/{publisher}/{name}/versions/{version}/{kind}.webc"),
        "title": "Package", "description": "Description", "changelog": "Initial release", "dependencies": [],
    });
    if kind == "app" {
        value["entry"] = json!("/");
    }
    value
}

fn catalog(items: Vec<Value>, page: u64, total: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({"apps": items, "page": page, "page_size": 100, "total": total}))
        .unwrap()
}

fn report(error: Whatever) -> String {
    snafu::Report::from_error(error).to_string()
}

#[test]
fn input_accepts_only_store_names_and_exact_versions() {
    for name in ["workspace", "dev.dhttp.net/workspace", "dev.dhttp.net/chat"] {
        assert!(validate_input(name, Some("0.2.0"), "app").is_ok());
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
        "workspace.webc",
        "dev/workspace",
        "dev.dhttp.net/a/b",
        "https://github.com/a/b",
        "file:///tmp/a",
        "Workspace",
        "workspace@0.2.0",
        "dev.dhttp.net/Workspace",
    ] {
        assert!(validate_input(name, None, "app").is_err(), "{name}");
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
    assert!(validate_input("workspace", None, "backend").is_err());
}

#[tokio::test]
async fn invalid_input_makes_no_requests() {
    assert!(
        resolve("./workspace", None, "app", |_| async {
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
    let result = resolve("workspace", None, "app", |path| {
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
            "/store/v1/apps?q=workspace&page=1&page_size=100",
            "/store/v1/apps/dev.dhttp.net/workspace"
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
    let error = resolve("workspace", None, "app", |_| {
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
    assert!(
        message.contains("first.dhttp.net/workspace")
            && message.contains("second.dhttp.net/workspace")
    );
    assert_eq!(calls, 2);
}

#[tokio::test]
async fn full_id_and_explicit_lib_version_use_only_exact_endpoint() {
    let target = release("dev.dhttp.net", "chat", "lib", "0.2.0");
    let result = resolve("dev.dhttp.net/chat", Some("0.2.0"), "lib", |path| {
        assert_eq!(path, "/store/v1/libs/dev.dhttp.net/chat/versions/0.2.0");
        let bytes = serde_json::to_vec(&target).unwrap();
        async { Ok(bytes) }
    })
    .await
    .unwrap();
    assert_eq!(
        install_body(&result),
        json!({"kind":"lib", "publisher":"dev.dhttp.net", "name":"chat", "version":"0.2.0"})
    );
}

#[tokio::test]
async fn missing_legal_name_is_a_store_error_without_file_fallback() {
    let mut calls = 0;
    let error = resolve("workspace", None, "app", |_| {
        calls += 1;
        async { Ok(catalog(vec![], 1, 0)) }
    })
    .await
    .unwrap_err();
    assert!(report(error).contains("No published app"));
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
            resolve("workspace", None, "app", |_| {
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
        let error = resolve("workspace", None, "app", |_| {
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
    let result = resolve("workspace", None, "app", |_| {
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
        ("publisher_owner_hash", json!("A".repeat(64))),
        ("download_path", json!("https://example.com/app.webc")),
    ] {
        let mut value_to_check = base.clone();
        value_to_check[key] = value;
        assert!(
            validate_release(
                &value_to_check,
                "app",
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
    assert!(validate_detail(&legacy, "app").is_err());
    let mut legacy = base;
    legacy["openapi"] = json!({});
    assert!(validate_detail(&legacy, "app").is_err());
}

#[test]
fn success_requires_matching_identity_kind_version_and_saved_entry() {
    let app = release("dev.dhttp.net", "workspace", "app", "0.2.0");
    assert_eq!(
        success(&app, &app, "alice.dhttp.net").unwrap(),
        json!({
            "id":"dev.dhttp.net/workspace", "kind":"app", "version":"0.2.0", "identity":"alice.dhttp.net", "entry_url":"https://alice.dhttp.net/std/workspace/"
        })
    );
    assert_eq!(install_body(&app).as_object().unwrap().len(), 4);
    for key in ["id", "kind", "version", "entry"] {
        let mut changed = app.clone();
        changed[key] = json!("wrong");
        assert!(
            report(success(&changed, &app, "alice.dhttp.net").unwrap_err())
                .contains("outcome is unknown")
        );
    }
    let lib = release("dev.dhttp.net", "chat", "lib", "0.2.0");
    assert!(
        success(&lib, &lib, "alice.dhttp.net")
            .unwrap()
            .get("entry_url")
            .is_none()
    );
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
fn package_cli_groups_operations_and_uses_type() {
    use clap::Parser;

    use crate::{Options, PackageCommand};
    let Options::Package {
        command: PackageCommand::Install {
            kind, version, id, ..
        },
    } = Options::try_parse_from(["genmeta", "package", "install", "workspace"]).unwrap()
    else {
        panic!()
    };
    assert_eq!(kind, "app");
    assert_eq!(version, None);
    assert_eq!(id, None);
    for flag in ["-i", "--id"] {
        let Options::Package {
            command: PackageCommand::Update {
                kind, version, id, ..
            },
        } = Options::try_parse_from([
            "genmeta",
            "package",
            "update",
            "dev.dhttp.net/message",
            flag,
            "alice",
            "--type",
            "lib",
            "--version",
            "0.2.0",
        ])
        .unwrap()
        else {
            panic!()
        };
        assert_eq!(kind, "lib");
        assert_eq!(version.as_deref(), Some("0.2.0"));
        assert_eq!(id.as_deref(), Some("alice"));
    }
    for operation in ["remove", "info"] {
        assert!(
            Options::try_parse_from([
                "genmeta", "package", operation, "message", "--type", "lib", "--id", "alice"
            ])
            .is_ok()
        );
    }
    assert!(matches!(
        Options::try_parse_from(["genmeta", "package", "list"]).unwrap(),
        Options::Package {
            command: PackageCommand::List { kind: None, .. }
        }
    ));
    for args in [
        vec!["genmeta", "install", "workspace"],
        vec!["genmeta", "pack"],
        vec!["genmeta", "upload", "package.webc"],
        vec!["genmeta", "package", "install"],
        vec!["genmeta", "package", "install", "workspace", "extra"],
        vec![
            "genmeta",
            "package",
            "install",
            "workspace",
            "--kind",
            "lib",
        ],
        vec![
            "genmeta",
            "package",
            "install",
            "workspace",
            "--type",
            "other",
        ],
        vec![
            "genmeta",
            "package",
            "remove",
            "workspace",
            "--version",
            "1.0.0",
        ],
        vec![
            "genmeta",
            "package",
            "update",
            "workspace",
            "--store",
            "other.dhttp.net",
        ],
    ] {
        assert!(Options::try_parse_from(args).is_err());
    }
    let help = Options::try_parse_from(["genmeta", "package", "install", "--help"])
        .unwrap_err()
        .to_string();
    assert!(help.contains("MAJOR.MINOR.PATCH") && help.contains("--type") && help.contains("--id"));
}

#[test]
fn installed_identity_and_update_preconditions() {
    let current = json!({"id":"alice.dhttp.net/message","kind":"lib","version":"1.0.0"});
    assert!(validate_installed(&current, "lib", Some("message")).is_ok());
    assert!(validate_installed(&current, "lib", Some("std.dhttp.net/message")).is_err());
    assert!(validate_installed(&current, "app", Some("message")).is_err());
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
    let error = resolve_with_deadline("workspace", None, "app", |_| {
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
