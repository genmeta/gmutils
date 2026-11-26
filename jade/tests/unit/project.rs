use super::*;

#[test]
fn reads_frontends_without_a_frontend_section() {
    for (source, build) in [
        (".", true),
        ("web", true),
        ("app", true),
        (".", false),
        ("web", false),
        ("app", false),
        ("public", false),
        ("dist", false),
        ("web/dist", false),
        ("app/dist", false),
    ] {
        let root = tempfile::tempdir().unwrap();
        let manifest_path = root.path().join("jade.toml");
        let original =
            "[package]\nname='hello'\nversion='1.0.0'\ndescription='Test'\nlicense='MIT'\n";
        std::fs::write(&manifest_path, original).unwrap();
        let directory = root.path().join(source);
        std::fs::create_dir_all(&directory).unwrap();
        if build {
            std::fs::write(
                directory.join("package.json"),
                r#"{"scripts":{"build":"vite build"}}"#,
            )
            .unwrap();
            // Sources must win over static templates and previous build output.
            for stale in ["public", "dist", "web/dist", "app/dist"] {
                std::fs::create_dir_all(root.path().join(stale)).unwrap();
                std::fs::write(root.path().join(stale).join("index.html"), "stale").unwrap();
            }
        } else {
            std::fs::write(directory.join("index.html"), "<h1>Static</h1>").unwrap();
        }
        let (_, manifest) = read(root.path()).unwrap();
        assert_eq!(manifest.frontend.as_deref(), Some(Path::new(source)));
        assert_eq!(
            manifest.metadata("alice.dhttp.net").unwrap().1["entry"],
            "/"
        );
        assert!(manifest.backend.is_none());
        std::fs::write(
            &manifest_path,
            format!("{original}\n[frontend]\npath='{source}'\n"),
        )
        .unwrap();
        assert!(
            read(root.path())
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
    }
}

#[test]
fn ambiguous_frontends_fail_instead_of_choosing_one() {
    for (sources, marker, content) in [
        (
            [".", "web"],
            "package.json",
            r#"{"scripts":{"build":"vite build"}}"#,
        ),
        ([".", "public"], "index.html", "static"),
        (["dist", "web/dist"], "index.html", "prebuilt"),
    ] {
        let root = tempfile::tempdir().unwrap();
        for source in sources {
            std::fs::create_dir_all(root.path().join(source)).unwrap();
            std::fs::write(root.path().join(source).join(marker), content).unwrap();
        }
        let error = discover_frontend(&root.path().canonicalize().unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("Multiple frontend sources found"), "{error}");
    }
}

#[test]
fn reads_backend_projects_without_a_backend_section() {
    for source in [".", "wasm", "lib", "lib.wasm"] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("jade.toml"),
            "[package]\nname='hello'\nversion='1.0.0'\ndescription='Test'\nlicense='MIT'\n",
        )
        .unwrap();
        if source == "lib.wasm" {
            std::fs::write(root.path().join(source), b"\0asm\x0d\0\x01\0").unwrap();
        } else {
            let directory = root.path().join(source);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                directory.join("Cargo.toml"),
                "[package]\nname='hello'\nversion='1.0.0'\n",
            )
            .unwrap();
            std::fs::write(root.path().join("lib.wasm"), "stale build output").unwrap();
        }
        let (_, manifest) = read(root.path()).unwrap();
        assert_eq!(manifest.backend.as_deref(), Some(Path::new(source)));
        assert!(
            manifest
                .metadata("alice.dhttp.net")
                .unwrap()
                .1
                .get("host")
                .is_none()
        );

        let manifest_path = root.path().join("jade.toml");
        let original = std::fs::read_to_string(&manifest_path).unwrap();
        std::fs::write(&manifest_path, format!("{original}\n[backend]\npath='.'\n")).unwrap();
        assert!(
            read(root.path())
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
    }
}

#[test]
fn ambiguous_backends_are_rejected_before_building() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("jade.toml"),
        "[package]\nname='hello'\nversion='1.0.0'\ndescription='Test'\nlicense='MIT'\n",
    )
    .unwrap();
    std::fs::create_dir(root.path().join("wasm")).unwrap();
    std::fs::write(root.path().join("wasm/Cargo.toml"), "").unwrap();
    std::fs::write(root.path().join("Cargo.toml"), "").unwrap();
    let error = read(root.path()).unwrap_err().to_string();
    assert!(
        error.contains("Multiple Rust backend sources found"),
        "{error}"
    );
    assert!(error.contains("Cargo.toml, wasm/Cargo.toml"), "{error}");
}

#[test]
fn package_manager_uses_bun_locks_and_rejects_ambiguous_locks() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path();
    assert_eq!(node_manager(path, &json!({})).unwrap(), "npm");
    std::fs::write(path.join("bun.lock"), "{}").unwrap();
    assert_eq!(node_manager(path, &json!({})).unwrap(), "bun");
    std::fs::write(path.join("package-lock.json"), "{}").unwrap();
    assert!(node_manager(path, &json!({})).is_err());
    assert_eq!(
        node_manager(path, &json!({"packageManager":"bun@1.2.16"})).unwrap(),
        "bun"
    );
    assert_eq!(
        node_manager(path, &json!({"packageManager":"npm@10"})).unwrap(),
        "npm"
    );
    assert!(node_manager(path, &json!({"packageManager":"unsupported@1"})).is_err());
}

#[test]
fn dependencies_are_exact_names_without_authors_or_published_paths() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("index.html"), "app").unwrap();
    let manifest = "[package]\nname='parent'\nversion='1.0.0'\ndescription='Test'\nlicense='MIT'\n[[dependencies]]\nname='child'\nversion='2.0.0'\npath='../child'\n";
    std::fs::write(root.path().join("jade.toml"), manifest).unwrap();
    let (_, config) = read(root.path()).unwrap();
    assert_eq!(
        config.metadata("alice.dhttp.net").unwrap().1["dependencies"],
        serde_json::json!([{"name":"child","version":"2.0.0"}])
    );
    std::fs::write(
        root.path().join("jade.toml"),
        format!("{manifest}author='alice.dhttp.net'\n"),
    )
    .unwrap();
    assert!(
        read(root.path())
            .unwrap_err()
            .message
            .contains("unknown field")
    );
}

#[test]
fn standard_http_paths_follow_declarations_and_reserve_native_services() {
    let backend = include_bytes!("../fixtures/wasi-http-read-request-then-respond.wasm");
    for (path, accepted) in [
        ("/run/python", true),
        ("/comm/message", true),
        ("/comm/group/{topic}/member/{name}/avatar", true),
        ("/{namespace}/group", false),
        ("/comm/{topic}/{topic}", false),
        ("/comm/group/prefix-{topic}", false),
        ("/comm/group/{topic?}", false),
        ("/runner", true),
        ("/sys/listen", false),
        ("/file", false),
        ("/forward/name", false),
    ] {
        let document=serde_json::to_vec(&json!({"openapi":"3.1.0","info":{"title":"Python","version":"0.1.0"},"paths":{path:{"post":{"operationId":"execute","summary":"Execute","responses":{"200":{"description":"ok"}}}}}})).unwrap();
        let bytes = crate::pack::embedded_openapi(backend.to_vec(), Some(&document)).unwrap();
        let result = validate_component(&bytes, "0.1.0", "dev.genmeta.tech.dhttp.net", "python");
        assert_eq!(result.is_ok(), accepted, "{path}: {result:?}");
    }
}

#[test]
#[ignore = "run with PISHOO_MESSAGE_COMPONENT built against call-context@0.3.0"]
fn accepts_verified_service_context_from_a_real_component() {
    let component = std::fs::read(std::env::var_os("PISHOO_MESSAGE_COMPONENT").unwrap()).unwrap();
    let document = serde_json::to_vec(&json!({
        "openapi":"3.1.0", "info":{"title":"Message","version":"0.3.4"},
        "paths":{"/comm/message":{"post":{"operationId":"message","summary":"Store messages",
            "responses":{"200":{"description":"ok"}}}}}
    }))
    .unwrap();
    let bytes = crate::pack::embedded_openapi(component, Some(&document)).unwrap();
    validate_component(
        &bytes,
        "0.3.4",
        "dev.genmeta.tech.dhttp.net",
        "std/comm/message",
    )
    .unwrap();
}

#[test]
fn overlapping_paths_require_a_strictly_more_specific_template() {
    let backend = include_bytes!("../fixtures/wasi-http-read-request-then-respond.wasm");
    let paths = [
        ("/comm/message/{name}", "/comm/message/list", true),
        ("/comm/message/history", "/comm/message/{name}", true),
        (
            "/comm/group/{topic}/member/list",
            "/comm/group/{group}/member/{name}",
            true,
        ),
        ("/comm/group/{topic}", "/comm/group/{name}", false),
        (
            "/comm/group/{topic}/member/owner",
            "/comm/group/dev/member/{name}",
            false,
        ),
        ("/a/{b}/c/d", "/a/b/{c}/{d}", false),
    ];
    for (first, second, accepted) in paths {
        let operation = |id: &str| {
            json!({"get": {"operationId":id,"summary":id,
            "responses":{"200":{"description":"ok"}}}})
        };
        let document = serde_json::to_vec(&json!({
            "openapi":"3.1.0","info":{"title":"Routes","version":"0.1.0"},
            "paths":{first:operation("first"),second:operation("second")}
        }))
        .unwrap();
        let bytes = crate::pack::embedded_openapi(backend.to_vec(), Some(&document)).unwrap();
        let result = validate_component(
            &bytes,
            "0.1.0",
            "dev.genmeta.tech.dhttp.net",
            "std/comm/group",
        );
        assert_eq!(result.is_ok(), accepted, "{first} and {second}: {result:?}");
    }
}
