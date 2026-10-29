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
    for source in [".", "api", "lib", "lib.wasm"] {
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
    std::fs::create_dir(root.path().join("api")).unwrap();
    std::fs::write(root.path().join("api/Cargo.toml"), "").unwrap();
    std::fs::write(root.path().join("Cargo.toml"), "").unwrap();
    let error = read(root.path()).unwrap_err().to_string();
    assert!(
        error.contains("Multiple Rust backend sources found"),
        "{error}"
    );
    assert!(error.contains("Cargo.toml, api/Cargo.toml"), "{error}");
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
