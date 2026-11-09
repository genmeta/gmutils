use super::*;

#[test]
fn embeds_one_openapi_before_package_signing() {
    let document = br#"{"openapi":"3.1.0","info":{"version":"1.0.0"},"paths":{}}"#;
    let original = b"\0asm\x0d\0\x01\0".to_vec();
    let embedded = embedded_openapi(original.clone(), Some(document)).unwrap();
    assert!(embedded.starts_with(&original));
    assert!(
        embedded
            .windows(document.len())
            .any(|bytes| bytes == document)
    );
    assert_eq!(embedded_openapi(embedded.clone(), None).unwrap(), embedded);
    assert_eq!(
        embedded_openapi(embedded.clone(), Some(document)).unwrap(),
        embedded
    );
    assert!(embedded_openapi(embedded, Some(br#"{"openapi":"3.1.0","paths":{"/x":{}}}"#)).is_err());
    assert!(embedded_openapi(original, None).is_err());
}

#[test]
fn rejects_duplicate_and_truncated_embedded_documents() {
    let document = br#"{"openapi":"3.1.0","paths":{}}"#;
    let original = b"\0asm\x0d\0\x01\0".to_vec();
    let mut embedded = embedded_openapi(original, Some(document)).unwrap();
    embedded.extend_from_within(8..);
    assert!(embedded_openapi(embedded, None).is_err());
    assert!(embedded_openapi(b"\0asm\x0d\0\x01\0\0\x80".to_vec(), None).is_err());
}

#[tokio::test]
async fn static_resources_exclude_local_dependency_projects_and_nested_manifests() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("index.html"), "application").unwrap();
    std::fs::write(root.join("jade.toml"), "[package]\nname='application'\nversion='1.0.0'\ndescription='Test'\nlicense='MIT'\n[[dependencies]]\nname='child'\nversion='1.0.0'\npath='packages/child/config.toml'\n").unwrap();
    for directory in ["packages/child", "assets/indirect"] {
        let path = root.join(directory);
        std::fs::create_dir_all(path.join("build")).unwrap();
        std::fs::write(path.join("build/private-key"), "local cache").unwrap();
        std::fs::write(path.join("source"), "private source").unwrap();
    }
    std::fs::write(
        root.join("packages/child/config.toml"),
        "path='/private/local/source'",
    )
    .unwrap();
    std::fs::write(
        root.join("assets/indirect/jade.toml"),
        "path='/private/transitive/source'",
    )
    .unwrap();
    std::fs::write(root.join("assets/style.css"), "body {}").unwrap();
    let (root, config) = crate::project::read(root).unwrap();
    let files = build_files(
        &root,
        &config,
        "dev.alex.chen.dhttp.net",
        &root.join("build/application-1.0.0.waz"),
    )
    .await
    .unwrap();
    let archive = crate::archive::waz_write(&files).unwrap();
    let packaged = crate::archive::waz_read(&archive).unwrap();
    assert_eq!(packaged["public/index.html"], b"application");
    assert_eq!(packaged["public/assets/style.css"], b"body {}");
    assert!(
        !packaged
            .keys()
            .any(|path| path.starts_with("public/packages/child/")
                || path.starts_with("public/assets/indirect/"))
    );
    assert!(!packaged.values().any(|bytes| {
        bytes
            .windows(b"/private/".len())
            .any(|part| part == b"/private/")
    }));
}
