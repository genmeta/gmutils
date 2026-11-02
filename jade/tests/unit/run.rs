use super::*;

fn project(root: &Path) {
    std::fs::write(
        root.join("jade.toml"),
        "[package]\nname='hello'\nversion='1.0.0'\ndescription='Local project'\nlicense='MIT'\n",
    )
    .unwrap();
    std::fs::create_dir(root.join("public")).unwrap();
    std::fs::write(root.join("public/index.html"), "first").unwrap();
}

#[tokio::test]
async fn local_build_does_not_require_or_generate_developer_credentials() {
    let root = tempfile::tempdir().unwrap();
    project(root.path());
    let bytes = snapshot(root.path(), "dev.sky.lee.dhttp.net")
        .await
        .unwrap();
    let files = crate::archive::waz_read(&bytes).unwrap();
    assert!(!files.contains_key("signature.json"));
    let manifest: Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
    assert_eq!(manifest["package"]["author"], "dev.sky.lee.dhttp.net");
    assert_eq!(files["public/index.html"], b"first");
    assert!(!root.path().join("build/hello-1.0.0.waz").exists());
    assert!(
        crate::package::inspect_package(&bytes).await.is_err(),
        "unsigned snapshots cannot be published as a signed release"
    );
}

#[test]
fn watcher_tracks_contents_and_ignores_build_outputs_and_dependencies() {
    let root = tempfile::tempdir().unwrap();
    project(root.path());
    let before = source_fingerprint(root.path()).unwrap();
    for ignored in ["build", "target", "node_modules", ".git", ".jade"] {
        std::fs::create_dir(root.path().join(ignored)).unwrap();
        std::fs::write(root.path().join(ignored).join("generated"), "output").unwrap();
    }
    assert_eq!(source_fingerprint(root.path()).unwrap(), before);
    std::fs::write(root.path().join("public/index.html"), "second").unwrap();
    assert_ne!(source_fingerprint(root.path()).unwrap(), before);
}

#[cfg(unix)]
#[tokio::test]
async fn local_control_protocol_checks_responses_and_reports_host_rejection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let task = tokio::spawn(async move {
        let length = server.read_u32().await.unwrap() as usize;
        let mut bytes = vec![0; length];
        server.read_exact(&mut bytes).await.unwrap();
        let open: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(open["op"], "open");
        assert!(open.get("certificate").is_none());
        let reply =
            serde_json::to_vec(&json!({"status":"error","message":"name already installed"}))
                .unwrap();
        server.write_u32(reply.len() as u32).await.unwrap();
        server.write_all(&reply).await.unwrap();
    });
    let error = exchange(
        &mut client,
        &json!({"op":"open","project":"a".repeat(64),"name":"hello","fresh":false}),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "E_DEV_REJECTED");
    assert!(error.message.contains("already installed"));
    task.await.unwrap();
}

#[test]
fn watcher_includes_static_dist_projects_but_excludes_compiler_dist_output() {
    let root = tempfile::tempdir().unwrap();
    project(root.path());
    std::fs::rename(root.path().join("public"), root.path().join("dist")).unwrap();
    let first = source_fingerprint(root.path()).unwrap();
    std::fs::write(root.path().join("dist/index.html"), "edited static input").unwrap();
    assert_ne!(source_fingerprint(root.path()).unwrap(), first);
    std::fs::write(
        root.path().join("package.json"),
        r#"{"scripts":{"build":"vite build"}}"#,
    )
    .unwrap();
    let before_output = source_fingerprint(root.path()).unwrap();
    std::fs::write(root.path().join("dist/index.html"), "compiler output").unwrap();
    assert_eq!(source_fingerprint(root.path()).unwrap(), before_output);
}
