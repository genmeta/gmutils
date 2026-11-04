use super::*;

#[tokio::test]
async fn hosting_credentials_require_a_matching_key_but_not_cached_ocsp() {
    let root = tempfile::tempdir().unwrap();
    let host = "dev.zero.ai.dhttp.net";
    crate::test_credentials::generate(root.path(), &[("dev.zero.ai", host, &"a".repeat(64))]);
    let profile =
        dhttp_home::identity::IdentityProfile::try_from(root.path().join("dev.zero.ai")).unwrap();
    std::fs::remove_file(profile.ocsp_path()).unwrap();
    validate_host(&profile).await.unwrap();

    let key = rcgen::KeyPair::generate().unwrap();
    std::fs::remove_file(profile.key_path()).unwrap();
    std::fs::write(profile.key_path(), key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(profile.key_path(), std::fs::Permissions::from_mode(0o400))
            .unwrap();
    }
    let error = validate_host(&profile).await.unwrap_err();
    assert_eq!(error.code, "E_IDENTITY_UNAVAILABLE");
    assert!(
        error
            .hint
            .unwrap()
            .contains("genmeta identity apply dev.zero.ai")
    );
}

fn project(root: &Path) {
    std::fs::write(
        root.join("jade.toml"),
        "[package]\nname='hello'\nversion='1.0.0'\ndescription='Local project'\nlicense='MIT'\n",
    )
    .unwrap();
    std::fs::create_dir(root.join("public")).unwrap();
    std::fs::write(root.join("public/index.html"), "first").unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn build_then_run_publishes_plain_files_without_developer_credentials() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("project");
    std::fs::create_dir(&source).unwrap();
    project(&source);
    let profile = root.path().join("profile");
    std::fs::create_dir(&profile).unwrap();
    crate::pack::run(source.clone(), None, Some("dev.test.sky.lee".into()), false)
        .await
        .unwrap();
    let release = source.join("build/hello-1.0.0.waz");
    let original = std::fs::read(&release).unwrap();
    assert!(
        !crate::archive::waz_read(&original)
            .unwrap()
            .contains_key("signature.json")
    );
    let (name, files) = build(&source, "dev.test.sky.lee.dhttp.net").await.unwrap();
    assert!(!files.contains_key("signature.json"));
    assert_eq!(crate::archive::waz_read(&original).unwrap(), files);
    publish(&profile, &name, &files, false).unwrap();
    assert_eq!(
        std::fs::read(profile.join("dev/hello/app/index.html")).unwrap(),
        b"first"
    );
    assert!(profile.join("dev/hello/manifest.json").exists());
    assert!(!profile.join("ssl").exists());
    assert_eq!(std::fs::read(&release).unwrap(), original);
    std::fs::write(profile.join(".volume/hello/database"), "test data").unwrap();
    std::fs::write(source.join("public/index.html"), "second").unwrap();
    let (_, files) = build(&source, "dev.test.sky.lee.dhttp.net").await.unwrap();
    publish(&profile, &name, &files, false).unwrap();
    assert_eq!(
        std::fs::read(profile.join("dev/hello/app/index.html")).unwrap(),
        b"second"
    );
    assert_eq!(
        std::fs::read(profile.join(".volume/hello/database")).unwrap(),
        b"test data"
    );
    publish(&profile, &name, &files, true).unwrap();
    assert!(!profile.join(".volume/hello/database").exists());
    let backups = std::fs::read_dir(profile.join(".volume"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".hello-previous-")
                .then_some(path)
        })
        .collect::<Vec<_>>();
    assert_eq!(backups.len(), 1);
    assert_eq!(
        std::fs::read(backups[0].join("database")).unwrap(),
        b"test data"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn failed_build_and_destination_symlinks_do_not_replace_published_files() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("project");
    std::fs::create_dir(&source).unwrap();
    project(&source);
    let profile = root.path().join("profile");
    std::fs::create_dir(&profile).unwrap();
    let (_, files) = build(&source, "test.sky.lee.dhttp.net").await.unwrap();
    publish(&profile, "hello", &files, false).unwrap();
    std::fs::write(source.join("jade.toml"), "invalid manifest").unwrap();
    assert!(build(&source, "test.sky.lee.dhttp.net").await.is_err());
    assert_eq!(
        std::fs::read(profile.join("dev/hello/app/index.html")).unwrap(),
        b"first"
    );
    std::os::unix::fs::symlink(&source, profile.join("dev/escape")).unwrap();
    assert!(publish(&profile, "escape", &files, false).is_err());
    assert!(source.join("public/index.html").exists());
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn stop_removes_app_and_api_but_preserves_data_and_later_publishers() {
    let root = tempfile::tempdir().unwrap();
    project(root.path());
    let profile = root.path().join("identity");
    std::fs::create_dir(&profile).unwrap();
    let (_, mut files) = build(root.path(), "test.sky.lee.dhttp.net").await.unwrap();
    files.insert("backend.wasm".into(), b"local artifact".to_vec());
    let (_, first) = publish(&profile, "hello", &files, false).unwrap();
    std::fs::write(profile.join(".volume/hello/database"), "keep").unwrap();
    let (_, second) = publish(&profile, "hello", &files, false).unwrap();
    assert!(!remove_published(&profile, "hello", &first).unwrap());
    assert!(profile.join("dev/hello/lib.wasm").exists());
    assert!(remove_published(&profile, "hello", &second).unwrap());
    assert!(!profile.join("dev/hello").exists());
    assert_eq!(
        std::fs::read(profile.join(".volume/hello/database")).unwrap(),
        b"keep"
    );
}

#[tokio::test]
async fn default_identity_resolves_its_child_while_explicit_identity_is_used_exactly() {
    let root = tempfile::tempdir().unwrap();
    let home = dhttp_home::DhttpHome::new(root.path().to_path_buf());
    assert_eq!(
        select_host(&home, None, true).await.unwrap(),
        "dev.zero.ai.dhttp.net"
    );
    assert_eq!(
        select_host(&home, Some("dev.one.ai"), true).await.unwrap(),
        "dev.one.ai.dhttp.net"
    );
    assert_eq!(
        select_host(&home, Some("dev.zero.ai"), true).await.unwrap(),
        "dev.zero.ai.dhttp.net"
    );
    for name in ["one.ai", "dev.wang"] {
        assert_eq!(
            select_host(&home, Some(name), true).await.unwrap_err().code,
            "E_IDENTITY_REQUIRED"
        );
    }
    std::fs::write(
        home.settings_path(),
        "[default]\nname='dev.wang.dhttp.net'\n",
    )
    .unwrap();
    assert_eq!(
        select_host(&home, None, true).await.unwrap(),
        "dev.dev.wang.dhttp.net"
    );
    std::fs::write(
        home.settings_path(),
        "[default]\nname='dev.dev.wang.dhttp.net'\n",
    )
    .unwrap();
    assert_eq!(
        select_host(&home, None, true).await.unwrap(),
        "dev.dev.wang.dhttp.net"
    );
}

#[tokio::test]
async fn local_dependencies_resolve_from_each_manifest_and_paths_stay_out_of_packages() {
    let root = tempfile::tempdir().unwrap();
    let app = root.path().join("app");
    let local = root.path().join("profile");
    for path in [&app, &local] {
        std::fs::create_dir(path).unwrap();
        project(path);
    }
    let app_manifest = std::fs::read_to_string(app.join("jade.toml")).unwrap();
    std::fs::write(app.join("jade.toml"), format!("{app_manifest}\n[[dependencies]]\nauthor='std.dhttp.net'\nname='profile'\nversion='1.0.0'\npath='../profile'\n\n[[dependencies]]\nauthor='std.dhttp.net'\nname='message'\nversion='0.2.1'\n")).unwrap();
    let local_manifest = std::fs::read_to_string(local.join("jade.toml"))
        .unwrap()
        .replace("name='hello'", "name='profile'\nauthor='std.dhttp.net'");
    std::fs::write(local.join("jade.toml"), local_manifest).unwrap();
    let (locals, remote) = projects(&app.join("jade.toml"), "dev.zero.ai.dhttp.net").unwrap();
    assert_eq!(locals.len(), 2);
    assert_eq!(locals["profile"], local.canonicalize().unwrap());
    assert_eq!(
        remote,
        vec![json!({"author":"std.dhttp.net","name":"message","version":"0.2.1"})]
    );
    let before = graph_fingerprint(&locals).unwrap();
    std::fs::write(local.join("public/index.html"), "local dependency changed").unwrap();
    assert_ne!(before, graph_fingerprint(&locals).unwrap());
    let (_, files) = build(&app, "dev.zero.ai.dhttp.net").await.unwrap();
    let manifest: Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
    assert_eq!(manifest["dependencies"].as_array().unwrap().len(), 2);
    assert!(
        manifest["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|dep| dep.get("path").is_none())
    );
    assert!(!String::from_utf8_lossy(&files["manifest.json"]).contains("../profile"));
    std::fs::write(
        local.join("jade.toml"),
        std::fs::read_to_string(local.join("jade.toml"))
            .unwrap()
            .replace("version='1.0.0'", "version='1.0.1'"),
    )
    .unwrap();
    assert!(projects(&app, "dev.zero.ai.dhttp.net").is_err());
}

#[test]
fn dependency_cycles_and_conflicting_versions_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    project(root.path());
    let manifest = std::fs::read_to_string(root.path().join("jade.toml")).unwrap();
    std::fs::write(root.path().join("jade.toml"), format!("{manifest}\n[[dependencies]]\nauthor='dev.zero.ai'\nname='hello'\nversion='1.0.0'\npath='.'\n")).unwrap();
    assert!(
        projects(root.path(), "dev.zero.ai.dhttp.net")
            .unwrap_err()
            .message
            .contains("cycle")
    );
    std::fs::write(root.path().join("jade.toml"), format!("{manifest}\n[[dependencies]]\nauthor='std.dhttp.net'\nname='message'\nversion='0.2.1'\n\n[[dependencies]]\nauthor='std.dhttp.net'\nname='message'\nversion='0.3.0'\n")).unwrap();
    assert!(projects(root.path(), "dev.zero.ai.dhttp.net").is_err());
}

#[derive(Debug)]
struct DevelopmentPeer(dhttp::resolve::EndpointAddr);
impl std::fmt::Display for DevelopmentPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("development test host")
    }
}
impl dhttp::resolve::Resolve for DevelopmentPeer {
    fn lookup<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: Option<dhttp::resolve::Family>,
    ) -> dhttp::resolve::ResolveFuture<'a> {
        use futures::{FutureExt, StreamExt};
        async move { Ok(futures::stream::iter([(dhttp::resolve::Source::System, self.0)]).boxed()) }
            .boxed()
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "run alone; generates ordinary TLS credentials and owns global TLS/DNS/UDP"]
async fn real_http3_installs_exact_dependencies_using_ordinary_identity_credentials() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use http_body_util::BodyExt;
    use qprotocol::{Dock, UdpSocket};
    let root = tempfile::tempdir().unwrap();
    let host = "dev.zero.ai.dhttp.net";
    crate::test_credentials::generate(root.path(), &[("dev.zero.ai", host, &"a".repeat(64))]);
    let profile =
        dhttp_home::identity::IdentityProfile::try_from(root.path().join("dev.zero.ai")).unwrap();
    let ca = std::fs::read(root.path().join("ca.crt")).unwrap();
    let peer = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    Dock::global().add(peer.clone()).unwrap().unwrap();
    dhttp::DhttpNetwork::init().await.unwrap();
    qtls::RootCerts::set(
        rustls_pemfile::certs(&mut ca.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap();
    dhttp::resolve::Resolver::add(Arc::new(DevelopmentPeer(
        dhttp::resolve::EndpointAddr::direct(peer.local_addr().unwrap()),
    )));
    let endpoint = dhttp::Endpoint::new(
        qbase::endpoint::Endpoint::new(
            host,
            profile.load_certs().await.unwrap(),
            profile.load_key().await.unwrap(),
            profile.load_ocsp().await.unwrap(),
        )
        .unwrap(),
    );
    let incorrect = Arc::new(AtomicBool::new(false));
    let dependency = json!({"author":"std.dhttp.net","name":"message","version":"0.2.1"});
    let listener = endpoint
        .listen(
            dhttp::Scope::Loopback.into(),
            tower::service_fn({
                let incorrect = incorrect.clone();
                let dependency = dependency.clone();
                move |request: http::Request<dhttp::Body>| {
                    let incorrect = incorrect.clone();
                    let dependency = dependency.clone();
                    async move {
                        assert_eq!(request.method(), http::Method::POST);
                        assert_eq!(request.uri().path(), "/std/sys/pkg/install");
                        let handshake = request
                            .extensions()
                            .get::<dhttp::HandshakeSummary>()
                            .unwrap();
                        assert_eq!(
                            handshake.remote.as_ref().unwrap().name(),
                            "dev.zero.ai.dhttp.net"
                        );
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), dependency);
                        let mut saved = dependency;
                        if incorrect.load(Ordering::SeqCst) {
                            saved["version"] = "9.9.9".into();
                        }
                        let body = http_body_util::Full::new(bytes::Bytes::from(
                            serde_json::to_vec(&saved).unwrap(),
                        ))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                        Ok::<_, dhttp::BoxError>(http::Response::new(body))
                    }
                }
            }),
        )
        .await
        .unwrap();
    let listener = tokio::spawn(listener);
    assert!(!profile.path().join("code-signing").exists());
    install_from_host(&endpoint, host, std::slice::from_ref(&dependency))
        .await
        .unwrap();
    incorrect.store(true, Ordering::SeqCst);
    assert_eq!(
        install_from_host(&endpoint, host, &[dependency])
            .await
            .unwrap_err()
            .code,
        "E_INSTALL_FAILED"
    );
    listener.abort();
}

#[tokio::test]
async fn root_static_package_never_embeds_local_dependency_configuration() {
    let root = tempfile::tempdir().unwrap();
    project(root.path());
    std::fs::rename(
        root.path().join("public/index.html"),
        root.path().join("index.html"),
    )
    .unwrap();
    std::fs::remove_dir(root.path().join("public")).unwrap();
    let (_, files) = build(root.path(), "dev.zero.ai.dhttp.net").await.unwrap();
    assert!(!files.contains_key("public/jade.toml"));
}
