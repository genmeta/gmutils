//! Real pack/check executables with generated credentials in isolated homes.
use std::{
    ffi::OsStr,
    path::Path,
    process::{Command, Output},
};

use serde_json::json;

fn identity(home: &Path) {
    let name = "alice.dhttp.net";
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    let ski = format!("1:0:{}", "a".repeat(64));
    let mut der = vec![4, ski.len() as u8];
    der.extend_from_slice(ski.as_bytes());
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 14],
            der,
        ));
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let ssl = home.join("alice/ssl");
    std::fs::create_dir_all(&ssl).unwrap();
    std::fs::write(ssl.join("fullchain.crt"), cert.pem()).unwrap();
    std::fs::write(ssl.join("privkey.pem"), key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            ssl.join("privkey.pem"),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
    }
    // Offline package signing needs certificate + private key, not transport OCSP.
}

fn project(path: &Path, kind: &str, repository: &str) {
    std::fs::create_dir_all(path).unwrap();
    let content = if kind == "app" {
        "entry='/'"
    } else {
        "host={}"
    };
    let mapping = if kind == "app" {
        "'/public'='public'"
    } else {
        "'/metadata'='metadata'"
    };
    let module = if kind == "app" {
        ""
    } else {
        "[[module]]\nname='backend'\nsource='lib.wasm'\n"
    };
    std::fs::write(path.join("wasmer.toml"), format!(
        "[package]\nname='alice.dhttp.net/hello'\nversion='1.0.0'\ndescription='Test package'\nlicense='MIT'\n{repository}\n[package.pishoo]\nkind='{kind}'\ntitle='Hello'\nchangelog='Initial release'\ndependencies=[]\n{content}\n[fs]\n{mapping}\n{module}"
    )).unwrap();
    if kind == "app" {
        std::fs::create_dir(path.join("public")).unwrap();
        std::fs::write(path.join("public/index.html"), "<h1>Hello</h1>").unwrap();
    } else {
        std::fs::create_dir(path.join("metadata")).unwrap();
        std::fs::write(path.join("metadata/openapi.json"), serde_json::to_vec(&json!({
            "openapi":"3.1.0","info":{"title":"Hello","version":"1.0.0"},
            "paths":{"/upload":{"post":{"operationId":"upload","summary":"Upload","responses":{"200":{"description":"OK"}}}}}
        })).unwrap()).unwrap();
        std::fs::write(
            path.join("lib.wasm"),
            include_bytes!("fixtures/wasi-http-read-request-then-respond.wasm"),
        )
        .unwrap();
    }
}

fn pack(home: &Path, cwd: &Path, args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_genmeta"))
        .env("HOME", home.parent().unwrap())
        .env("DHTTP_HOME", "/nonexistent-ignored-pishoo-home")
        .current_dir(cwd)
        .args(["package", "build", "--no-build"])
        .args(args)
        .output()
        .unwrap()
}
fn fails(output: &Output, error: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "unexpected success output");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(error),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn urls_and_missing_credentials_and_id_mismatches_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("app");
    project(&app, "app", "");
    let home = dir.path().join("empty-home/.dhttp");
    for url in [
        "https://example.com/wasmer.toml",
        "https:example.com/wasmer.toml",
        "file:/tmp/wasmer.toml",
        "data:text/plain,manifest",
        "git:repository",
    ] {
        fails(&pack(&home, &app, &[url.as_ref()]), "local filesystem");
    }
    fails(
        &pack(&home, &app, &["-i".as_ref(), "bob~".as_ref()]),
        "differs from manifest publisher",
    );
    fails(&pack(&home, &app, &[]), "local credentials");
    assert!(!app.join("dist").exists());
}

#[test]
fn malformed_repository_is_rejected_before_loading_credentials() {
    for raw in [
        "''",
        "123",
        "'http://github.com/x/y'",
        "'https://user:password@example.com/a'",
        "'https://@example.com/a'",
        "'https://'",
        "'https:///path'",
        "'https://example.com/a b'",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("app");
        project(&app, "app", &format!("repository={raw}"));
        let result = pack(&dir.path().join("empty-home/.dhttp"), &app, &[]);
        fails(&result, "repository");
        assert!(!app.join("dist").exists());
    }
}

#[test]
fn invalid_declarations_and_missing_artifacts_do_not_publish() {
    for (kind, from, to, error) in [
        (
            "app",
            "dependencies=[]",
            "dependencies=[{publisher='alice.dhttp.net',name='hello',version='01.0.0'}]",
            "dependency",
        ),
        (
            "app",
            "version='1.0.0'",
            "version='1.0.0-preview'",
            "MAJOR.MINOR.PATCH",
        ),
        ("app", "kind='app'", "kind='app'\nhost={}", "forbids host"),
        (
            "app",
            "[fs]",
            "[[module]]\nname='backend'\nsource='lib.wasm'\n[fs]",
            "zero backend",
        ),
        ("lib", "host={}", "entry='/'\nhost={}", "forbids entry"),
        (
            "lib",
            "dependencies=[]",
            "dependencies=[{publisher='alice.dhttp.net',name='hello',version='1.0.0'}]",
            "self Lib dependency",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("project");
        project(&app, kind, "");
        let manifest = app.join("wasmer.toml");
        std::fs::write(
            &manifest,
            std::fs::read_to_string(&manifest)
                .unwrap()
                .replace(from, to),
        )
        .unwrap();
        fails(
            &pack(&dir.path().join("empty-home/.dhttp"), &app, &[]),
            error,
        );
        assert!(!app.join("dist").exists());
    }
    for (kind, missing) in [
        ("app", "public/index.html"),
        ("lib", "metadata/openapi.json"),
        ("lib", "lib.wasm"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("project");
        project(&app, kind, "");
        std::fs::remove_file(app.join(missing)).unwrap();
        fails(
            &pack(&dir.path().join("empty-home/.dhttp"), &app, &[]),
            "build artifact",
        );
        assert!(!app.join("dist").exists());
    }
}

#[test]
fn invalid_files_and_existing_targets_preserve_old_content() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home/.dhttp");
    identity(&home);
    let app = dir.path().join("app");
    project(&app, "app", "");
    let file = dir.path().join("old.webc");
    std::fs::write(&file, "old content").unwrap();
    fails(
        &pack(&home, &app, &["-o".as_ref(), file.as_os_str()]),
        "output already exists",
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"old content");
    for invalid in ["a%20b", "name with space", "question?", "back\\slash"] {
        let bad = app.join("public").join(invalid);
        std::fs::write(&bad, "invalid").unwrap();
        fails(&pack(&home, &app, &[]), "invalid content file path");
        std::fs::remove_file(bad).unwrap();
        assert!(!app.join("dist").exists());
    }
    let large = app.join("public/large.bin");
    std::fs::File::create(&large)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    fails(&pack(&home, &app, &[]), "size limit");
    assert!(!app.join("dist").exists());
}

#[cfg(unix)]
#[test]
fn backend_fifo_is_rejected_without_waiting_for_a_writer() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    project(&lib, "lib", "");
    let backend = lib.join("lib.wasm");
    std::fs::remove_file(&backend).unwrap();
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&backend)
            .status()
            .unwrap()
            .success()
    );
    fails(
        &pack(&dir.path().join("empty-home/.dhttp"), &lib, &[]),
        "regular files",
    );
    assert!(!lib.join("dist").exists());
}
