//! Offline build/sign executables with generated credentials in isolated homes.
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
    let content = match kind {
        "app" => "entry='/'",
        "lib" => "host={}",
        _ => "entry='/'\nhost={}",
    };
    let mapping = if kind == "lib" {
        ""
    } else {
        "[fs]\n'/public'='public'\n"
    };
    let module = if kind == "app" {
        ""
    } else {
        "[[module]]\nname='backend'\nsource='lib.wasm'\n"
    };
    std::fs::write(path.join("wasmer.toml"),format!("[package]\nname='alice.dhttp.net/hello'\nversion='1.0.0'\ndescription='Test package'\nlicense='MIT'\n{repository}\n[package.pishoo]\ntitle='Hello'\nchangelog='Initial release'\ndependencies=[]\n{content}\n{mapping}{module}")).unwrap();
    if kind != "lib" {
        std::fs::create_dir(path.join("public")).unwrap();
        std::fs::write(path.join("public/index.html"), "<h1>Hello</h1>").unwrap();
    }
    if kind != "app" {
        let mut backend =
            include_bytes!("fixtures/wasi-http-read-request-then-respond.wasm").to_vec();
        let document=serde_json::to_vec(&json!({"openapi":"3.1.0","info":{"title":"Hello","version":"1.0.0"},"paths":{"/upload":{"post":{"operationId":"upload","summary":"Upload","responses":{"200":{"description":"OK"}}}}}})).unwrap();
        let name = b"pishoo:openapi";
        let mut section = vec![name.len() as u8];
        section.extend(name);
        section.extend(document);
        backend.push(0);
        let mut n = section.len();
        while n >= 128 {
            backend.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        backend.push(n as u8);
        backend.extend(section);
        std::fs::write(path.join("lib.wasm"), backend).unwrap();
    }
}

fn pack(home: &Path, cwd: &Path, args: &[&OsStr]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_genmeta"));
    #[cfg(windows)]
    command.env("USERPROFILE", home.parent().unwrap());
    command
        .env("HOME", home.parent().unwrap())
        .env("DHTTP_HOME", "/nonexistent-ignored-pishoo-home")
        .current_dir(cwd)
        .args(["jade", "build", "--no-build"])
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
fn jade_create_scaffolds_a_package_that_builds_with_local_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home/.dhttp");
    let create = || {
        Command::new(env!("CARGO_BIN_EXE_genmeta"))
            .current_dir(dir.path())
            .args(["jade", "create", "hello", "--id", "alice~"])
            .output()
            .unwrap()
    };
    let created = create();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(summary["id"], "alice~/hello");
    let app = dir.path().join("hello");
    let manifest = std::fs::read_to_string(app.join("wasmer.toml")).unwrap();
    let config: toml::Value = toml::from_str(&manifest).unwrap();
    assert_eq!(
        config["package"]["name"].as_str(),
        Some("alice.dhttp.net/hello")
    );
    assert!(app.join("public/index.html").is_file());
    assert_eq!(
        std::fs::read_to_string(app.join(".gitignore")).unwrap(),
        "/dist/\n"
    );
    fails(&create(), "use a new path");
    assert_eq!(
        std::fs::read_to_string(app.join("wasmer.toml")).unwrap(),
        manifest
    );

    identity(&home);
    let built = pack(&home, &app, &[]);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let file = app.join("dist/hello-0.1.0.waz");
    let package = webc::Container::from_bytes_and_version(
        std::fs::read(file).unwrap().into(),
        webc::Version::V3,
    )
    .unwrap();
    package.validate().unwrap();
    assert!(package.get_volume("pishoo-signature").is_some());
    assert!(
        package
            .get_volume("public")
            .unwrap()
            .read_file("/index.html")
            .is_some()
    );
}

#[test]
fn jade_create_rejects_invalid_names_and_publishers_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    for (name, publisher, error) in [
        ("Hello", "alice~", "Package name"),
        ("bad name", "alice~", "Package name"),
        ("hello", "https://example.com", "publisher"),
        ("https://example.com/hello", "alice~", "local filesystem"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_genmeta"))
            .current_dir(dir.path())
            .args(["jade", "create", name, "--id", publisher])
            .output()
            .unwrap();
        fails(&output, error);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
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
        (
            "app",
            "entry='/'",
            "entry='/'\nhost={}",
            "require a backend",
        ),
        (
            "app",
            "title='Hello'",
            "title='Hello'\nkind='app'",
            "unknown package.pishoo",
        ),
        (
            "lib",
            "host={}",
            "entry='/'\nhost={}",
            "entry requires public resources",
        ),
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
    for (kind, missing) in [("app", "public/index.html"), ("lib", "lib.wasm")] {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("project");
        project(&app, kind, "");
        std::fs::remove_file(app.join(missing)).unwrap();
        fails(
            &pack(&dir.path().join("empty-home/.dhttp"), &app, &[]),
            if kind == "app" {
                "frontend requires"
            } else {
                "build artifact"
            },
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
    let file = dir.path().join("old.waz");
    std::fs::write(&file, "old content").unwrap();
    fails(
        &pack(&home, &app, &["-o".as_ref(), file.as_os_str()]),
        "output already exists",
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"old content");
    let invalid_names = ["a%20b", "name with space", "hash#name"];
    #[cfg(unix)]
    let invalid_names = invalid_names
        .into_iter()
        .chain(["question?", "back\\slash"]);
    // Windows rejects '?' as a filename and treats '\\' as a separator before
    // the packer can inspect them. Keep portable invalid-name coverage there.
    for invalid in invalid_names {
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

#[test]
fn app_and_lib_build_signed_packages_offline_without_a_host_service() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rcgen::PublicKeyData;
    use sha2::{Digest, Sha256};
    for kind in ["app", "lib", "both"] {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home/.dhttp");
        identity(&home);
        let input = dir.path().join(kind);
        project(&input, kind, "");
        let output = input.join("dist/signed.dhttp.net.waz");
        let result = pack(&home, &input, &["--output".as_ref(), output.as_os_str()]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let summary: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(summary["id"], "alice~/hello");
        assert_eq!(
            summary["file"],
            std::fs::canonicalize(&output)
                .unwrap()
                .to_string_lossy()
                .as_ref()
        );
        let bytes = std::fs::read(&output).unwrap();
        assert_eq!(
            summary["package_sha256"],
            format!("{:x}", Sha256::digest(&bytes))
        );
        let package =
            webc::Container::from_bytes_and_version(bytes.clone().into(), webc::Version::V3)
                .unwrap();
        package.validate().unwrap();
        let raw = package
            .get_volume("pishoo-signature")
            .unwrap()
            .read_file("/signature.json")
            .unwrap()
            .0;
        let envelope: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let signature = STANDARD
            .decode(envelope["signature"].as_str().unwrap())
            .unwrap();
        let reader = webc::v3::read::OwnedReader::parse(bytes.clone()).unwrap();
        let index = reader.index();
        let mut digest = Sha256::new();
        digest.update(b"\0webc003");
        for entry in std::iter::once(&index.manifest)
            .chain(std::iter::once(&index.atoms))
            .chain(
                index
                    .volumes
                    .iter()
                    .filter(|(name, _)| name.as_str() != "pishoo-signature")
                    .map(|(_, entry)| entry),
            )
        {
            digest.update(&bytes[entry.span.start..entry.span.end()]);
        }
        let mut signed = b"pishoo-webc-signature-v1\0".to_vec();
        signed.extend_from_slice(&digest.finalize());
        let key = rcgen::KeyPair::from_pem(
            &std::fs::read_to_string(home.join("alice/ssl/privkey.pem")).unwrap(),
        )
        .unwrap();
        assert!(
            dhttp_home::certificate::verify_signature(
                &key.subject_public_key_info(),
                &signed,
                &signature
            )
            .unwrap()
        );
        if kind != "app" {
            let backend = package.get_atom("backend").unwrap();
            assert!(
                backend
                    .windows(b"pishoo:openapi".len())
                    .any(|value| value == b"pishoo:openapi")
            );
            assert!(package.get_volume("metadata").is_none());
        }
    }
}
