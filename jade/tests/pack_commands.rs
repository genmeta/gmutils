//! Offline build/sign executables with generated credentials in isolated homes.
use std::{
    ffi::OsStr,
    path::Path,
    process::{Command, Output},
};

use serde_json::json;

#[path = "support/identity.rs"]
mod test_identity;
use test_identity::create as identity;
#[allow(dead_code)]
#[path = "../src/archive.rs"]
mod archive;

fn package(bytes: Vec<u8>) -> webc::Container {
    assert!(bytes.starts_with(b"PK\x03\x04"));
    webc::Container::from_bytes_and_version(
        archive::waz_convert(&bytes).unwrap().into(),
        webc::Version::V3,
    )
    .unwrap()
}

fn project(path: &Path, kind: &str, repository: &str) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::write(path.join("jade.toml"),format!("dependencies=[]\n[package]\nname='hello'\nauthor='alice.dhttp.net'\nversion='1.0.0'\ndescription='Test package'\nlicense='MIT'\ntitle='Hello'\nrelease-notes='Initial release'\n{repository}\n")).unwrap();
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_jade"));
    #[cfg(windows)]
    command.env("USERPROFILE", home.parent().unwrap());
    command
        .env("HOME", home.parent().unwrap())
        .env("DHTTP_HOME", home)
        .current_dir(cwd)
        .args(["--json", "build"])
        .args(args)
        .output()
        .unwrap()
}
fn fails(output: &Output, error: &str) {
    assert!(!output.status.success());
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON failure document");
    assert_eq!(result["status"], "error");
    assert!(result["error"]["code"].as_str().unwrap().starts_with("E_"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(error),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn jade_create_static_scaffolds_a_package_that_builds_with_local_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home/.dhttp");
    let create = || {
        Command::new(env!("CARGO_BIN_EXE_jade"))
            .current_dir(dir.path())
            .args(["--json", "create", "hello", "--template", "static"])
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
    assert_eq!(summary["result"]["name"], "hello");
    let app = dir.path().join("hello");
    let manifest = std::fs::read_to_string(app.join("jade.toml")).unwrap();
    let config: toml::Value = toml::from_str(&manifest).unwrap();
    assert_eq!(config["package"]["name"].as_str(), Some("hello"));
    assert!(config.get("frontend").is_none());
    assert!(config.get("backend").is_none());
    assert!(app.join("public/index.html").is_file());
    assert_eq!(
        std::fs::read_to_string(app.join(".gitignore")).unwrap(),
        "/build/\n"
    );
    fails(&create(), "use a new path");
    assert_eq!(
        std::fs::read_to_string(app.join("jade.toml")).unwrap(),
        manifest
    );

    identity(&home);
    let built = pack(&home, &app, &[]);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let file = app.join("build/hello-0.1.0.waz");
    let package = package(std::fs::read(file).unwrap());
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
fn jade_create_rejects_invalid_names_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    for (name, error) in [
        ("Hello", "Package name"),
        ("bad name", "Package name"),
        ("https://example.com/hello", "local filesystem"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_jade"))
            .current_dir(dir.path())
            .args(["--json", "create", name])
            .output()
            .unwrap();
        fails(&output, error);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_jade"))
        .current_dir(dir.path())
        .args([
            "--json",
            "create",
            "directory with spaces",
            "--name",
            "hello",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join("directory with spaces/jade.toml").is_file());
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
        "differs from package.author",
    );
    fails(&pack(&home, &app, &[]), "credentials");
    assert!(!app.join("build").exists());
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
        assert!(!app.join("build").exists());
    }
}

#[test]
fn invalid_declarations_and_missing_artifacts_do_not_publish() {
    for (kind, from, to, error) in [
        (
            "app",
            "dependencies=[]",
            "dependencies=[{author='alice.dhttp.net',name='hello',version='01.0.0'}]",
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
            "title='Hello'",
            "title='Hello'\nkind='app'",
            "unknown field",
        ),
        (
            "app",
            "dependencies=[]",
            "[frontend]\npath='public'",
            "unknown field",
        ),
        (
            "lib",
            "dependencies=[]",
            "dependencies=[{author='alice.dhttp.net',name='hello',version='1.0.0'}]",
            "dependency",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("project");
        project(&app, kind, "");
        let manifest = app.join("jade.toml");
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
        assert!(!app.join("build").exists());
    }
    for (kind, missing) in [("app", "public/index.html"), ("lib", "lib.wasm")] {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("project");
        project(&app, kind, "");
        identity(&dir.path().join("empty-home/.dhttp"));
        std::fs::remove_file(app.join(missing)).unwrap();
        fails(
            &pack(&dir.path().join("empty-home/.dhttp"), &app, &[]),
            "No frontend or backend found",
        );
        assert!(!app.join("build").exists());
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
        "Output already exists",
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
        assert!(!app.join("build").exists());
    }
    let large = app.join("public/large.bin");
    std::fs::File::create(&large)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    fails(&pack(&home, &app, &[]), "size limit");
    assert!(!app.join("build").exists());
}

#[cfg(unix)]
#[test]
fn backend_fifo_is_rejected_without_waiting_for_a_writer() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    project(&lib, "lib", "");
    identity(&dir.path().join("empty-home/.dhttp"));
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
    assert!(!lib.join("build").exists());
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
        let envelope: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        let summary = &envelope["result"];
        assert_eq!(summary["id"], "alice.dhttp.net/hello");
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
        let package = package(bytes.clone());
        package.validate().unwrap();
        let manifest = serde_json::to_value(package.manifest()).unwrap();
        assert!(manifest["package"]["pishoo"].get("host").is_none());
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
        use std::io::Read;
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).unwrap();
        let mut paths = archive.file_names().map(str::to_owned).collect::<Vec<_>>();
        paths.sort();
        let mut digest = Sha256::new();
        digest.update(b"pishoo-waz-payload-v1\0");
        for path in paths
            .iter()
            .filter(|path| path.as_str() != "signature.json")
        {
            let mut content = Vec::new();
            archive
                .by_name(path)
                .unwrap()
                .read_to_end(&mut content)
                .unwrap();
            digest.update((path.len() as u32).to_le_bytes());
            digest.update(path.as_bytes());
            digest.update((content.len() as u64).to_le_bytes());
            digest.update(Sha256::digest(&content));
        }
        let mut signed = b"pishoo-waz-signature-v1\0".to_vec();
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

#[test]
fn optional_project_documents_are_signed_for_frontend_backend_and_combined_packages() {
    for kind in ["app", "lib", "both"] {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home/.dhttp");
        identity(&home);
        let app = dir.path().join(kind);
        project(&app, kind, "");
        let mut previous = None;
        for names in [
            vec![],
            vec!["README.md"],
            vec!["CHANGELOG.md"],
            vec!["README.md", "CHANGELOG.md"],
        ] {
            for name in ["README.md", "CHANGELOG.md"] {
                if names.contains(&name) {
                    std::fs::write(app.join(name), format!("# {name}\nPackage documentation\n"))
                        .unwrap();
                } else if app.join(name).exists() {
                    std::fs::remove_file(app.join(name)).unwrap();
                }
            }
            let built = pack(&home, &app, &[]);
            assert!(
                built.status.success(),
                "{}",
                String::from_utf8_lossy(&built.stderr)
            );
            let result: serde_json::Value = serde_json::from_slice(&built.stdout).unwrap();
            let digest = result["result"]["payload_sha256"].clone();
            if let Some(previous) = previous.replace(digest.clone()) {
                assert_ne!(
                    digest, previous,
                    "document changes must change the signed payload"
                );
            }
            let bytes = std::fs::read(app.join("build/hello-1.0.0.waz")).unwrap();
            let package = package(bytes);
            package.validate().unwrap();
            assert_eq!(package.get_atom("backend").is_some(), kind != "app");
            assert_eq!(package.get_volume("public").is_some(), kind != "lib");
            let documents = package.get_volume("metadata");
            assert_eq!(documents.is_some(), !names.is_empty());
            if let Some(documents) = documents {
                assert_eq!(documents.read_dir("/").unwrap().len(), names.len());
                for name in &names {
                    assert_eq!(
                        documents.read_file(format!("/{name}")).unwrap().0.as_ref(),
                        std::fs::read(app.join(name)).unwrap()
                    );
                }
            }
            let manifest = serde_json::to_value(package.manifest()).unwrap();
            assert_eq!(
                manifest["package"]["wapm"].get("readme").is_some(),
                names.contains(&"README.md")
            );
            assert!(
                package
                    .manifest()
                    .filesystem()
                    .unwrap()
                    .unwrap_or_default()
                    .iter()
                    .all(|mapping| mapping.volume_name == "public")
            );
        }
    }
}

#[test]
fn invalid_project_documents_preserve_the_existing_package() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home/.dhttp");
    identity(&home);
    let app = dir.path().join("app");
    project(&app, "app", "");
    let document = app.join("README.md");
    std::fs::write(&document, "# Readme").unwrap();
    let built = pack(&home, &app, &[]);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let output = app.join("build/hello-1.0.0.waz");
    let before = std::fs::read(&output).unwrap();
    std::fs::remove_file(&document).unwrap();
    std::fs::create_dir(&document).unwrap();
    fails(&pack(&home, &app, &[]), "regular files");
    assert_eq!(std::fs::read(&output).unwrap(), before);
    std::fs::remove_dir(&document).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(app.join("public/index.html"), &document).unwrap();
        fails(&pack(&home, &app, &[]), "regular files");
        assert_eq!(std::fs::read(&output).unwrap(), before);
        std::fs::remove_file(&document).unwrap();
    }
    std::fs::File::create(&document)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    fails(&pack(&home, &app, &[]), "size limit");
    assert_eq!(std::fs::read(output).unwrap(), before);
}

#[test]
fn repeated_builds_are_atomic_and_root_static_projects_exclude_build_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home/.dhttp");
    identity(&home);
    let app = dir.path().join("app");
    project(&app, "app", "");
    std::fs::remove_dir_all(app.join("public")).unwrap();
    std::fs::write(app.join("index.html"), "<h1>First</h1>").unwrap();
    std::fs::write(app.join("README.md"), "# Root project").unwrap();
    std::fs::create_dir_all(app.join("build/target")).unwrap();
    std::fs::write(app.join("build/target/not-a-resource"), "excluded").unwrap();
    std::fs::create_dir_all(app.join(".jade/target")).unwrap();
    std::fs::write(app.join(".jade/target/legacy-artifact"), "excluded").unwrap();
    let first = pack(&home, &app, &[]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let file = app.join("build/hello-1.0.0.waz");
    let second = pack(&home, &app, &[]);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(
        first["result"]["payload_sha256"],
        second["result"]["payload_sha256"]
    );
    let container = package(std::fs::read(&file).unwrap());
    assert!(
        container
            .get_volume("public")
            .unwrap()
            .read_file("/README.md")
            .is_none()
    );
    assert_eq!(
        container
            .get_volume("metadata")
            .unwrap()
            .read_file("/README.md")
            .unwrap()
            .0
            .as_ref(),
        b"# Root project"
    );
    assert!(
        container
            .get_volume("public")
            .unwrap()
            .read_dir("/build")
            .is_none()
    );
    assert!(
        container
            .get_volume("public")
            .unwrap()
            .read_dir("/.jade")
            .is_none()
    );
    std::fs::write(app.join("index.html"), "<h1>Changed</h1>").unwrap();
    let changed = pack(&home, &app, &[]);
    assert!(
        changed.status.success(),
        "{}",
        String::from_utf8_lossy(&changed.stderr)
    );
    let changed: serde_json::Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_ne!(
        first["result"]["payload_sha256"],
        changed["result"]["payload_sha256"]
    );
    let previous = std::fs::read(&file).unwrap();
    std::fs::write(app.join("invalid%file"), "bad").unwrap();
    assert!(!pack(&home, &app, &[]).status.success());
    assert_eq!(std::fs::read(&file).unwrap(), previous);
}

#[test]
fn explicit_overwrite_and_noninteractive_identity_selection_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home/.dhttp");
    identity(&home);
    let app = dir.path().join("app");
    project(&app, "app", "");
    let manifest = app.join("jade.toml");
    std::fs::write(
        &manifest,
        std::fs::read_to_string(&manifest)
            .unwrap()
            .replace("author='alice.dhttp.net'\n", ""),
    )
    .unwrap();
    // A single usable local identity is sufficient, with no Jade preferences.
    let first = pack(&home, &app, &[]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(!app.join("build/local.toml").exists());
    let file = dir.path().join("explicit.waz");
    std::fs::write(&file, "old").unwrap();
    fails(
        &pack(&home, &app, &["-o".as_ref(), file.as_os_str()]),
        "Output already exists",
    );
    let overwrite = pack(
        &home,
        &app,
        &["-o".as_ref(), file.as_os_str(), "--overwrite".as_ref()],
    );
    assert!(
        overwrite.status.success(),
        "{}",
        String::from_utf8_lossy(&overwrite.stderr)
    );
    assert!(std::fs::read(&file).unwrap().starts_with(b"PK\x03\x04"));
    let default = app.join("build/hello-1.0.0.waz");
    std::fs::write(&default, "unrelated").unwrap();
    let rejected = pack(&home, &app, &[]);
    assert!(!rejected.status.success());
    assert_eq!(std::fs::read(&default).unwrap(), b"unrelated");
}

#[test]
fn json_parameter_errors_are_one_document_with_usage_exit_code() {
    for args in [
        vec!["--json", "build", "--no-build"],
        vec!["create", "--json"],
        vec!["--json", "unknown-command"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_jade"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"]["code"], "E_USAGE");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_jade"))
        .args(["--json", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
}

#[test]
#[ignore = "requires Node.js, npm and registry access for the Vite template dependencies"]
fn web_template_builds_without_manual_dependency_installation() {
    frontend_template_builds(Some("web"));
}

#[test]
#[ignore = "requires Node.js, npm, registry access and a Rust toolchain with wasm32-wasip2"]
fn default_fullstack_template_builds_without_manual_dependency_installation() {
    frontend_template_builds(None);
}

fn frontend_template_builds(template: Option<&str>) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let home = root.join("home/.dhttp");
    identity(&home);
    let app = root.join("frontend");
    let mut create = Command::new(env!("CARGO_BIN_EXE_jade"));
    create.arg("create").arg(&app);
    if let Some(template) = template {
        create.args(["--template", template]);
    }
    let created = create.output().unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(!app.join("web/node_modules").exists());

    let mut build = Command::new(env!("CARGO_BIN_EXE_jade"));
    build
        .current_dir(&app)
        .env("DHTTP_HOME", &home)
        .env("NODE_ENV", "production")
        .env("npm_config_omit", "dev")
        .env("npm_config_cache", root.join("npm-cache"))
        .args(["--json", "build", "--id", "alice"]);
    if let Some(toolchain) = std::env::var_os("JADE_TEST_RUST_TOOLCHAIN") {
        build.env("RUSTUP_TOOLCHAIN", toolchain);
    }
    let built = build.output().unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&built.stdout).unwrap();
    assert_eq!(result["status"], "ok");
    assert!(app.join("web/node_modules/vite/package.json").is_file());
    assert!(app.join("web/package-lock.json").is_file());
    assert!(app.join("web/dist/index.html").is_file());
    let package = std::fs::metadata(app.join("build/frontend-0.1.0.waz")).unwrap();
    assert!(package.len() > 0);
    assert_eq!(result["result"]["size"], package.len());
    if template.is_none() {
        assert!(
            app.join("build/target/wasm32-wasip2/release/frontend.wasm")
                .is_file()
        );
    }
}

#[test]
#[ignore = "requires a Rust toolchain with wasm32-wasip2 and template dependencies"]
fn rust_api_template_builds_without_developer_build_scripts() {
    let directory = tempfile::tempdir().unwrap();
    let root = std::env::var_os("JADE_TEST_PROJECT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| directory.path().to_owned());
    std::fs::create_dir_all(&root).unwrap();
    let home = root.join("home/.dhttp");
    identity(&home);
    let app = root.join("rust-api");
    let created = Command::new(env!("CARGO_BIN_EXE_jade"))
        .args(["--json", "create"])
        .arg(&app)
        .args(["--template", "api"])
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(!app.join("api/build.rs").exists());
    assert!(!app.join("api/build.sh").exists());
    assert!(!app.join("api/src/sdk.rs").exists());
    let build = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_jade"));
        command
            .current_dir(&app)
            .env("DHTTP_HOME", &home)
            .args(["--json", "build", "--id", "alice"]);
        if let Some(toolchain) = std::env::var_os("JADE_TEST_RUST_TOOLCHAIN") {
            command.env("RUSTUP_TOOLCHAIN", toolchain);
        }
        command.output().unwrap()
    };
    let built = build();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let first: serde_json::Value = serde_json::from_slice(&built.stdout).unwrap();
    let file = Path::new(first["result"]["file"].as_str().unwrap());
    assert_eq!(
        file,
        app.canonicalize().unwrap().join("build/rust-api-0.1.0.waz")
    );
    assert!(
        app.join("build/target/wasm32-wasip2/release/rust_api.wasm")
            .is_file()
    );
    let package = package(std::fs::read(file).unwrap());
    package.validate().unwrap();
    let backend = package.get_atom("backend").unwrap();
    let doc = wasmparser::Parser::new(0)
        .parse_all(&backend)
        .filter_map(|item| match item.unwrap() {
            wasmparser::Payload::CustomSection(section) if section.name() == "pishoo:openapi" => {
                Some(serde_json::from_slice::<serde_json::Value>(section.data()).unwrap())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(doc.len(), 1);
    assert!(doc[0]["paths"]["/hello"]["get"].is_object());
    assert_eq!(doc[0]["paths"].as_object().unwrap().len(), 1);
    let source = app.join("api/src/lib.rs");
    std::fs::write(
        &source,
        std::fs::read_to_string(&source)
            .unwrap()
            .replace("Hello from Rust", "Updated business handler"),
    )
    .unwrap();
    let rebuilt = build();
    assert!(
        rebuilt.status.success(),
        "{}",
        String::from_utf8_lossy(&rebuilt.stderr)
    );
    let second: serde_json::Value = serde_json::from_slice(&rebuilt.stdout).unwrap();
    assert_ne!(
        first["result"]["payload_sha256"],
        second["result"]["payload_sha256"]
    );
    eprintln!("Rust API acceptance package: {}", file.display());
}

#[test]
fn multiple_identities_require_selection_and_use_the_existing_dhttp_default() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home/.dhttp");
    identity(&home);
    test_identity::create_named(&home, "bob.dhttp.net");
    let app = root.path().join("app");
    project(&app, "app", "");
    let manifest = app.join("jade.toml");
    std::fs::write(
        &manifest,
        std::fs::read_to_string(&manifest)
            .unwrap()
            .replace("author='alice.dhttp.net'\n", ""),
    )
    .unwrap();
    let missing = pack(&home, &app, &[]);
    let result: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(result["error"]["code"], "E_IDENTITY_REQUIRED");
    std::fs::write(
        home.join("settings.toml"),
        "[default]\nname='bob.dhttp.net'\n",
    )
    .unwrap();
    let selected = pack(&home, &app, &[]);
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&selected.stdout).unwrap();
    assert_eq!(result["result"]["id"], "bob.dhttp.net/hello");
    assert!(!app.join("build/local.toml").exists());
}

#[test]
fn wasm_commands_and_wrong_keys_fail_before_writing_a_package() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home/.dhttp");
    identity(&home);
    let app = root.path().join("app");
    project(&app, "lib", "");
    // A syntactically valid empty component still lacks the required HTTP world.
    let mut component = b"\0asm\x0d\0\x01\0".to_vec();
    let data = br#"{"openapi":"3.1.0","info":{"title":"Test","version":"1.0.0"},"paths":{}}"#;
    let mut section = vec![b"pishoo:openapi".len() as u8];
    section.extend_from_slice(b"pishoo:openapi");
    section.extend_from_slice(data);
    component.push(0);
    let mut size = section.len();
    while size >= 128 {
        component.push((size as u8 & 127) | 128);
        size >>= 7;
    }
    component.push(size as u8);
    component.extend(section);
    std::fs::write(app.join("lib.wasm"), component).unwrap();
    let output = pack(&home, &app, &[]);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["error"]["code"], "E_ARTIFACT_INVALID");
    assert!(!app.join("build/hello-1.0.0.waz").exists());
    let other = root.path().join("other/.dhttp");
    identity(&other);
    let key = home.join("alice/ssl/privkey.pem");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::copy(other.join("alice/ssl/privkey.pem"), &key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).unwrap();
    }
    let output = pack(&home, &app, &[]);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["error"]["code"], "E_IDENTITY_UNAVAILABLE");
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not match")
    );
}

#[test]
fn concurrent_default_builds_publish_complete_packages() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home/.dhttp");
    identity(&home);
    let app = root.path().join("app");
    project(&app, "app", "");
    let spawn = || {
        Command::new(env!("CARGO_BIN_EXE_jade"))
            .current_dir(&app)
            .env("DHTTP_HOME", &home)
            .args(["--json", "build"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = spawn();
    let second = spawn();
    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(
        first["result"]["payload_sha256"],
        second["result"]["payload_sha256"]
    );
    let bytes = std::fs::read(app.join("build/hello-1.0.0.waz")).unwrap();
    package(bytes.clone()).validate().unwrap();
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(bytes));
    assert!(
        first["result"]["package_sha256"] == hash || second["result"]["package_sha256"] == hash
    );
}

#[test]
fn malformed_commands_do_not_infer_a_command_from_later_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_jade"))
        .env("CLICOLOR_FORCE", "1")
        .args(["--json", "unknown-command", "build"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["command"].is_null());
    assert!(
        !value["error"]["message"]
            .as_str()
            .unwrap()
            .contains('\u{1b}')
    );
}
