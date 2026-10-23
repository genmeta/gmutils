//! Native source builds preserve argument boundaries, diagnostics and old packages.
#![cfg(unix)]
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

use serde_json::{Value, json};
#[allow(dead_code)]
#[path = "../src/archive.rs"]
mod archive;
#[path = "support/identity.rs"]
mod test_identity;

fn execute(root: &Path, home: &Path, bin: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_jade"))
        .current_dir(root)
        .env("DHTTP_HOME", home)
        .env("PATH", bin)
        .env_remove("WASI_SDK_PATH")
        .env_remove("CC_wasm32_wasip2")
        .env_remove("AR_wasm32_wasip2")
        .args(["--json", "build"])
        .output()
        .unwrap()
}
fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}
fn config(root: &Path) {
    std::fs::write(root.join("jade.toml"),toml::to_string(&json!({
        "package":{"name":"hello","version":"1.0.0","author":"alice","description":"Test","license":"MIT"}
    })).unwrap()).unwrap();
}

#[test]
fn npm_uses_literal_working_directory_and_failure_preserves_the_signed_output() {
    let root = tempfile::Builder::new()
        .prefix("jade $(touch unexpected) ")
        .tempdir()
        .unwrap();
    let home = root.path().join("home/.dhttp");
    test_identity::create(&home);
    let bin = root.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let web = root.path().join("web");
    std::fs::create_dir_all(web.join("dist")).unwrap();
    config(root.path());
    std::fs::write(
        web.join("package.json"),
        r#"{"packageManager":"npm@10","scripts":{"build":"some existing tool"}}"#,
    )
    .unwrap();
    script(
        &bin.join("npm"),
        r#"printf '%s\n' "$@" >> received
printf 'tool stdout\n'
case "$1" in
    install) if [ -f fail-install ]; then exit 18; fi;;
    run)
        if [ -f fail ]; then exit 17; fi
        printf '<h1>Built</h1>' > dist/index.html;;
    *) exit 99;;
esac"#,
    );
    for obsolete in ["pishoo", "pishoo-pack", "genmeta"] {
        script(&bin.join(obsolete), "touch invoked\nexit 99");
    }
    let built = execute(root.path(), &home, &bin);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let result: Value = serde_json::from_slice(&built.stdout).unwrap();
    assert_eq!(result["status"], "ok");
    assert!(String::from_utf8_lossy(&built.stderr).contains("tool stdout"));
    assert_eq!(
        std::fs::read_to_string(web.join("received")).unwrap(),
        "install\n--include=dev\nrun\nbuild\n"
    );
    assert!(!root.path().join("unexpected").exists());
    assert!(!root.path().join("invoked").exists());
    let file = Path::new(result["result"]["file"].as_str().unwrap());
    let before = std::fs::read(file).unwrap();
    std::fs::write(web.join("fail"), "").unwrap();
    let failed = execute(root.path(), &home, &bin);
    assert!(!failed.status.success());
    let result: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(result["error"]["code"], "E_BUILD_FAILED");
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("npm run build failed")
    );
    assert_eq!(std::fs::read(file).unwrap(), before);

    std::fs::remove_file(web.join("fail")).unwrap();
    std::fs::write(web.join("fail-install"), "").unwrap();
    std::fs::write(web.join("received"), "").unwrap();
    let failed = execute(root.path(), &home, &bin);
    assert!(!failed.status.success());
    let result: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(result["error"]["code"], "E_BUILD_FAILED");
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("npm install --include=dev failed")
    );
    assert_eq!(
        std::fs::read_to_string(web.join("received")).unwrap(),
        "install\n--include=dev\n"
    );
    assert_eq!(std::fs::read(file).unwrap(), before);
}

#[test]
fn created_web_projects_install_build_tools_before_building_with_each_manager() {
    for (manager, lock, install_args) in [
        ("npm", None, "install --include=dev"),
        ("pnpm", Some("pnpm-lock.yaml"), "install --prod=false"),
        ("bun", Some("bun.lock"), "install"),
        ("bun", Some("bun.lockb"), "install"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home/.dhttp");
        test_identity::create(&home);
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let created = Command::new(env!("CARGO_BIN_EXE_jade"))
            .current_dir(root.path())
            .args(["create", "hello", "--template", "web"])
            .output()
            .unwrap();
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        let app = root.path().join("hello");
        let web = app.join("web");
        assert!(!web.join("node_modules").exists());
        if let Some(lock) = lock {
            std::fs::write(web.join(lock), "").unwrap();
        }
        script(
            &bin.join(manager),
            &format!(
                r#"
printf '%s\n' "$*" >> received
case "$*" in
    '{install_args}')
        /bin/mkdir -p node_modules/.bin
        printf 'installed Vite' > node_modules/.bin/vite;;
    'run build')
        test -f node_modules/.bin/vite || exit 127
        /bin/mkdir -p dist
        printf '<h1>Built</h1>' > dist/index.html;;
    *) exit 99;;
esac
"#
            ),
        );
        // Rebuilding also synchronizes dependencies instead of trusting node_modules.
        for _ in 0..2 {
            let output = execute(&app, &home, &bin);
            assert!(
                output.status.success(),
                "{manager}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["status"], "ok");
            assert_eq!(
                std::fs::read_to_string(web.join("dist/index.html")).unwrap(),
                "<h1>Built</h1>"
            );
            let package = std::fs::metadata(app.join("build/hello-0.1.0.waz")).unwrap();
            assert!(package.len() > 0);
            assert_eq!(result["result"]["size"], package.len());
            std::fs::remove_file(web.join("node_modules/.bin/vite")).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(web.join("received")).unwrap(),
            format!("{install_args}\nrun build\n{install_args}\nrun build\n")
        );
    }
}

#[test]
fn a_package_json_without_a_build_script_is_still_a_static_project() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home/.dhttp");
    test_identity::create(&home);
    let bin = root.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    script(&bin.join("npm"), "touch invoked\nexit 99");
    let web = root.path().join("public");
    std::fs::create_dir(&web).unwrap();
    std::fs::write(web.join("index.html"), "<h1>Static</h1>").unwrap();
    std::fs::write(web.join("package.json"), r#"{"scripts":{"dev":"unused"}}"#).unwrap();
    config(root.path());
    let result = execute(root.path(), &home, &bin);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!web.join("invoked").exists());
}

#[test]
fn malformed_build_scripts_and_ambiguous_lockfiles_report_configuration_errors() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home/.dhttp");
    test_identity::create(&home);
    let web = root.path().join("web");
    std::fs::create_dir(&web).unwrap();
    config(root.path());
    std::fs::write(web.join("package.json"), r#"{"scripts":{"build":false}}"#).unwrap();
    let output = execute(root.path(), &home, root.path());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["error"]["code"], "E_CONFIG_INVALID");
    std::fs::write(web.join("package.json"), r#"{"scripts":{"build":"build"}}"#).unwrap();
    std::fs::write(web.join("package-lock.json"), "{}").unwrap();
    std::fs::write(web.join("pnpm-lock.yaml"), "").unwrap();
    let output = execute(root.path(), &home, root.path());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["error"]["code"], "E_CONFIG_INVALID");
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("lockfiles")
    );
}

#[test]
fn rust_source_embeds_existing_openapi_without_losing_schemas_or_failed_rebuilds() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let home = root.join("home/.dhttp");
    test_identity::create(&home);
    let bin = root.join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::write(root.join("jade.toml"), toml::to_string(&json!({
        "package":{"name":"hello","version":"1.0.0","author":"alice","description":"Test","license":"MIT"}
    })).unwrap()).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='hello'\nversion='1.0.0'\n",
    )
    .unwrap();
    std::fs::write(
        root.join("metadata.json"),
        serde_json::to_vec(&json!({"packages":[{
            "manifest_path":root.join("Cargo.toml"), "id":"hello",
            "dependencies":[{"name":"wasip2"}], "targets":[{"crate_types":["cdylib"]}]
        }]}))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("artifact.json"),
        serde_json::to_vec(&json!({
            "reason":"compiler-artifact","package_id":"hello","filenames":[root.join("raw.wasm")]
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("raw.wasm"),
        include_bytes!("fixtures/wasi-http-read-request-then-respond.wasm"),
    )
    .unwrap();
    script(
        &bin.join("cargo"),
        "case \"$1\" in metadata) /bin/cat metadata.json;; build) /bin/cat artifact.json;; *) exit 99;; esac",
    );
    let mut doc = json!({"openapi":"3.1.0","info":{"title":"Existing API","version":"1.0.0"},
        "paths":{"/upload":{"post":{"operationId":"upload","summary":"Upload",
            "responses":{"200":{"description":"Saved","content":{"application/json":{"schema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}}}}}}}});
    std::fs::write(root.join("openapi.json"), serde_json::to_vec(&doc).unwrap()).unwrap();
    let built = execute(&root, &home, &bin);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let result: Value = serde_json::from_slice(&built.stdout).unwrap();
    let file = Path::new(result["result"]["file"].as_str().unwrap());
    let before = std::fs::read(file).unwrap();
    let container = webc::Container::from_bytes_and_version(
        archive::waz_convert(&before).unwrap().into(),
        webc::Version::V3,
    )
    .unwrap();
    let atom = container.get_atom("backend").unwrap();
    let documents = wasmparser::Parser::new(0)
        .parse_all(&atom)
        .filter_map(|item| match item.unwrap() {
            wasmparser::Payload::CustomSection(section) if section.name() == "pishoo:openapi" => {
                Some(serde_json::from_slice::<Value>(section.data()).unwrap())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(documents, [doc.clone()]);
    doc["info"]["version"] = "2.0.0".into();
    std::fs::write(root.join("openapi.json"), serde_json::to_vec(&doc).unwrap()).unwrap();
    let failed = execute(&root, &home, &bin);
    assert!(!failed.status.success());
    let result: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(result["error"]["code"], "E_ARTIFACT_INVALID");
    assert_eq!(std::fs::read(file).unwrap(), before);
}

#[test]
fn cargo_failure_hints_follow_diagnostics_without_losing_logs() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let home = root.join("home/.dhttp");
    test_identity::create(&home);
    let bin = root.join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::write(root.join("jade.toml"), toml::to_string(&json!({
        "package":{"name":"hello","version":"1.0.0","author":"alice","description":"Test","license":"MIT"}
    })).unwrap()).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='hello'\nversion='1.0.0'\n",
    )
    .unwrap();
    std::fs::write(
        root.join("metadata.json"),
        serde_json::to_vec(&json!({"packages":[{
            "manifest_path":root.join("Cargo.toml"), "id":"hello",
            "dependencies":[{"name":"wasip2"}], "targets":[{"crate_types":["cdylib"]}]
        }]}))
        .unwrap(),
    )
    .unwrap();
    script(
        &bin.join("cargo"),
        "case \"$1\" in metadata) /bin/cat metadata.json;; build) /bin/cat diagnostics.stderr >&2; /bin/cat diagnostics.stdout; exit 1;; *) exit 99;; esac",
    );
    let wasi_header_error = format!(
        "sqlite3/sqlite3.c:14678:10: fatal error: 'stdio.h' file not found\n{}clang --target=wasm32-wasip2 -c sqlite3/sqlite3.c\n",
        "additional build output\n".repeat(8192)
    );
    for (name, rendered, stderr, expected) in [
        (
            "WASI standard header",
            None,
            wasi_header_error.as_str(),
            "WASI_SDK_PATH",
        ),
        (
            "WASI sysroot",
            None,
            "Environment variable WASI_SYSROOT not defined.\n",
            "WASI_SDK_PATH",
        ),
        (
            "WASI compiler",
            None,
            "TARGET = Some(wasm32-wasip2)\nerror occurred in cc-rs: failed to find tool \"clang\": No such file or directory\n",
            "WASI_SDK_PATH",
        ),
        (
            "Rust target",
            Some(
                "error[E0463]: can't find crate for `std`\n  = note: the `wasm32-wasip2` target may not be installed\n",
            ),
            "",
            "rustup target add wasm32-wasip2",
        ),
        (
            "Rust syntax",
            Some("error: expected `;`, found `}`\n"),
            "WASI_SDK_PATH = None\n",
            "Check the Cargo diagnostics",
        ),
        (
            "Dependency download",
            None,
            "error: failed to get `pishoo-sdk` as a dependency\nfailed to connect to github.com\n",
            "Check the Cargo diagnostics",
        ),
        (
            "Project header",
            None,
            "fatal error: 'application.h' file not found\nclang --target=wasm32-wasip2\n",
            "Check the Cargo diagnostics",
        ),
        (
            "Host C header",
            None,
            "fatal error: 'stdio.h' file not found\nclang --target=arm64-apple-darwin\n",
            "Check the Cargo diagnostics",
        ),
        (
            "Ordinary linker error",
            None,
            "wasm-ld: error: undefined symbol: application_function\n--target=wasm32-wasip2\n",
            "Check the Cargo diagnostics",
        ),
    ] {
        let stdout = rendered
            .map(|rendered| {
                json!({
                    "reason":"compiler-message", "message":{"rendered":rendered}
                })
                .to_string()
                    + "\n"
            })
            .unwrap_or_default();
        std::fs::write(root.join("diagnostics.stdout"), stdout).unwrap();
        std::fs::write(root.join("diagnostics.stderr"), stderr).unwrap();
        let output = execute(&root, &home, &bin);
        assert_eq!(output.status.code(), Some(1), "{name}");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["error"]["code"], "E_BUILD_FAILED", "{name}");
        let hint = result["error"]["hint"].as_str().unwrap();
        assert!(hint.contains(expected), "{name}: {hint}");
        assert_eq!(
            hint.contains("WASI_SDK_PATH"),
            expected == "WASI_SDK_PATH",
            "{name}: {hint}"
        );
        assert_eq!(
            hint.contains("rustup target add"),
            expected.starts_with("rustup"),
            "{name}: {hint}"
        );
        let logs = String::from_utf8(output.stderr).unwrap();
        assert!(logs.contains(stderr), "{name}: stderr was not preserved");
        assert!(
            logs.contains(rendered.unwrap_or_default()),
            "{name}: rendered diagnostic was not preserved"
        );
        assert!(
            logs.contains(hint),
            "{name}: terminal and JSON hints differ"
        );
    }
}
