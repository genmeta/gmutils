//! Native source builds preserve argument boundaries, diagnostics and old packages.
#![cfg(unix)]
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

use serde_json::{Value, json};
#[path = "support/identity.rs"]
mod test_identity;

fn execute(root: &Path, home: &Path, bin: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_jade"))
        .current_dir(root)
        .env("DHTTP_HOME", home)
        .env("PATH", bin)
        .args(["--json", "build"])
        .output()
        .unwrap()
}
fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}
fn config(root: &Path, frontend: &str) {
    std::fs::write(root.join("jade.toml"),toml::to_string(&json!({
        "package":{"name":"hello","version":"1.0.0","author":"alice","description":"Test","license":"MIT"},
        "frontend":{"path":frontend}
    })).unwrap()).unwrap();
}

#[test]
fn npm_uses_literal_working_directory_and_failure_preserves_the_signed_output() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home/.dhttp");
    test_identity::create(&home);
    let bin = root.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let frontend = "web $(touch unexpected)";
    let web = root.path().join(frontend);
    std::fs::create_dir_all(web.join("dist")).unwrap();
    config(root.path(), frontend);
    std::fs::write(
        web.join("package.json"),
        r#"{"packageManager":"npm@10","scripts":{"build":"some existing tool"}}"#,
    )
    .unwrap();
    script(
        &bin.join("npm"),
        "printf '%s\\n' \"$@\" > received\nprintf 'tool stdout\\n'\nif [ -f fail ]; then exit 17; fi\nprintf '<h1>Built</h1>' > dist/index.html",
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
        "run\nbuild\n"
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
    assert_eq!(std::fs::read(file).unwrap(), before);
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
    config(root.path(), "public");
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
    config(root.path(), "web");
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
        "package":{"name":"hello","version":"1.0.0","author":"alice","description":"Test","license":"MIT"},
        "backend":{"path":"."}
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
    let container =
        webc::Container::from_bytes_and_version(before.clone().into(), webc::Version::V3).unwrap();
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
