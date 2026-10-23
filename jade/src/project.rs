//! Jade configuration and native source builds. No per-project build scripts.
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    process::Stdio,
};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

use crate::error::{Error, Result};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub package: Package,
    pub frontend: Option<Frontend>,
    pub backend: Option<Backend>,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Package {
    pub name: String,
    pub version: String,
    pub description: String,
    pub license: String,
    pub author: Option<String>,
    pub title: Option<String>,
    pub release_notes: Option<String>,
    pub repository: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frontend {
    pub path: PathBuf,
    pub output: Option<PathBuf>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Backend {
    pub path: PathBuf,
    #[serde(default)]
    pub host: BTreeMap<String, String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Dependency {
    author: String,
    name: String,
    version: String,
}

pub(crate) fn read(path: &Path) -> Result<(PathBuf, Manifest)> {
    crate::pack::reject_url(path.as_os_str()).map_err(|e| Error::new("E_CONFIG_INVALID", e))?;
    let path = if path.is_dir() {
        path.join("jade.toml")
    } else {
        path.to_owned()
    };
    let source = crate::pack::read_bounded(&path, 1024 * 1024)
        .map_err(|e| Error::new("E_CONFIG_INVALID", e).context(json!({"file":path})))?;
    let source = std::str::from_utf8(&source).map_err(|e| Error::new("E_CONFIG_INVALID", e))?;
    let manifest: Manifest = toml::from_str(source).map_err(|e: toml::de::Error| {
        let mut context = json!({"file":path});
        if let Some(span) = e.span() {
            let prefix = &source[..span.start.min(source.len())];
            context["line"] = (prefix.bytes().filter(|c| *c == b'\n').count() + 1).into();
            context["column"] = (prefix
                .rsplit('\n')
                .next()
                .unwrap_or_default()
                .chars()
                .count()
                + 1)
            .into();
        }
        Error::new("E_CONFIG_INVALID", format!("{}: {e}", path.display())).context(context)
    })?;
    if manifest.frontend.is_none() && manifest.backend.is_none() {
        return Err(
            Error::new("E_CONFIG_INVALID", "Declare frontend or backend")
                .context(json!({"file":path})),
        );
    }
    let author = manifest
        .package
        .author
        .as_deref()
        .unwrap_or("jade-validation.dhttp.net");
    let (wapm, annotation) = manifest.metadata(&crate::identity::normalize(author)?)?;
    crate::pack::validate_metadata(&wapm, &annotation)
        .map_err(|e| Error::new("E_CONFIG_INVALID", e).context(json!({"file":path})))?;
    let path = std::fs::canonicalize(&path)?;
    Ok((path.parent().unwrap().to_path_buf(), manifest))
}

impl Manifest {
    pub(crate) fn metadata(&self, author: &str) -> Result<(Value, Value)> {
        let package = &self.package;
        let mut wapm = json!({"name":format!("{author}/{}",package.name),"version":package.version,
            "description":package.description,"license":package.license});
        if let Some(repository) = &package.repository {
            wapm["repository"] = repository.clone().into();
        }
        let dependencies = self.dependencies.iter().map(|dep| Ok(json!({
            "publisher":crate::identity::normalize(&dep.author)?,"name":dep.name,"version":dep.version
        }))).collect::<Result<Vec<_>>>()?;
        let mut annotation = json!({"title":package.title.as_ref().unwrap_or(&package.name),
            "changelog":package.release_notes.clone().unwrap_or_else(||format!("Release {}",package.version)),
            "dependencies":dependencies});
        if self.frontend.is_some() {
            annotation["entry"] = "/".into();
        }
        if let Some(backend) = &self.backend {
            annotation["host"] = json!(backend.host);
        }
        Ok((wapm, annotation))
    }
}

pub(crate) fn local_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let path = path
        .to_str()
        .ok_or_else(|| Error::new("E_CONFIG_INVALID", "Artifact path must be UTF-8"))?;
    crate::pack::local_content_path(root, path).map_err(|e| Error::new("E_ARTIFACT_INVALID", e))
}

pub(crate) async fn frontend(root: &Path, config: &Frontend) -> Result<PathBuf> {
    let path = local_path(root, &config.path)?;
    if !path.is_dir() {
        return Err(Error::new(
            "E_ARTIFACT_INVALID",
            "frontend.path must be a directory",
        ));
    }
    let package_path = path.join("package.json");
    let package = if package_path.exists() {
        let bytes = crate::pack::read_bounded(&package_path, 1024 * 1024)
            .map_err(|e| Error::new("E_CONFIG_INVALID", e))?;
        Some(serde_json::from_slice::<Value>(&bytes).map_err(|e| {
            Error::new(
                "E_CONFIG_INVALID",
                format!("{}: {e}", package_path.display()),
            )
        })?)
    } else {
        None
    };
    let script = package.as_ref().and_then(|p| p.get("scripts"));
    if script.is_some_and(|s| !s.is_object()) {
        return Err(Error::new(
            "E_CONFIG_INVALID",
            "package.json scripts must be an object",
        ));
    }
    let build = script.and_then(|s| s.get("build"));
    let directory = if let Some(build) = build {
        if build.as_str().is_none_or(|s| s.trim().is_empty()) {
            return Err(Error::new(
                "E_CONFIG_INVALID",
                "package.json scripts.build must be a nonempty string",
            ));
        }
        let manager = node_manager(&path, package.as_ref().unwrap())?;
        eprintln!("  Building  frontend ({manager} run build)");
        run(manager, &["run", "build"], &path).await?;
        let output = config.output.as_deref().unwrap_or(Path::new("dist"));
        local_path(root, &path.join(output))?
    } else {
        if config.output.is_some() {
            return Err(Error::new(
                "E_CONFIG_INVALID",
                "frontend.output requires a package.json build script",
            )
            .hint("For static files, point frontend.path directly at the resource directory"));
        }
        path
    };
    if !directory.is_dir() || !directory.join("index.html").is_file() {
        return Err(Error::new(
            "E_ARTIFACT_INVALID",
            format!(
                "Frontend output requires index.html: {}",
                directory.display()
            ),
        ));
    }
    Ok(directory)
}

fn node_manager<'a>(path: &Path, package: &'a Value) -> Result<&'a str> {
    let explicit = match package.get("packageManager") {
        Some(value) => {
            let value = value
                .as_str()
                .ok_or_else(|| Error::new("E_CONFIG_INVALID", "packageManager must be a string"))?;
            let manager = value.split('@').next().unwrap_or_default();
            if !matches!(manager, "npm" | "pnpm" | "bun") {
                return Err(Error::new(
                    "E_TOOLCHAIN_UNAVAILABLE",
                    format!("Unsupported package manager: {manager}"),
                ));
            }
            Some(manager)
        }
        None => None,
    };
    let npm = path.join("package-lock.json").exists() || path.join("npm-shrinkwrap.json").exists();
    let pnpm = path.join("pnpm-lock.yaml").exists();
    let bun = path.join("bun.lock").exists() || path.join("bun.lockb").exists();
    if let Some(manager) = explicit {
        return Ok(manager);
    }
    match (npm, pnpm, bun) {
        (true, true, _) | (true, _, true) | (_, true, true) => Err(Error::new(
            "E_CONFIG_INVALID",
            "Multiple package-manager lockfiles",
        )
        .hint("Set packageManager in package.json")),
        (false, true, false) => Ok("pnpm"),
        (false, false, true) => Ok("bun"),
        _ if path.join("yarn.lock").exists() => Err(Error::new(
            "E_TOOLCHAIN_UNAVAILABLE",
            "This frontend uses an unsupported package manager",
        )),
        _ => Ok("npm"),
    }
}

async fn run(program: &str, args: &[&str], directory: &Path) -> Result<()> {
    #[cfg(windows)]
    let executable = std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|path| path.join(format!("{program}.cmd")))
                .find(|path| path.is_file())
        })
        .unwrap_or_else(|| PathBuf::from(program));
    #[cfg(not(windows))]
    let executable = program;
    let status = tokio::process::Command::new(executable)
        .args(args)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::io::stderr()))
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .status()
        .await
        .map_err(|e| {
            Error::new(
                "E_TOOLCHAIN_UNAVAILABLE",
                format!("Cannot run {program}: {e}"),
            )
        })?;
    if !status.success() {
        return Err(Error::new(
            "E_BUILD_FAILED",
            format!("{program} build failed ({status})"),
        ));
    }
    Ok(())
}

pub(crate) async fn backend(root: &Path, config: &Backend, package: &Package) -> Result<Vec<u8>> {
    let path = local_path(root, &config.path)?;
    let source = path.is_dir();
    let file = if source {
        cargo_build(root, &path).await?
    } else {
        path.clone()
    };
    let mut bytes = crate::pack::read_bounded(&file, crate::package::PACKAGE_LIMIT)
        .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
    if source {
        let routes = sdk_routes(&bytes)?;
        let api_file = path.join("openapi.json");
        let document = match (routes, api_file.try_exists()?) {
            (Some(_), true) => {
                return Err(Error::new(
                    "E_CONFIG_INVALID",
                    "Choose one OpenAPI source: SDK routes or openapi.json",
                ));
            }
            (Some(routes), false) => Some(openapi(&routes, package)?),
            (None, true) => {
                let api_file = local_path(root, &api_file)?;
                Some(
                    crate::pack::read_bounded(&api_file, 1024 * 1024)
                        .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?,
                )
            }
            (None, false) => None,
        };
        if let Some(document) = document {
            bytes = crate::pack::embedded_openapi(bytes, Some(&document))
                .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
        }
    }
    Ok(bytes)
}

async fn cargo_build(root: &Path, path: &Path) -> Result<PathBuf> {
    let manifest = local_path(root, &path.join("Cargo.toml"))?;
    eprintln!("  Building  Rust HTTP API (wasm32-wasip2)");
    let mut command = tokio::process::Command::new("cargo");
    command
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(&manifest)
        .current_dir(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|e| Error::new("E_TOOLCHAIN_UNAVAILABLE", format!("Cannot run cargo: {e}")))?;
    let mut metadata = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut metadata)
        .await?;
    if metadata.len() > 4 * 1024 * 1024 {
        return Err(Error::new("E_BUILD_FAILED", "Cargo metadata exceeds 4 MiB"));
    }
    if !child.wait().await?.success() {
        return Err(Error::new("E_BUILD_FAILED", "Cargo metadata failed"));
    }
    let metadata: Value =
        serde_json::from_slice(&metadata).map_err(|e| Error::new("E_BUILD_FAILED", e))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| Error::new("E_BUILD_FAILED", "Cargo did not return packages"))?;
    let package = packages
        .iter()
        .find(|p| {
            p["manifest_path"]
                .as_str()
                .is_some_and(|p| Path::new(p) == manifest)
        })
        .ok_or_else(|| {
            Error::new(
                "E_CONFIG_INVALID",
                "backend.path must select one Rust package",
            )
        })?;
    let id = package["id"].as_str().unwrap_or_default();
    let has_sdk = package["dependencies"]
        .as_array()
        .is_some_and(|deps| deps.iter().any(|d| d["name"] == "wasip2"));
    let cdylibs = package["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| {
            t["crate_types"]
                .as_array()
                .is_some_and(|k| k.iter().any(|v| v == "cdylib"))
        })
        .count();
    if !has_sdk || cdylibs != 1 {
        return Err(Error::new(
            "E_CONFIG_INVALID",
            "Rust backend requires one cdylib and WASI HTTP bindings",
        )
        .hint("Start with jade create PATH --template api, or provide a prebuilt Component"));
    }
    let target_dir = root.join(".jade/target");
    crate::pack::resolved_output(&target_dir).map_err(|e| Error::new("E_OUTPUT_CONFLICT", e))?;
    let mut command = tokio::process::Command::new("cargo");
    command
        .args([
            "build",
            "--release",
            "--lib",
            "--target",
            "wasm32-wasip2",
            "--message-format=json-render-diagnostics",
            "--manifest-path",
        ])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target_dir)
        .current_dir(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    // Native C dependencies use the same installed WASI toolchain as Cargo.
    // Application-specific flags stay in the application's Cargo configuration.
    if let Some(sdk) = std::env::var_os("WASI_SDK_PATH") {
        let sdk = PathBuf::from(sdk);
        for (key, tool) in [
            ("CC_wasm32_wasip2", "clang"),
            ("AR_wasm32_wasip2", "llvm-ar"),
        ] {
            if std::env::var_os(key).is_none() {
                let tool = sdk.join("bin").join(if cfg!(windows) {
                    format!("{tool}.exe")
                } else {
                    tool.to_owned()
                });
                if !tool.is_file() {
                    return Err(Error::new(
                        "E_TOOLCHAIN_UNAVAILABLE",
                        format!("WASI_SDK_PATH is missing {}", tool.display()),
                    ));
                }
                command.env(key, tool);
            }
        }
    }
    let mut child = command
        .spawn()
        .map_err(|e| Error::new("E_TOOLCHAIN_UNAVAILABLE", e))?;
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut output = None;
    while let Some(line) = lines.next_line().await? {
        if line.len() > 4 * 1024 * 1024 {
            return Err(Error::new(
                "E_BUILD_FAILED",
                "Cargo diagnostic exceeds 4 MiB",
            ));
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(message)
                if message["reason"] == "compiler-artifact" && message["package_id"] == id =>
            {
                for file in message["filenames"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    if Path::new(file).extension().is_some_and(|ext| ext == "wasm") {
                        if output.is_some() {
                            return Err(Error::new(
                                "E_BUILD_FAILED",
                                "Cargo returned multiple backend Components",
                            ));
                        }
                        output = Some(PathBuf::from(file));
                    }
                }
            }
            Ok(message) => {
                if let Some(rendered) = message["message"]["rendered"].as_str() {
                    eprint!("{rendered}");
                }
            }
            Err(_) => eprintln!("{line}"),
        }
    }
    if !child.wait().await?.success() {
        return Err(Error::new("E_BUILD_FAILED","Rust backend compilation failed")
            .hint("Check the Cargo diagnostics; install the target with rustup target add wasm32-wasip2 if needed"));
    }
    let output = output.ok_or_else(|| {
        Error::new(
            "E_BUILD_FAILED",
            "Cargo did not produce a backend Component",
        )
    })?;
    local_path(root, &output)
}

fn sdk_routes(bytes: &[u8]) -> Result<Option<Value>> {
    let mut routes = None;
    for item in wasmparser::Parser::new(0).parse_all(bytes) {
        if let wasmparser::Payload::CustomSection(section) =
            item.map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?
            && section.name() == "jade:routes"
        {
            if routes.is_some() || section.data().len() > 1024 * 1024 {
                return Err(Error::new(
                    "E_ARTIFACT_INVALID",
                    "Duplicate or oversized SDK route declarations",
                ));
            }
            routes = Some(serde_json::from_slice(section.data()).map_err(|e| {
                Error::new("E_ARTIFACT_INVALID", format!("Invalid SDK routes: {e}"))
            })?);
        }
    }
    Ok(routes)
}

fn openapi(routes: &Value, package: &Package) -> Result<Vec<u8>> {
    let routes = routes
        .as_array()
        .ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "SDK routes must be an array"))?;
    let mut paths = serde_json::Map::new();
    for route in routes {
        let path = route["path"]
            .as_str()
            .ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "SDK route has no path"))?;
        let method = route["method"]
            .as_str()
            .ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "SDK route has no method"))?;
        let handler = route["handler"]
            .as_str()
            .ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "SDK route has no handler"))?;
        let item = paths.entry(path.to_owned()).or_insert_with(|| json!({}));
        if item.get(method).is_some() {
            return Err(Error::new("E_ARTIFACT_INVALID", "Duplicate SDK route"));
        }
        item[method] = json!({"operationId":handler,"summary":handler.replace('_'," "),
            "responses":{"200":{"description":"Success","content":{"application/json":{"schema":{}}}}}});
    }
    serde_json::to_vec(&json!({"openapi":"3.1.0","info":{"title":package.title.as_ref().unwrap_or(&package.name),"version":package.version},"paths":paths}))
        .map_err(|e|Error::new("E_ARTIFACT_INVALID",e))
}

/// Validate structure and the host's HTTP entry point without executing guest code.
pub(crate) fn validate_component(
    bytes: &[u8],
    host: &Value,
    version: &str,
    author: &str,
    name: &str,
) -> Result<()> {
    let invalid = |message: &str| Error::new("E_ARTIFACT_INVALID", message);
    if bytes.get(..8) != Some(b"\0asm\x0d\0\x01\0") {
        return Err(invalid("Backend must be a WASM Component"));
    }
    let mut features = wasmparser::WasmFeatures::default();
    features.set(wasmparser::WasmFeatures::THREADS, false);
    wasmparser::Validator::new_with_features(features)
        .validate_all(bytes)
        .map_err(|e| invalid(&format!("Invalid backend Component: {e}")))?;
    let mut depth = 0;
    let mut document = None;
    for item in wasmparser::Parser::new(0).parse_all(bytes) {
        match item.map_err(|e| invalid(&e.to_string()))? {
            wasmparser::Payload::ModuleSection { .. }
            | wasmparser::Payload::ComponentSection { .. } => depth += 1,
            wasmparser::Payload::End(_) if depth > 0 => depth -= 1,
            wasmparser::Payload::CustomSection(section) if section.name() == "pishoo:signature" => {
                return Err(invalid("Backend must not embed a second signature"));
            }
            wasmparser::Payload::CustomSection(section) if section.name() == "pishoo:openapi" => {
                if depth != 0 || document.is_some() || section.data().len() > 1024 * 1024 {
                    return Err(invalid(
                        "OpenAPI must be one bounded top-level custom section",
                    ));
                }
                document = Some(section.data());
            }
            _ => {}
        }
    }
    let document: Value = serde_json::from_slice(document.ok_or_else(|| {
        invalid("Missing embedded OpenAPI; use the API template or provide a prepared Component")
    })?)
    .map_err(|e| invalid(&format!("Invalid OpenAPI JSON: {e}")))?;
    if !document["openapi"]
        .as_str()
        .is_some_and(|s| s.starts_with("3.1."))
        || document["info"]["version"] != version
        || document["info"]["title"]
            .as_str()
            .is_none_or(|s| s.trim().is_empty())
    {
        return Err(invalid(
            "OpenAPI requires version 3.1.x, an info.title and the package's info.version",
        ));
    }
    let paths = document["paths"]
        .as_object()
        .ok_or_else(|| invalid("OpenAPI paths must be an object"))?;
    let mut operation_ids = HashSet::new();
    for (path, item) in paths {
        if !path.starts_with('/')
            || path.contains(['{', '}', '?', '#', '%', '\\'])
            || path.contains("//")
            || path.chars().any(|c| c.is_whitespace() || c.is_control())
            || path.split('/').any(|s| s == "." || s == "..")
            || path.len() > 1024
            || (path != "/" && path.ends_with('/'))
            || item.get("$ref").is_some()
            || ["/api", "/app"]
                .iter()
                .any(|p| path == p || path.starts_with(&format!("{p}/")))
        {
            return Err(invalid(&format!("Unsupported OpenAPI path: {path}")));
        }
        if author == "std.dhttp.net"
            && path != &format!("/{name}")
            && !path.starts_with(&format!("/{name}/"))
        {
            return Err(invalid(
                "Standard API paths must stay under their package name",
            ));
        }
        for method in [
            "get", "head", "post", "put", "patch", "delete", "options", "trace",
        ] {
            if let Some(operation) = item.get(method) {
                let id = operation["operationId"]
                    .as_str()
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| invalid("OpenAPI operationId is required"))?;
                if !operation_ids.insert(id)
                    || operation["summary"]
                        .as_str()
                        .is_none_or(|s| s.trim().is_empty())
                    || operation["responses"]
                        .as_object()
                        .is_none_or(|r| r.is_empty())
                {
                    return Err(invalid(
                        "OpenAPI operations require unique IDs, summaries and responses",
                    ));
                }
            }
        }
    }
    let wit_parser::decoding::DecodedWasm::Component(resolve, world) =
        wit_parser::decoding::decode(bytes)
            .map_err(|e| invalid(&format!("Cannot decode backend interface: {e}")))?
    else {
        return Err(invalid("Expected a Component interface"));
    };
    let world = &resolve.worlds[world];
    let mut handler = None;
    for item in world.exports.values() {
        if let wit_parser::WorldItem::Interface { id, .. } = item {
            let interface = &resolve.interfaces[*id];
            if interface.name.as_deref() == Some("incoming-handler") && wasi_http(&resolve, *id) {
                handler = Some(interface);
            }
        }
    }
    let handler =
        handler.ok_or_else(|| invalid("Backend must export wasi:http/incoming-handler@0.2.x"))?;
    let handle = handler
        .functions
        .get("handle")
        .ok_or_else(|| invalid("Missing HTTP handle function"))?;
    if handler.functions.len() != 1
        || handle.kind != wit_parser::FunctionKind::Freestanding
        || handle.result.is_some()
        || handle.params.len() != 2
        || !http_resource(&resolve, handle.params[0].1, "incoming-request")
        || !http_resource(&resolve, handle.params[1].1, "response-outparam")
    {
        return Err(invalid("HTTP handler has an incompatible signature"));
    }
    let host = host
        .as_object()
        .ok_or_else(|| invalid("Backend requires a host capability map"))?;
    for item in world.imports.values() {
        let wit_parser::WorldItem::Interface { id, .. } = item else {
            return Err(invalid("Unsupported top-level backend import"));
        };
        let interface = &resolve.interfaces[*id];
        let package = &resolve.packages[interface
            .package
            .ok_or_else(|| invalid("Unnamed backend import"))?]
        .name;
        let interface_name = interface.name.as_deref().unwrap_or_default();
        let supported = if package.namespace == "wasi"
            && package
                .version
                .as_ref()
                .is_some_and(|v| v.major == 0 && v.minor == 2)
        {
            match package.name.as_str() {
                "http" => matches!(interface_name, "types" | "outgoing-handler"),
                "io" => matches!(interface_name, "poll" | "streams" | "error"),
                "clocks" => matches!(interface_name, "wall-clock" | "monotonic-clock"),
                "random" => matches!(interface_name, "random" | "insecure" | "insecure-seed"),
                "filesystem" => matches!(interface_name, "types" | "preopens"),
                "cli" => matches!(
                    interface_name,
                    "environment"
                        | "exit"
                        | "stdin"
                        | "stdout"
                        | "stderr"
                        | "terminal-input"
                        | "terminal-output"
                        | "terminal-stdin"
                        | "terminal-stdout"
                        | "terminal-stderr"
                ),
                _ => false,
            }
        } else {
            package.namespace == "pishoo"
                && package.name == "identity"
                && package.version.as_ref().is_some_and(|v| {
                    v.major == 0
                        && ((v.minor == 1
                            && matches!(interface_name, "request-identity" | "signatures"))
                            || (v.minor == 2 && interface_name == "request-identity"))
                })
        };
        if !supported {
            return Err(invalid(&format!(
                "Unsupported host import: {}/{interface_name}",
                package
            )));
        }
        let capability = match (
            package.namespace.as_str(),
            package.name.as_str(),
            interface_name,
        ) {
            ("wasi", "filesystem", _) => Some("private-storage"),
            ("pishoo", "identity", "request-identity") => Some("request-identity"),
            ("pishoo", "identity", "signatures") => Some("signatures"),
            _ => None,
        };
        if let Some(capability) = capability
            && !host.contains_key(capability)
        {
            return Err(invalid(&format!(
                "Imported host capability requires a purpose in backend.host.{capability}"
            )));
        }
    }
    Ok(())
}

fn wasi_http(resolve: &wit_parser::Resolve, interface: wit_parser::InterfaceId) -> bool {
    resolve.interfaces[interface].package.is_some_and(|id| {
        let name = &resolve.packages[id].name;
        name.namespace == "wasi"
            && name.name == "http"
            && name
                .version
                .as_ref()
                .is_some_and(|v| v.major == 0 && v.minor == 2)
    })
}
fn http_resource(resolve: &wit_parser::Resolve, mut ty: wit_parser::Type, name: &str) -> bool {
    // Types form a validated graph; aliases can occur before both the handle and resource.
    for _ in 0..resolve.types.len() {
        let wit_parser::Type::Id(id) = ty else {
            return false;
        };
        match resolve.types[id].kind {
            wit_parser::TypeDefKind::Type(alias) => ty = alias,
            wit_parser::TypeDefKind::Handle(wit_parser::Handle::Own(mut resource)) => {
                for _ in 0..resolve.types.len() {
                    match resolve.types[resource].kind {
                        wit_parser::TypeDefKind::Type(wit_parser::Type::Id(alias)) => {
                            resource = alias
                        }
                        wit_parser::TypeDefKind::Resource => {
                            return resolve.types[resource].name.as_deref() == Some(name)
                                && matches!(resolve.types[resource].owner,wit_parser::TypeOwner::Interface(owner) if resolve.interfaces[owner].name.as_deref()==Some("types") && wasi_http(resolve,owner));
                        }
                        _ => return false,
                    }
                }
                return false;
            }
            _ => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
