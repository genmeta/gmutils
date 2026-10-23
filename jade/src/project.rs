//! Jade configuration and native source builds. No per-project build scripts.
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::Stdio,
};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::error::{Error, Result};

pub(crate) const BUILD_DIR: &str = "build";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub package: Package,
    #[serde(skip)]
    pub frontend: Option<PathBuf>,
    #[serde(skip)]
    pub backend: Option<PathBuf>,
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
    let mut manifest: Manifest = toml::from_str(source).map_err(|e: toml::de::Error| {
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
    let path = std::fs::canonicalize(&path)?;
    let root = path.parent().unwrap();
    manifest.frontend = discover_frontend(root)?;
    manifest.backend = discover_backend(root)?;
    if manifest.frontend.is_none() && manifest.backend.is_none() {
        return Err(
            Error::new("E_CONFIG_INVALID", "No frontend or backend found")
                .hint("Add index.html, public/index.html, a frontend package.json build script, or a Rust backend")
                .context(json!({"file":path})),
        );
    }
    let author = manifest
        .package
        .author
        .as_deref()
        .unwrap_or("jade-validation.dhttp.net");
    let (wapm, annotation) = manifest.metadata(&crate::identity::normalize(author)?)?;
    crate::pack::validate_metadata(&wapm, &annotation, manifest.backend.is_some())
        .map_err(|e| Error::new("E_CONFIG_INVALID", e).context(json!({"file":path})))?;
    Ok((root.to_path_buf(), manifest))
}

fn discover_frontend(root: &Path) -> Result<Option<PathBuf>> {
    let mut candidates = Vec::new();
    for source in [".", "web", "app"] {
        let path = root.join(source);
        if marker_exists(&path.join("package.json"))?
            && node_package(&local_path(root, Path::new(source))?)?
                .as_ref()
                .and_then(|package| package.get("scripts"))
                .and_then(|scripts| scripts.get("build"))
                .is_some()
        {
            candidates.push(PathBuf::from(source));
        }
    }
    // Source wins over static fallbacks, including stale dist outputs.
    for sources in [
        &[".", "web", "app", "public"][..],
        &["dist", "web/dist", "app/dist"][..],
    ] {
        if !candidates.is_empty() {
            break;
        }
        for source in sources {
            if marker_exists(&root.join(source).join("index.html"))? {
                candidates.push(PathBuf::from(source));
            }
        }
    }
    if candidates.len() > 1 {
        return Err(Error::new(
            "E_CONFIG_INVALID",
            format!(
                "Multiple frontend sources found: {}",
                candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .hint("Keep one frontend build project or one static entry directory"));
    }
    Ok(candidates.pop())
}

fn marker_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::new("E_CONFIG_INVALID", error)),
    }
}

fn discover_backend(root: &Path) -> Result<Option<PathBuf>> {
    let mut candidates = Vec::new();
    for (marker, source) in [
        ("Cargo.toml", "."),
        ("api/Cargo.toml", "api"),
        ("lib/Cargo.toml", "lib"),
    ] {
        match std::fs::symlink_metadata(root.join(marker)) {
            Ok(_) => candidates.push((marker, PathBuf::from(source))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::new("E_CONFIG_INVALID", error)),
        }
    }
    if candidates.len() > 1 {
        return Err(Error::new(
            "E_CONFIG_INVALID",
            format!(
                "Multiple Rust backend sources found: {}",
                candidates
                    .iter()
                    .map(|(marker, _)| *marker)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .hint("Keep one Rust backend source: Cargo.toml, api/Cargo.toml or lib/Cargo.toml"));
    }
    if let Some((_, source)) = candidates.pop() {
        return Ok(Some(source));
    }
    // A prebuilt Component is a fallback; old build outputs must not mask source.
    match std::fs::symlink_metadata(root.join("lib.wasm")) {
        Ok(_) => Ok(Some(PathBuf::from("lib.wasm"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::new("E_CONFIG_INVALID", error)),
    }
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
        Ok((wapm, annotation))
    }
}

pub(crate) fn local_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let path = path
        .to_str()
        .ok_or_else(|| Error::new("E_CONFIG_INVALID", "Artifact path must be UTF-8"))?;
    crate::pack::local_content_path(root, path).map_err(|e| Error::new("E_ARTIFACT_INVALID", e))
}

pub(crate) async fn frontend(root: &Path, source: &Path) -> Result<PathBuf> {
    let path = local_path(root, source)?;
    if !path.is_dir() {
        return Err(Error::new(
            "E_ARTIFACT_INVALID",
            "Frontend source must be a directory",
        ));
    }
    let package = node_package(&path)?;
    let directory = if package
        .as_ref()
        .and_then(|p| p.get("scripts"))
        .and_then(|s| s.get("build"))
        .is_some()
    {
        let manager = node_manager(&path, package.as_ref().unwrap())?;
        // Build tools such as Vite live in devDependencies, even for production builds.
        let install_args: &[&str] = match manager {
            "npm" => &["install", "--include=dev"],
            "pnpm" => &["install", "--prod=false"],
            _ => &["install"],
        };
        eprintln!(
            "  Installing  frontend dependencies ({manager} {})",
            install_args.join(" ")
        );
        run(manager, install_args, &path).await?;
        eprintln!("  Building  frontend ({manager} run build)");
        run(manager, &["run", "build"], &path).await?;
        local_path(root, &path.join("dist"))?
    } else {
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

fn node_package(path: &Path) -> Result<Option<Value>> {
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
    if let Some(build) = build
        && build.as_str().is_none_or(|s| s.trim().is_empty())
    {
        return Err(Error::new(
            "E_CONFIG_INVALID",
            "package.json scripts.build must be a nonempty string",
        ));
    }
    Ok(package)
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
            format!("{program} {} failed ({status})", args.join(" ")),
        ));
    }
    Ok(())
}

pub(crate) async fn backend(root: &Path, source: &Path, package: &Package) -> Result<Vec<u8>> {
    let path = local_path(root, source)?;
    let source = path.is_dir();
    let file = if source {
        cargo_build(root, &path).await?
    } else {
        path.clone()
    };
    let mut bytes = crate::pack::read_bounded(&file, crate::package::PACKAGE_LIMIT)
        .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
    if source {
        let routes = declared_routes(&bytes)?;
        let api_file = path.join("openapi.json");
        let document = match (routes, api_file.try_exists()?) {
            (Some(_), true) => {
                return Err(Error::new(
                    "E_CONFIG_INVALID",
                    "Choose one OpenAPI source: route metadata or openapi.json",
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

fn wasi_sdk_hint() -> &'static str {
    if cfg!(windows) {
        "Install WASI SDK from https://github.com/WebAssembly/wasi-sdk/releases and set WASI_SDK_PATH to the extracted SDK root (containing bin and share/wasi-sysroot). In PowerShell:\n  $env:WASI_SDK_PATH = 'C:\\path\\to\\wasi-sdk'\nThen retry jade build."
    } else {
        "Install WASI SDK from https://github.com/WebAssembly/wasi-sdk/releases and set WASI_SDK_PATH to the extracted SDK root (containing bin and share/wasi-sysroot):\n  export WASI_SDK_PATH=\"/path/to/wasi-sdk\"\nThen retry jade build."
    }
}

#[derive(Default)]
struct CargoDiagnostics {
    wasi_target: bool,
    missing_c_toolchain: bool,
    missing_wasi_sysroot: bool,
    missing_rust_target: bool,
}

impl CargoDiagnostics {
    fn observe(&mut self, text: &str) {
        let text = text.to_ascii_lowercase();
        self.wasi_target |= text.contains("wasm32-wasi");
        self.missing_wasi_sysroot |= text.contains("environment variable wasi_sysroot not defined");
        for line in text.lines() {
            self.missing_rust_target |=
                line.contains("wasm32-wasip2") && line.contains("target may not be installed");
            self.missing_c_toolchain |= line.contains("failed to find tool")
                && (line.contains("\"clang\"") || line.contains("\"clang++\""));
            if let Some((_, detail)) = line.split_once("fatal error:")
                && (detail.contains("file not found")
                    || detail.contains("no such file or directory"))
            {
                let header = detail
                    .split([' ', '\t', '\'', '"', '<', '>', ':'])
                    .find(|part| !part.is_empty());
                self.missing_c_toolchain |= header.is_some_and(|header| {
                    [
                        "stdio.h",
                        "stdlib.h",
                        "string.h",
                        "stdint.h",
                        "stddef.h",
                        "stdbool.h",
                        "limits.h",
                        "errno.h",
                        "assert.h",
                        "math.h",
                        "time.h",
                        "iostream",
                        "vector",
                        "string",
                        "memory",
                        "cstddef",
                        "cstdio",
                        "cstdlib",
                        "cstdint",
                    ]
                    .contains(&header)
                });
            }
        }
    }

    fn merge(&mut self, other: Self) {
        self.wasi_target |= other.wasi_target;
        self.missing_c_toolchain |= other.missing_c_toolchain;
        self.missing_wasi_sysroot |= other.missing_wasi_sysroot;
        self.missing_rust_target |= other.missing_rust_target;
    }

    fn hint(&self) -> &'static str {
        if self.missing_rust_target {
            "Install the missing Rust target with: rustup target add wasm32-wasip2"
        } else if self.missing_wasi_sysroot || (self.wasi_target && self.missing_c_toolchain) {
            wasi_sdk_hint()
        } else {
            "Check the Cargo diagnostics above for the failing crate and error"
        }
    }
}

async fn forward_cargo_stderr(mut stderr: tokio::process::ChildStderr) -> Result<CargoDiagnostics> {
    let mut diagnostics = CargoDiagnostics::default();
    let mut output = tokio::io::stderr();
    let mut buffer = [0; 8192];
    let mut window = Vec::new();
    loop {
        let count = stderr.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count]).await?;
        window.extend_from_slice(&buffer[..count]);
        diagnostics.observe(&String::from_utf8_lossy(&window));
        // Retain only a small overlap to recognize diagnostics split across reads.
        if window.len() > 2048 {
            window.drain(..window.len() - 2048);
        }
    }
    output.flush().await?;
    Ok(diagnostics)
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
                "Backend source must contain one Rust package",
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
    let target_dir = root.join(BUILD_DIR).join("target");
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
        .stderr(Stdio::piped())
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
                    )
                    .hint(wasi_sdk_hint()));
                }
                command.env(key, tool);
            }
        }
    }
    let mut child = command
        .spawn()
        .map_err(|e| Error::new("E_TOOLCHAIN_UNAVAILABLE", e))?;
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let stderr = child.stderr.take().unwrap();
    let stdout = async {
        let mut output = None;
        let mut diagnostics = CargoDiagnostics::default();
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
                        diagnostics.observe(rendered);
                        eprint!("{rendered}");
                    }
                }
                Err(_) => {
                    diagnostics.observe(&line);
                    eprintln!("{line}");
                }
            }
        }
        Ok((output, diagnostics))
    };
    let ((output, mut diagnostics), stderr_diagnostics) =
        tokio::try_join!(stdout, forward_cargo_stderr(stderr))?;
    diagnostics.merge(stderr_diagnostics);
    if !child.wait().await?.success() {
        return Err(
            Error::new("E_BUILD_FAILED", "Rust backend compilation failed")
                .hint(diagnostics.hint()),
        );
    }
    let output = output.ok_or_else(|| {
        Error::new(
            "E_BUILD_FAILED",
            "Cargo did not produce a backend Component",
        )
    })?;
    local_path(root, &output)
}

fn declared_routes(bytes: &[u8]) -> Result<Option<Value>> {
    let mut routes = None;
    for item in wasmparser::Parser::new(0).parse_all(bytes) {
        if let wasmparser::Payload::CustomSection(section) =
            item.map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?
            && section.name() == "jade:routes"
        {
            if routes.is_some() || section.data().len() > 1024 * 1024 {
                return Err(Error::new(
                    "E_ARTIFACT_INVALID",
                    "Duplicate or oversized route declarations",
                ));
            }
            routes = Some(serde_json::from_slice(section.data()).map_err(|e| {
                Error::new("E_ARTIFACT_INVALID", format!("Invalid route metadata: {e}"))
            })?);
        }
    }
    Ok(routes)
}

fn openapi(routes: &Value, package: &Package) -> Result<Vec<u8>> {
    let routes = routes
        .as_array()
        .ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "Route metadata must be an array"))?;
    let mut paths = serde_json::Map::new();
    for route in routes {
        let path = route["path"]
            .as_str()
            .ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "Route has no path"))?;
        let method = route["method"]
            .as_str()
            .ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "Route has no method"))?;
        let handler = route["handler"]
            .as_str()
            .ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "Route has no handler"))?;
        let item = paths.entry(path.to_owned()).or_insert_with(|| json!({}));
        if item.get(method).is_some() {
            return Err(Error::new("E_ARTIFACT_INVALID", "Duplicate route"));
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
}
