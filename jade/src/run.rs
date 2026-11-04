//! Build and watch a dependency graph on a separate, ordinary development identity.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub(super) async fn run(
    path: PathBuf,
    id: Option<String>,
    fresh: bool,
    machine: bool,
) -> Result<Value> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (path, id, fresh, machine);
        Err(Error::new(
            "E_DEV_UNSUPPORTED",
            "Local development publishing requires Linux or macOS",
        ))
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let home = crate::identity::home()?;
        let host = select_host(&home, id.as_deref(), machine).await?;
        let profile = home
            .resolve_identity_profile_exactly(&host)
            .await
            .map_err(|error| match error {
                dhttp_home::identity::ssl::ResolveIdentityProfileError::ExactNotFound {
                    ..
                } => {
                    let name = host.strip_suffix(dhttp_home::DHTTP_SUFFIX).unwrap_or(&host);
                    Error::new(
                        "E_IDENTITY_UNAVAILABLE",
                        format!("Development identity {name} is not set up yet."),
                    )
                    .hint(format!(
                        "Run `genmeta identity apply {name}`, then retry `jade run`."
                    ))
                }
                error => Error::new("E_IDENTITY_UNAVAILABLE", error),
            })?;
        validate_host(&profile).await?;
        let profile = profile.path().canonicalize()?;
        let (project, config) = crate::project::read(&path)?;
        let root_author =
            crate::identity::normalize(config.package.author.as_deref().unwrap_or(&host))?;
        let data_directory =
            profile
                .join(".volume")
                .join(if crate::identity::is_standard_author(&root_author) {
                    format!("std/{}", config.package.name)
                } else {
                    config.package.name.clone()
                });
        projects(&project, &host)?;
        prepare_host(&profile).await?;
        let mut published_directories = BTreeMap::new();
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let work = async {
            let mut previous = None;
            let mut installed_dependencies = None;
            let mut last_error = None;
            let mut reset_data = fresh;
            loop {
                let candidate = async {
                    let (locals, remote) = projects(&project, &host)?;
                    let fingerprint = graph_fingerprint(&locals)?;
                    if previous.as_ref() == Some(&fingerprint) {
                        return Ok(());
                    }
                    previous = Some(fingerprint.clone());
                    if installed_dependencies.as_ref() != Some(&remote) {
                        install_dependencies(&profile, &host, &remote).await?;
                        installed_dependencies = Some(remote);
                    }
                    let mut built = Vec::new();
                    for (name, path) in &locals {
                        eprintln!("Building  {name}");
                        built.push((name.clone(), build(path, &host).await?.1));
                    }
                    if graph_fingerprint(&locals)? != fingerprint {
                        previous = None;
                        return Ok(());
                    }
                    // Build the complete local graph before replacing any running files.
                    for (name, files) in built {
                        let (mut result, directory) = publish(&profile, &name, &files, reset_data)?;
                        published_directories.insert(name.clone(), directory);
                        result["host"] = host.clone().into();
                        let manifest: Value = serde_json::from_slice(&files["manifest.json"]).map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
                        if result["has_api"] == true {
                            let prefix = if crate::identity::is_standard_author(manifest["package"]["author"].as_str().unwrap_or("")) { "/std" } else { "" };
                            result["api"] = format!("https://{host}{prefix}/{name}").into();
                        }
                        if result["has_app"] == true {
                            result["app"] = format!("https://{host}/app/{name}/").into();
                        }
                        if machine {
                            eprintln!("{}", json!({"command":"run","event":"published","result":result}));
                        } else {
                            eprintln!("Published {}", result["directory"].as_str().unwrap());
                            for key in ["api", "app"] {
                                if let Some(url) = result[key].as_str() { eprintln!("{key}  {url}"); }
                            }
                        }
                    }
                    for stale in published_directories.keys().filter(|name| !locals.contains_key(*name)).cloned().collect::<Vec<_>>() {
                        let directory = published_directories.remove(&stale).unwrap();
                        remove_published(&profile, &stale, &directory)?;
                    }
                    reset_data = false;
                    eprintln!("Watching local projects. Ctrl+C removes local App/API files and keeps development data.");
                    Ok::<_, Error>(())
                }.await;
                if let Err(error) = candidate {
                    if previous.is_none()
                        || (published_directories.is_empty()
                            && matches!(
                                error.code,
                                "E_INSTALL_FAILED"
                                    | "E_HOST_UNAVAILABLE"
                                    | "E_IDENTITY_UNAVAILABLE"
                            ))
                    {
                        return Err(error);
                    }
                    let message =
                        json!({"command":"run","event":"not_applied","error":error.json()})
                            .to_string();
                    if last_error.as_ref() != Some(&message) {
                        eprintln!("{message}");
                    }
                    last_error = Some(message);
                } else {
                    last_error = None;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        };
        let result: Result<Value> = tokio::select! {
            result = work => result,
            _ = tokio::signal::ctrl_c() => Ok(json!({"stopped":true})),
            _ = terminate.recv() => Ok(json!({"stopped":true})),
        };
        // Stopping the watcher owns filesystem cleanup; Pishoo only observes files.
        let mut removed = false;
        let mut cleanup_error = None;
        for (name, directory) in published_directories {
            match remove_published(&profile, &name, &directory) {
                Ok(did_remove) => removed |= did_remove,
                Err(error) => {
                    cleanup_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = cleanup_error {
            return Err(error);
        }
        result.map(|mut value| {
            value["removed"] = removed.into();
            value["data_directory"] = data_directory.to_string_lossy().as_ref().into();
            value
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn remove_published(profile: &Path, name: &str, published: &std::fs::File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let dev = profile.join("dev");
    if !dev.try_exists()? {
        return Ok(false);
    }
    let root = private_directory(&dev, &profile.metadata()?)?;
    rustix::fs::flock(&root, rustix::fs::FlockOperation::LockExclusive)
        .map_err(std::io::Error::from)?;
    let path = dev.join(name);
    let current = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    // A later publisher may have replaced the same slot. Never remove its files.
    let published = published.metadata()?;
    if !current.is_dir() || current.dev() != published.dev() || current.ino() != published.ino() {
        return Ok(false);
    }
    std::fs::remove_dir_all(&path)
        .map_err(|e| Error::new("E_DEV_CLEANUP", e).context(json!({"directory":path})))?;
    root.sync_all()?;
    Ok(true)
}

async fn build(path: &Path, host: &str) -> Result<(String, BTreeMap<String, Vec<u8>>)> {
    let (project, config) = crate::project::read(path)?;
    let author = crate::identity::normalize(config.package.author.as_deref().unwrap_or(host))?;
    let files = crate::pack::build_files(
        &project,
        &config,
        &author,
        &project
            .join(crate::project::BUILD_DIR)
            .join(".development-files"),
    )
    .await?;
    Ok((config.package.name, files))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn publish(
    profile: &Path,
    name: &str,
    files: &BTreeMap<String, Vec<u8>>,
    fresh: bool,
) -> Result<(Value, std::fs::File)> {
    use std::{
        fs::File,
        io::Write,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };
    let owner = profile.metadata()?;
    let dev = profile.join("dev");
    let root = private_directory(&dev, &owner)?;
    rustix::fs::flock(&root, rustix::fs::FlockOperation::LockExclusive)
        .map_err(std::io::Error::from)?;
    let staged = tempfile::Builder::new().prefix(".jade-").tempdir_in(&dev)?;
    let has_api = files.contains_key("backend.wasm");
    let has_app = files.contains_key("public/index.html");
    for (source, bytes) in files {
        let target = if source == "manifest.json" {
            Some("manifest.json".to_owned())
        } else if source == "backend.wasm" {
            Some("lib.wasm".to_owned())
        } else {
            source
                .strip_prefix("public/")
                .map(|relative| format!("app/{relative}"))
        };
        let Some(target) = target else {
            continue;
        };
        if Path::new(&target)
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(Error::new(
                "E_ARTIFACT_INVALID",
                "Invalid development resource path",
            ));
        }
        let target = staged.path().join(target);
        std::fs::create_dir_all(target.parent().unwrap())?;
        let mut file = File::create(target)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fn own(path: &Path, owner: &std::fs::Metadata) -> std::io::Result<()> {
        let file = File::open(path)?;
        if file.metadata()?.is_dir() {
            file.set_permissions(std::fs::Permissions::from_mode(0o700))?;
            for entry in std::fs::read_dir(path)? {
                own(&entry?.path(), owner)?;
            }
        }
        if unsafe { libc::geteuid() } == 0 {
            use std::os::fd::AsRawFd;
            if unsafe { libc::fchown(file.as_raw_fd(), owner.uid(), owner.gid()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
    own(staged.path(), &owner)?;
    let data_root = profile.join(".volume");
    let _data = private_directory(&data_root, &owner)?;
    let manifest: Value = serde_json::from_slice(&files["manifest.json"])
        .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
    let data_root = if crate::identity::is_standard_author(
        manifest["package"]["author"].as_str().unwrap_or(""),
    ) {
        let standard = data_root.join("std");
        private_directory(&standard, &owner)?;
        standard
    } else {
        data_root
    };
    let data = data_root.join(name);
    if fresh && data.try_exists()? {
        let _ = private_directory(&data, &owner)?;
        let previous = tempfile::Builder::new()
            .prefix(&format!(".{name}-previous-"))
            .tempdir_in(&data_root)?
            .keep();
        std::fs::rename(&data, &previous)?;
    }
    let _ = private_directory(&data, &owner)?;
    let target = dev.join(name);
    let flags = match target.symlink_metadata() {
        Ok(metadata)
            if metadata.is_dir()
                && metadata.uid() == owner.uid()
                && metadata.mode() & 0o022 == 0 =>
        {
            rustix::fs::RenameFlags::EXCHANGE
        }
        Ok(_) => {
            return Err(Error::new(
                "E_OUTPUT_CONFLICT",
                "Development destination must be an owned directory",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            rustix::fs::RenameFlags::NOREPLACE
        }
        Err(error) => return Err(error.into()),
    };
    rustix::fs::renameat_with(
        &root,
        staged.path().file_name().unwrap(),
        &root,
        name,
        flags,
    )
    .map_err(std::io::Error::from)?;
    root.sync_all()?;
    // EXCHANGE leaves the previous artifacts in staged; removing those files does
    // not affect already-open HTTP files or previously compiled WASM instances.
    // Keep the directory inode alive until this publisher stops, so a reused
    // inode can never make cleanup mistake a later publisher's directory for ours.
    let metadata = std::fs::File::from(
        rustix::fs::open(
            &target,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    Ok((
        json!({"name":name,"directory":target,"data_directory":data,"has_api":has_api,"has_app":has_app}),
        metadata,
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn private_directory(path: &Path, owner: &std::fs::Metadata) -> Result<std::fs::File> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let created = match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    let file = std::fs::File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    if created && unsafe { libc::geteuid() } == 0 {
        use std::os::fd::AsRawFd;
        if unsafe { libc::fchown(file.as_raw_fd(), owner.uid(), owner.gid()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let metadata = file.metadata()?;
    if metadata.uid() != owner.uid() || metadata.mode() & 0o022 != 0 {
        return Err(Error::new(
            "E_OUTPUT_CONFLICT",
            "Development directories must belong to the identity owner and not be writable by other users",
        ));
    }
    Ok(file)
}

async fn select_host(
    home: &dhttp_home::DhttpHome,
    explicit: Option<&str>,
    _machine: bool,
) -> Result<String> {
    if let Some(name) = explicit {
        return crate::identity::developer_name(name);
    }
    crate::identity::default_developer_name(home).await
}

// Local paths resolve against the manifest that declares them, including nested dependencies.
fn projects(root: &Path, host: &str) -> Result<(BTreeMap<String, PathBuf>, Vec<Value>)> {
    fn visit(
        path: &Path,
        host: &str,
        active: &mut Vec<PathBuf>,
        locals: &mut BTreeMap<String, PathBuf>,
        versions: &mut BTreeMap<String, (String, String)>,
        remote: &mut BTreeMap<String, Value>,
    ) -> Result<()> {
        let (root, manifest) = crate::project::read(path)?;
        if active.contains(&root) {
            return Err(Error::new("E_CONFIG_INVALID", "Local dependency cycle"));
        }
        let author =
            crate::identity::normalize(manifest.package.author.as_deref().unwrap_or(host))?;
        let name = &manifest.package.name;
        let identity = (author.clone(), manifest.package.version.clone());
        if let Some(previous) = versions.insert(name.clone(), identity.clone())
            && previous != identity
        {
            return Err(Error::new(
                "E_CONFIG_INVALID",
                format!("Conflicting dependency versions or authors for {name}"),
            ));
        }
        if let Some(previous) = locals.get(name) {
            if previous != &root {
                return Err(Error::new(
                    "E_CONFIG_INVALID",
                    format!("Multiple local projects named {name}"),
                ));
            }
            return Ok(());
        }
        active.push(root.clone());
        for dependency in &manifest.dependencies {
            let author = crate::identity::normalize(&dependency.author)?;
            let identity = (author.clone(), dependency.version.clone());
            if let Some(previous) = versions.insert(dependency.name.clone(), identity.clone())
                && previous != identity
            {
                return Err(Error::new(
                    "E_CONFIG_INVALID",
                    format!("Conflicting dependency {}", dependency.name),
                ));
            }
            if let Some(path) = &dependency.path {
                let path = root.join(path);
                let (_, local) = crate::project::read(&path)?;
                if local.package.name != dependency.name
                    || local.package.version != dependency.version
                    || crate::identity::normalize(local.package.author.as_deref().unwrap_or(host))?
                        != author
                {
                    return Err(Error::new(
                        "E_CONFIG_INVALID",
                        format!(
                            "Local dependency {} does not match author/name/version",
                            dependency.name
                        ),
                    ));
                }
                visit(&path, host, active, locals, versions, remote)?;
            } else {
                remote.insert(
                    dependency.name.clone(),
                    json!({"author":author,"name":dependency.name,"version":dependency.version}),
                );
            }
        }
        active.pop();
        locals.insert(name.clone(), root);
        Ok(())
    }
    let mut locals = BTreeMap::new();
    let mut remote = BTreeMap::new();
    visit(
        root,
        host,
        &mut Vec::new(),
        &mut locals,
        &mut BTreeMap::new(),
        &mut remote,
    )?;
    Ok((locals, remote.into_values().collect()))
}

fn graph_fingerprint(projects: &BTreeMap<String, PathBuf>) -> Result<Vec<u8>> {
    let mut digest = Sha256::new();
    for (name, path) in projects {
        digest.update(name.as_bytes());
        digest.update(path.as_os_str().as_encoded_bytes());
        digest.update(source_fingerprint(path)?);
    }
    Ok(digest.finalize().to_vec())
}

async fn validate_host(profile: &dhttp_home::identity::IdentityProfile) -> Result<()> {
    let name = profile
        .name()
        .strip_suffix(dhttp_home::DHTTP_SUFFIX)
        .unwrap_or(profile.name());
    let unavailable = |detail: String| {
        Error::new(
            "E_IDENTITY_UNAVAILABLE",
            format!("Development identity {name} needs ordinary hosting credentials: {detail}"),
        )
        .hint(format!(
            "Run `genmeta identity apply {name}`, then retry `jade run`."
        ))
    };
    // An existing profile may contain only a pending developer request or code-signing
    // credentials. Pishoo discovers ordinary SSL identities, not profile directories.
    let certificates = profile
        .load_certs()
        .await
        .map_err(|error| unavailable(error.to_string()))?;
    let key = profile
        .load_key()
        .await
        .map_err(|error| unavailable(error.to_string()))?;
    let ski = dhttp_home::certificate::extract_dhttp_subject_key_identifier(&certificates)
        .map_err(|error| unavailable(error.to_string()))?;
    if ski.chain().usage() != dhttp_home::certificate::CertificateUsage::ClientAndServer {
        return Err(unavailable(
            "a ClientAndServer certificate is required".into(),
        ));
    }
    rustls::sign::CertifiedKey::from_der(
        certificates,
        key,
        &rustls::crypto::ring::default_provider(),
    )
    .map_err(|error| unavailable(error.to_string()))?;
    // The host refreshes OCSP when loading this identity; no network setup is needed here.
    Ok(())
}

async fn prepare_host(profile: &Path) -> Result<()> {
    // Reuse the existing daemon; this subprocess only writes its normal identity configuration.
    let executable = std::env::var_os("PISHOO_BIN").unwrap_or_else(|| "pishoo".into());
    let output = tokio::process::Command::new(executable)
        .arg("configure")
        .arg("--profile")
        .arg(profile)
        .args(["--listen", "all"])
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| Error::new("E_HOST_UNAVAILABLE", e))?;
    if !output.status.success() {
        return Err(Error::new(
            "E_HOST_UNAVAILABLE",
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(())
}

async fn install_dependencies(profile: &Path, host: &str, dependencies: &[Value]) -> Result<()> {
    if dependencies.is_empty() {
        return Ok(());
    }
    crate::upload::init_network()
        .await
        .map_err(|e| Error::new("E_HOST_UNAVAILABLE", e))?;
    let endpoint = dhttp::Endpoint::load_from_with_ocsp(profile)
        .await
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    install_from_host(&endpoint, host, dependencies).await
}

async fn install_from_host(
    endpoint: &dhttp::Endpoint,
    host: &str,
    dependencies: &[Value],
) -> Result<()> {
    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;
    let local = endpoint
        .local_authority()
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    let owner = dhttp_home::certificate::extract_dhttp_subject_key_identifier(local.certificates())
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?
        .owner_hash()
        .clone();
    for dependency in dependencies {
        let operation = async {
            let uri: http::Uri = format!("https://{host}/std/sys/pkg/install")
                .parse()
                .map_err(|e| Error::new("E_HOST_UNAVAILABLE", e))?;
            let (mut writer, receive) = endpoint
                .post(uri)
                .expect_remote_owner_hash(owner.clone())
                .header(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                )
                .await
                .map_err(|e| Error::new("E_HOST_UNAVAILABLE", e))?;
            let bytes =
                serde_json::to_vec(dependency).map_err(|e| Error::new("E_CONFIG_INVALID", e))?;
            let upload = async {
                writer.write_all(&bytes).await?;
                writer.shutdown().await?;
                Ok::<_, Error>(())
            };
            let receive = async { receive.await.map_err(|e| Error::new("E_INSTALL_FAILED", e)) };
            let (_, response) = tokio::try_join!(upload, receive)?;
            let status = response.status();
            let bytes = http_body_util::Limited::new(response.into_body(), 1024 * 1024)
                .collect()
                .await
                .map_err(|e| Error::new("E_INSTALL_FAILED", e))?
                .to_bytes();
            if status != http::StatusCode::OK {
                return Err(Error::new(
                    "E_INSTALL_FAILED",
                    format!(
                        "{dependency}: HTTP {status}: {}",
                        String::from_utf8_lossy(&bytes)
                    ),
                ));
            }
            let installed: Value =
                serde_json::from_slice(&bytes).map_err(|e| Error::new("E_INSTALL_FAILED", e))?;
            if installed["author"] != dependency["author"]
                || installed["name"] != dependency["name"]
                || installed["version"] != dependency["version"]
            {
                return Err(Error::new(
                    "E_INSTALL_FAILED",
                    "Host returned a different dependency version",
                ));
            }
            Ok(())
        };
        tokio::time::timeout(std::time::Duration::from_secs(120), operation)
            .await
            .map_err(|e| Error::new("E_INSTALL_FAILED", e))??;
    }
    Ok(())
}

fn source_fingerprint(root: &Path) -> Result<Vec<u8>> {
    let canonical_root = root.canonicalize()?;
    let root = canonical_root.as_path();
    fn collect(
        root: &Path,
        directory: &Path,
        files: &mut BTreeMap<PathBuf, Vec<u8>>,
        remaining: &mut usize,
        frontend_output: Option<&Path>,
    ) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            if matches!(
                name.to_str(),
                Some(".git" | "target" | "node_modules" | "build" | ".jade" | ".DS_Store")
            ) {
                continue;
            }
            if frontend_output == Some(path.as_path()) {
                continue;
            }
            let kind = entry.file_type()?;
            let relative = path
                .strip_prefix(root)
                .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?
                .to_path_buf();
            if kind.is_dir() {
                collect(root, &path, files, remaining, frontend_output)?;
            } else if kind.is_file() {
                if files.len() >= 20_000 {
                    return Err(Error::new(
                        "E_ARTIFACT_INVALID",
                        "Project watcher exceeds 20000 files",
                    ));
                }
                let bytes = crate::pack::read_bounded(&path, (*remaining).min(64 * 1024 * 1024))
                    .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
                *remaining -= bytes.len();
                files.insert(relative, bytes);
            } else if kind.is_symlink() {
                files.insert(
                    relative,
                    std::fs::read_link(&path)?
                        .as_os_str()
                        .as_encoded_bytes()
                        .to_vec(),
                );
            }
        }
        Ok(())
    }
    let frontend_output = crate::project::read(root)
        .ok()
        .and_then(|(project, config)| {
            let source = project.join(config.frontend?);
            let bytes =
                crate::pack::read_bounded(&source.join("package.json"), 1024 * 1024).ok()?;
            let package: Value = serde_json::from_slice(&bytes).ok()?;
            package["scripts"]["build"]
                .is_string()
                .then(|| source.join("dist"))
        });
    let mut files = BTreeMap::new();
    collect(
        root,
        root,
        &mut files,
        &mut (256 * 1024 * 1024),
        frontend_output.as_deref(),
    )?;
    let mut digest = Sha256::new();
    for (path, bytes) in files {
        digest.update(path.as_os_str().as_encoded_bytes());
        digest.update([0]);
        digest.update(Sha256::digest(bytes));
    }
    Ok(digest.finalize().to_vec())
}

#[cfg(test)]
#[path = "../tests/unit/run.rs"]
mod tests;
