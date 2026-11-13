//! Build and watch a dependency graph on a separate, ordinary development identity.
use std::path::PathBuf;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use std::{collections::BTreeMap, path::Path};

use serde_json::Value;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use serde_json::json;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub(super) async fn run(path: PathBuf, fresh: bool, machine: bool) -> Result<Value> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (path, fresh, machine);
        Err(Error::new(
            "E_DEV_UNSUPPORTED",
            "Local development publishing requires Linux or macOS",
        ))
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let home = crate::identity::home()?;
        let (project, config) = crate::project::read(&path)?;
        let host = crate::identity::select(config.package.author.as_deref()).await?;
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
        let data_directory = profile.join(".volume").join(
            if crate::identity::is_standard_author(&host)
                && !config.package.name.starts_with("std/")
            {
                format!("std/{}", config.package.name)
            } else {
                config.package.name.to_owned()
            },
        );
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
                        let (mut result, directory) = publish(&profile, &name, &files, reset_data, published_directories.get(&name))?;
                        published_directories.insert(name.clone(), directory);
                        result["host"] = host.clone().into();
                        let manifest = crate::archive::waz_manifest(&files).map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
                        if result["has_api"] == true {
                            let prefix = if crate::identity::is_standard_author(manifest["package"]["author"].as_str().unwrap_or("")) { "/std" } else { "" };
                            let document = wasmparser::Parser::new(0).parse_all(crate::archive::waz_backend(&files).ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "Missing backend"))?)
                                .find_map(|payload| match payload {
                                    Ok(wasmparser::Payload::CustomSection(section)) if section.name() == "pishoo:openapi" => Some(section.data()),
                                    _ => None,
                                }).ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "Missing backend OpenAPI"))?;
                            let document: Value = serde_json::from_slice(document).map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
                            let path = document["paths"].as_object().and_then(|paths| paths.keys().next())
                                .ok_or_else(|| Error::new("E_ARTIFACT_INVALID", "Missing API path"))?;
                            let base = if prefix == "/std" { "/std".to_owned() } else { format!("/{name}") };
                            result["api"] = format!("https://{host}{base}{path}").into();
                        }
                        if result["has_app"] == true {
                            result["app"] = format!("https://{host}/app/{}/", name.to_owned()).into();
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
    let owner = profile.metadata()?;
    let root = private_directory(profile, &owner)?;
    rustix::fs::flock(&root, rustix::fs::FlockOperation::LockExclusive)
        .map_err(std::io::Error::from)?;
    let marker_relative = format!("lib/{name}.preview");
    package_directory(
        profile,
        Path::new(&marker_relative)
            .parent()
            .unwrap()
            .to_str()
            .unwrap(),
        &owner,
    )?;
    let marker = profile.join(marker_relative);
    let current = match marker.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let published = published.metadata()?;
    if !current.is_dir() || current.dev() != published.dev() || current.ino() != published.ino() {
        return Ok(false);
    }
    let mut moves = Vec::new();
    if let Err(error) = restore_preview(profile, name, &marker, &mut moves) {
        rollback_moves(&moves)?;
        return Err(error);
    }
    std::fs::remove_dir_all(&marker)?;
    std::fs::File::open(marker.parent().unwrap())?.sync_all()?;
    root.sync_all()?;
    Ok(true)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn preview_paths(name: &str, manifest: &Value) -> Result<Vec<(&'static str, PathBuf)>> {
    let version = manifest["package"]["version"].as_str().unwrap_or("");
    if manifest["package"]["name"] != name
        || name.split('/').any(|part| {
            part.is_empty()
                || !part.as_bytes()[0].is_ascii_lowercase()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || version.is_empty()
        || version.len() > 128
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
    {
        return Err(Error::new(
            "E_ARTIFACT_INVALID",
            "Invalid preview package name or version",
        ));
    }
    let lib = if crate::identity::is_standard_author(
        manifest["package"]["author"].as_str().unwrap_or(""),
    ) && !name.starts_with("std/")
    {
        "lib/std"
    } else {
        "lib"
    };
    Ok(vec![
        ("lib", PathBuf::from(format!("{lib}/{name}.wasm.{version}"))),
        ("app", PathBuf::from(format!("app/{name}.{version}"))),
        ("app_link", PathBuf::from(format!("app/{name}"))),
    ])
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn move_resource(from: &Path, to: &Path, moves: &mut Vec<(PathBuf, PathBuf)>) -> Result<()> {
    std::fs::rename(from, to)?;
    moves.push((from.to_owned(), to.to_owned()));
    std::fs::File::open(from.parent().unwrap())?.sync_all()?;
    std::fs::File::open(to.parent().unwrap())?.sync_all()?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rollback_moves(moves: &[(PathBuf, PathBuf)]) -> Result<()> {
    for (from, to) in moves.iter().rev() {
        std::fs::rename(to, from)?;
        std::fs::File::open(from.parent().unwrap())?.sync_all()?;
        std::fs::File::open(to.parent().unwrap())?.sync_all()?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn published_paths(
    name: &str,
    manifest: &Value,
    state: &Value,
) -> Result<Vec<(&'static str, PathBuf)>> {
    let mut paths = preview_paths(name, manifest)?;
    if state["layout"] != "versions" {
        let version = manifest["package"]["version"].as_str().unwrap();
        let lib = if crate::identity::is_standard_author(
            manifest["package"]["author"].as_str().unwrap_or(""),
        ) && !name.starts_with("std/")
        {
            "lib/std"
        } else {
            "lib"
        };
        paths = vec![
            ("lib", PathBuf::from(format!("{lib}/{name}_{version}.wasm"))),
            ("app", PathBuf::from(format!("app/{name}"))),
        ];
    }
    Ok(paths)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_published_files(profile: &Path, name: &str, published: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let replaced = || {
        Error::new(
            "E_DEV_REPLACED",
            "Published resources were taken over; restart jade run to start a new preview.",
        )
    };
    let owner = profile.metadata()?;
    let marker = profile.join(format!("lib/{name}.preview"));
    let current = marker.symlink_metadata().map_err(|_| replaced())?;
    let previous = published.metadata()?;
    if !current.is_dir() || current.dev() != previous.dev() || current.ino() != previous.ino() {
        return Err(replaced());
    }
    let manifest: Value = serde_json::from_reader(private_resource(
        &marker.join("manifest.json"),
        &owner,
        false,
    )?)
    .map_err(|error| Error::new("E_ARTIFACT_INVALID", error))?;
    let state: Value =
        serde_json::from_reader(private_resource(&marker.join("state.json"), &owner, false)?)
            .map_err(|error| Error::new("E_ARTIFACT_INVALID", error))?;
    for (kind, relative) in published_paths(name, &manifest, &state)? {
        if state[kind].is_null() {
            continue;
        }
        let current = profile
            .join(relative)
            .symlink_metadata()
            .map_err(|_| replaced())?;
        if state[kind]["dev"].as_u64() != Some(current.dev())
            || state[kind]["ino"].as_u64() != Some(current.ino())
        {
            return Err(replaced());
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn restore_preview(
    profile: &Path,
    name: &str,
    marker: &Path,
    moves: &mut Vec<(PathBuf, PathBuf)>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let owner = profile.metadata()?;
    private_directory(marker, &owner)?;
    let manifest: Value = serde_json::from_reader(private_resource(
        &marker.join("manifest.json"),
        &owner,
        false,
    )?)
    .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
    let state: Value =
        serde_json::from_reader(private_resource(&marker.join("state.json"), &owner, false)?)
            .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
    let paths = published_paths(name, &manifest, &state)?;
    for (kind, relative) in paths {
        if state[kind].is_null() {
            continue;
        }
        package_directory(
            profile,
            relative.parent().unwrap().to_str().unwrap(),
            &owner,
        )?;
        let path = profile.join(&relative);
        let current = match path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        // A later watcher or formal installer owns a different inode.
        if state[kind]["dev"].as_u64() != Some(current.dev())
            || state[kind]["ino"].as_u64() != Some(current.ino())
        {
            continue;
        }
        preview_resource(&path, &owner, kind, name)?;
        move_resource(&path, &marker.join(format!("retired-{kind}")), moves)?;
        let previous = marker.join(format!("previous-{kind}"));
        if previous.try_exists()? {
            preview_resource(&previous, &owner, kind, name)?;
            move_resource(&previous, &path, moves)?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn preview_resource(path: &Path, owner: &std::fs::Metadata, kind: &str, name: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = path.symlink_metadata()?;
    if kind == "app_link" && metadata.file_type().is_symlink() {
        let target = std::fs::read_link(path)?;
        let leaf = name.rsplit('/').next().unwrap();
        let valid = target
            .to_str()
            .and_then(|target| target.strip_prefix(&format!("{leaf}.")))
            .is_some_and(|version| {
                !version.is_empty()
                    && version.len() <= 128
                    && version.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+')
                    })
            });
        if !valid || metadata.uid() != owner.uid() || metadata.dev() != owner.dev() {
            return Err(Error::new(
                "E_OUTPUT_CONFLICT",
                "Invalid preview frontend link",
            ));
        }
    } else {
        private_resource(path, owner, kind != "lib")?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn private_resource(
    path: &Path,
    owner: &std::fs::Metadata,
    directory: bool,
) -> Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt;
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::NONBLOCK
        | rustix::fs::OFlags::CLOEXEC;
    let file = std::fs::File::from(
        rustix::fs::open(path, flags, rustix::fs::Mode::empty()).map_err(std::io::Error::from)?,
    );
    let metadata = file.metadata()?;
    if metadata.uid() != owner.uid()
        || metadata.dev() != owner.dev()
        || metadata.mode() & 0o022 != 0
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
    {
        return Err(Error::new(
            "E_OUTPUT_CONFLICT",
            "Preview resources must be owned regular files and directories",
        ));
    }
    Ok(file)
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
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
    published: Option<&std::fs::File>,
) -> Result<(Value, std::fs::File)> {
    use std::{
        fs::File,
        io::Write,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };
    let owner = profile.metadata()?;
    let root = private_directory(profile, &owner)?;
    rustix::fs::flock(&root, rustix::fs::FlockOperation::LockExclusive)
        .map_err(std::io::Error::from)?;
    if let Some(published) = published {
        verify_published_files(profile, name, published)?;
    }
    let staged = tempfile::Builder::new()
        .prefix(".jade-")
        .tempdir_in(profile)?;
    let has_api = crate::archive::waz_backend(files).is_some();
    let has_app = files.contains_key("public/index.html") || files.contains_key("web/index.html");
    let preview_manifest = serde_json::to_vec(
        &crate::archive::waz_manifest(files).map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?,
    )
    .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
    for (source, content) in files {
        let bytes = if source == "manifest.toml" {
            &preview_manifest
        } else {
            content
        };
        let target = if source == "manifest.json" || source == "manifest.toml" {
            Some("manifest.json".to_owned())
        } else if source == "backend.wasm" || source.starts_with("wasm/") {
            Some("lib.wasm".to_owned())
        } else {
            source
                .strip_prefix(if files.contains_key("manifest.toml") {
                    "web/"
                } else {
                    "public/"
                })
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
    rustix::fs::flock(&_data, rustix::fs::FlockOperation::LockExclusive)
        .map_err(std::io::Error::from)?;
    let manifest =
        crate::archive::waz_manifest(files).map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
    let standard =
        crate::identity::is_standard_author(manifest["package"]["author"].as_str().unwrap_or(""));
    let data_root = if standard && !name.starts_with("std/") {
        let standard = data_root.join("std");
        private_directory(&standard, &owner)?;
        standard
    } else {
        data_root
    };
    let data = data_root.join(name);
    package_directory(
        &data_root,
        name.rsplit_once('/').map_or("", |(parent, _)| parent),
        &owner,
    )?;
    if !data.try_exists()? {
        let legacy_name = if standard {
            name.strip_prefix("std/").unwrap_or(name)
        } else {
            name
        };
        let legacy_root = if standard {
            profile.join(".volume/std")
        } else {
            data_root.clone()
        };
        let mut legacy = vec![legacy_root.join(legacy_name.replace('/', "%2F"))];
        if standard && legacy_name == "comm/message" {
            legacy.push(legacy_root.join("message"));
        }
        let legacy = legacy
            .into_iter()
            .filter(|path| path != &data && path.try_exists().unwrap_or(true))
            .collect::<Vec<_>>();
        if legacy.len() > 1 {
            return Err(Error::new(
                "E_OUTPUT_CONFLICT",
                "Multiple previous data directories require reconciliation",
            ));
        }
        if let Some(previous) = legacy.first() {
            private_directory(previous, &owner)?;
            std::fs::rename(previous, &data)?;
            std::fs::File::open(previous.parent().unwrap())?.sync_all()?;
            std::fs::File::open(data.parent().unwrap())?.sync_all()?;
        }
    }
    if fresh && data.try_exists()? {
        let _ = private_directory(&data, &owner)?;
        let previous = tempfile::Builder::new()
            .prefix(&format!(".{}-previous-", name.replace('/', "%2F")))
            .tempdir_in(&data_root)?
            .keep();
        std::fs::rename(&data, &previous)?;
    }
    let _ = private_directory(&data, &owner)?;
    let marker_relative = format!("lib/{name}.preview");
    let marker = profile.join(&marker_relative);
    let parent = package_directory(
        profile,
        Path::new(&marker_relative)
            .parent()
            .unwrap()
            .to_str()
            .unwrap(),
        &owner,
    )?;
    let paths = preview_paths(name, &manifest)?;
    let mut moves = Vec::new();
    let mut exchanged = false;
    let result = (|| -> Result<std::fs::File> {
        let exists = marker.try_exists()?;
        if exists {
            restore_preview(profile, name, &marker, &mut moves)?;
        } else if marker.symlink_metadata().is_ok() {
            return Err(Error::new(
                "E_OUTPUT_CONFLICT",
                "Preview marker must be an owned directory",
            ));
        }
        let mut state = json!({"layout":"versions"});
        if has_app {
            let version = manifest["package"]["version"].as_str().unwrap();
            let leaf = name.rsplit('/').next().unwrap();
            let link = staged.path().join("app-link");
            std::os::unix::fs::symlink(format!("{leaf}.{version}"), &link)?;
            if unsafe { libc::geteuid() } == 0 {
                rustix::fs::chownat(
                    rustix::fs::CWD,
                    &link,
                    Some(rustix::fs::Uid::from_raw(owner.uid())),
                    Some(rustix::fs::Gid::from_raw(owner.gid())),
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(std::io::Error::from)?;
            }
        }
        for (kind, relative) in paths {
            if (kind == "lib" && !has_api) || (kind != "lib" && !has_app) {
                continue;
            }
            package_directory(
                profile,
                relative.parent().unwrap().to_str().unwrap(),
                &owner,
            )?;
            let path = profile.join(relative);
            match path.symlink_metadata() {
                Ok(_) => {
                    preview_resource(&path, &owner, kind, name)?;
                    move_resource(
                        &path,
                        &staged.path().join(format!("previous-{kind}")),
                        &mut moves,
                    )?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let source = staged.path().join(match kind {
                "lib" => "lib.wasm",
                "app" => "app",
                _ => "app-link",
            });
            move_resource(&source, &path, &mut moves)?;
            let metadata = path.symlink_metadata()?;
            state[kind] = json!({"dev":metadata.dev(),"ino":metadata.ino()});
        }
        let state_path = staged.path().join("state.json");
        std::fs::write(
            &state_path,
            serde_json::to_vec(&state).map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?,
        )?;
        own(&state_path, &owner)?;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))?;
        File::open(&state_path)?.sync_all()?;
        let published = File::open(staged.path())?;
        published.sync_all()?;
        if exists {
            rustix::fs::renameat_with(
                &root,
                staged.path().file_name().unwrap(),
                &parent,
                marker.file_name().unwrap(),
                rustix::fs::RenameFlags::EXCHANGE,
            )
            .map_err(std::io::Error::from)?;
            exchanged = true;
        } else {
            move_resource(staged.path(), &marker, &mut moves)?;
        }
        parent.sync_all()?;
        root.sync_all()?;
        Ok(published)
    })();
    match result {
        Ok(published) => Ok((
            json!({"name":name,"directory":marker,"data_directory":data,"has_api":has_api,"has_app":has_app}),
            published,
        )),
        Err(error) => {
            let rollback = (|| -> Result<()> {
                if exchanged {
                    rustix::fs::renameat_with(
                        &root,
                        staged.path().file_name().unwrap(),
                        &parent,
                        marker.file_name().unwrap(),
                        rustix::fs::RenameFlags::EXCHANGE,
                    )
                    .map_err(std::io::Error::from)?;
                }
                rollback_moves(&moves)
            })();
            if let Err(rollback_error) = rollback {
                let recovery = staged.keep();
                return Err(Error::new("E_DEV_CLEANUP", rollback_error)
                    .context(json!({"directory":recovery,"publication_error":error.json()})));
            }
            Err(error)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn package_directory(
    root: &Path,
    relative: &str,
    owner: &std::fs::Metadata,
) -> Result<std::fs::File> {
    let mut path = root.to_path_buf();
    let mut directory = private_directory(&path, owner)?;
    for part in Path::new(relative).components() {
        let std::path::Component::Normal(part) = part else {
            return Err(Error::new("E_CONFIG_INVALID", "Invalid package directory"));
        };
        path.push(part);
        directory = private_directory(&path, owner)?;
    }
    Ok(directory)
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

// Local paths resolve against the manifest that declares them, including nested dependencies.
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn projects(root: &Path, host: &str) -> Result<(BTreeMap<String, PathBuf>, Vec<Value>)> {
    let (_, manifest) = crate::project::read_manifest(root)?;
    if let Some(author) = manifest.package.author
        && crate::identity::normalize(&author)? != host
    {
        return Err(Error::new(
            "E_IDENTITY_MISMATCH",
            "The project author changed while running",
        )
        .hint("Restart jade run after changing package.author to use the new identity."));
    }
    fn visit(
        path: &Path,
        active: &mut Vec<PathBuf>,
        locals: &mut BTreeMap<String, PathBuf>,
        remote: &mut BTreeMap<(String, String), Value>,
    ) -> Result<()> {
        let (root, manifest) = crate::project::read(path)?;
        if active.contains(&root) {
            return Err(Error::new("E_CONFIG_INVALID", "Local dependency cycle"));
        }
        let name = &manifest.package.name;
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
            if let Some(path) = &dependency.path {
                let path = root.join(path);
                let (_, local) = crate::project::read(&path)?;
                if local.package.name != dependency.name
                    || local.package.version != dependency.version
                {
                    return Err(Error::new(
                        "E_CONFIG_INVALID",
                        format!(
                            "Local dependency {} does not match name/version",
                            dependency.name
                        ),
                    ));
                }
                visit(&path, active, locals, remote)?;
            } else {
                remote.insert(
                    (dependency.name.clone(), dependency.version.clone()),
                    json!({"name":dependency.name,"version":dependency.version}),
                );
            }
        }
        active.pop();
        locals.insert(name.clone(), root);
        Ok(())
    }
    let mut locals = BTreeMap::new();
    let mut remote = BTreeMap::new();
    visit(root, &mut Vec::new(), &mut locals, &mut remote)?;
    Ok((locals, remote.into_values().collect()))
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn graph_fingerprint(projects: &BTreeMap<String, PathBuf>) -> Result<Vec<u8>> {
    let mut digest = Sha256::new();
    for (name, path) in projects {
        digest.update(name.as_bytes());
        digest.update(path.as_os_str().as_encoded_bytes());
        digest.update(source_fingerprint(path)?);
    }
    Ok(digest.finalize().to_vec())
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
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
            if installed["name"] != dependency["name"]
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

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
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
