//! Build unsigned snapshots for an authenticated, temporary local Pishoo session.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

use crate::error::{Error, Result};

pub(super) async fn run(
    path: PathBuf,
    id: Option<String>,
    watch: bool,
    fresh: bool,
    machine: bool,
) -> Result<Value> {
    #[cfg(not(unix))]
    {
        let _ = (path, id, watch, fresh, machine);
        return Err(Error::new(
            "E_DEV_UNSUPPORTED",
            "Local Pishoo development requires a Unix host",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let home = crate::identity::home()?;
        let host = select_host(&home, id.as_deref(), machine).await?;
        let profile = home
            .resolve_identity_profile_exactly(&host)
            .await
            .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
        let profile_path = profile.path().canonicalize()?;
        let owner = std::fs::metadata(&profile_path)?;
        let hash = format!(
            "{:x}",
            Sha256::digest(profile_path.as_os_str().as_encoded_bytes())
        );
        let socket = PathBuf::from(format!(
            "/tmp/pishoo-dev-{}/{}.sock",
            owner.uid(),
            &hash[..32]
        ));
        let unavailable = |error: &dyn std::fmt::Display| {
            Error::new("E_DEV_HOST_UNAVAILABLE", error)
            .hint(format!("Start a Pishoo version with jade run support, then enable the test identity with genmeta listen --id {host} internal."))
        };
        let directory =
            std::fs::symlink_metadata(socket.parent().unwrap()).map_err(|e| unavailable(&e))?;
        let endpoint = std::fs::symlink_metadata(&socket).map_err(|e| unavailable(&e))?;
        if !directory.file_type().is_dir()
            || directory.uid() != owner.uid()
            || directory.mode() & 0o077 != 0
            || !endpoint.file_type().is_socket()
        {
            return Err(Error::new(
                "E_DEV_HOST_UNAVAILABLE",
                "The local Pishoo control socket is not private to the host owner",
            ));
        }
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|e| unavailable(&e))?;
        let peer = stream.peer_cred()?;
        if peer.uid() != owner.uid() && peer.uid() != 0 {
            return Err(Error::new(
                "E_DEV_HOST_UNAVAILABLE",
                "Unexpected local Pishoo process owner",
            ));
        }
        let (project, config) = crate::project::read(&path)?;
        let project_id = format!(
            "{:x}",
            Sha256::digest(project.as_os_str().as_encoded_bytes())
        );
        let opened = exchange(
            &mut stream,
            &json!({"op":"open","project":project_id,"name":config.package.name,"fresh":fresh}),
        )
        .await?;
        if opened["protocol"] != "jade-dev/1"
            || opened["host"] != host
            || opened["name"] != config.package.name
        {
            return Err(Error::new(
                "E_DEV_HOST_UNAVAILABLE",
                "Pishoo returned an incompatible development session",
            ));
        }
        event(machine, "connected", &opened);
        let mut revision = 0u64;
        let mut previous = None;
        let mut last_watch_error = None;
        loop {
            let fingerprint = match tokio::task::block_in_place(|| source_fingerprint(&project)) {
                Ok(fingerprint) => {
                    last_watch_error = None;
                    fingerprint
                }
                Err(error) if watch => {
                    if last_watch_error.as_deref() != Some(error.message.as_str()) {
                        event(machine, "not_applied", &json!({"error":error.json()}));
                        last_watch_error = Some(error.message);
                    }
                    wait_for_changes(&mut stream).await?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if previous.as_ref() != Some(&fingerprint) {
                previous = Some(fingerprint.clone());
                revision = revision
                    .checked_add(1)
                    .ok_or_else(|| Error::new("E_INTERNAL", "Development revision overflow"))?;
                event(machine, "building", &json!({"revision":revision}));
                let candidate = snapshot(&path, &host).await;
                // A source change during compilation schedules a fresh build; stale output is not loaded.
                let after = match tokio::task::block_in_place(|| source_fingerprint(&project)) {
                    Ok(fingerprint) => fingerprint,
                    Err(error) if watch => {
                        previous = None;
                        event(machine, "not_applied", &json!({"error":error.json()}));
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if after != fingerprint {
                    event(
                        machine,
                        "changed_during_build",
                        &json!({"revision":revision}),
                    );
                    continue;
                }
                let loaded = match candidate {
                    Ok(bytes) => exchange(
                        &mut stream,
                        &json!({"op":"load","revision":revision,"snapshot":STANDARD.encode(bytes)}),
                    )
                    .await,
                    Err(error) => Err(error),
                };
                match loaded {
                    Ok(result) => event(machine, "loaded", &result),
                    Err(error) if watch && error.code != "E_DEV_CONNECTION" => {
                        event(
                            machine,
                            "not_applied",
                            &json!({"revision":revision,"error":error.json(),"message":"Changes are not active; the previous loaded revision remains available."}),
                        );
                    }
                    Err(error) => return Err(error),
                }
                if !watch {
                    // The control connection owns the session. --no-watch still serves until cancelled.
                    let result = stream.read_u8().await;
                    return Err(Error::new(
                        "E_DEV_CONNECTION",
                        match result {
                            Ok(_) => "Unexpected Pishoo response".to_owned(),
                            Err(error) => error.to_string(),
                        },
                    ));
                }
            }
            wait_for_changes(&mut stream).await?;
        }
    }
}

async fn select_host(
    home: &dhttp_home::DhttpHome,
    explicit: Option<&str>,
    machine: bool,
) -> Result<String> {
    use std::io::IsTerminal;

    use futures::StreamExt;
    if let Some(name) = explicit {
        return crate::identity::normalize(name);
    }
    if home.settings_path().try_exists()? {
        let settings = home
            .load_settings()
            .await
            .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
        if let Some(name) = settings.settings().default_identity_name() {
            return Ok(name.as_full().to_owned());
        }
    }
    let names = home.identity_profile_names();
    futures::pin_mut!(names);
    let mut candidates = Vec::new();
    while let Some(name) = names.next().await {
        candidates.push(name.map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?);
    }
    candidates.sort();
    candidates.dedup();
    if candidates.len() == 1 {
        return Ok(candidates.remove(0));
    }
    if candidates.is_empty() || machine || !std::io::stdin().is_terminal() {
        return Err(Error::new("E_IDENTITY_REQUIRED", "Select a local Pishoo test identity")
            .hint("Run jade run --id HOST. A normal host identity is sufficient; a developer certificate is not required."));
    }
    inquire::Select::new("Run on local Pishoo identity:", candidates)
        .prompt()
        .map_err(|e| Error::new("E_CANCELLED", e))
}

async fn snapshot(path: &Path, host: &str) -> Result<Vec<u8>> {
    let (project, config) = crate::project::read(path)?;
    let author = crate::identity::normalize(config.package.author.as_deref().unwrap_or(host))?;
    let files = crate::pack::build_files(
        &project,
        &config,
        &author,
        &project
            .join(crate::project::BUILD_DIR)
            .join(".development-snapshot"),
    )
    .await?;
    crate::archive::waz_write(&files).map_err(|e| Error::new("E_ARTIFACT_INVALID", e))
}

#[cfg(unix)]
async fn wait_for_changes(stream: &mut UnixStream) -> Result<()> {
    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => Ok(()),
        disconnected = stream.read_u8() => Err(Error::new("E_DEV_CONNECTION", match disconnected {
            Ok(_) => "Unexpected Pishoo response".to_owned(),
            Err(error) => error.to_string(),
        })),
    }
}

#[cfg(unix)]
async fn exchange(stream: &mut UnixStream, request: &Value) -> Result<Value> {
    let bytes = serde_json::to_vec(request).map_err(|e| Error::new("E_INTERNAL", e))?;
    if bytes.len() > 92 * 1024 * 1024 {
        return Err(Error::new(
            "E_ARTIFACT_INVALID",
            "Development snapshot exceeds its size limit",
        ));
    }
    async {
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        let length = stream.read_u32().await? as usize;
        if length == 0 || length > 64 * 1024 {
            return Err(std::io::Error::other(
                "Pishoo response exceeds its size limit",
            ));
        }
        let mut response = vec![0; length];
        stream.read_exact(&mut response).await?;
        Ok(response)
    }
    .await
    .map_err(|e: std::io::Error| Error::new("E_DEV_CONNECTION", e))
    .and_then(|bytes| {
        let response: Value =
            serde_json::from_slice(&bytes).map_err(|e| Error::new("E_DEV_CONNECTION", e))?;
        match response["status"].as_str() {
            Some("ok") => Ok(response["result"].clone()),
            Some("error") => Err(Error::new(
                "E_DEV_REJECTED",
                response["message"]
                    .as_str()
                    .unwrap_or("Pishoo rejected the development snapshot"),
            )),
            _ => Err(Error::new("E_DEV_CONNECTION", "Invalid Pishoo response")),
        }
    })
}

fn event(machine: bool, state: &str, value: &Value) {
    if machine {
        eprintln!("{}", json!({"command":"run","event":state,"result":value}));
        return;
    }
    match state {
        "connected" => eprintln!(
            "Connected Pishoo · {}\nTest data {}",
            value["host"].as_str().unwrap_or(""),
            value["data_directory"].as_str().unwrap_or("")
        ),
        "building" => eprintln!("Building  revision {}", value["revision"]),
        "loaded" => {
            eprintln!(
                "Loaded    {} · revision {}",
                value["id"].as_str().unwrap_or(""),
                value["revision"]
            );
            for (key, label) in [("api", "API"), ("app", "App")] {
                if let Some(url) = value[key].as_str() {
                    eprintln!("{label}       {url}");
                }
            }
            if let (Some(host), Some(example)) = (value["host"].as_str(), value["example"].as_str())
            {
                eprintln!("Try       genmeta curl --id {host} {example}");
            }
        }
        "not_applied" => eprintln!(
            "Changes not applied: {}\nThe previous loaded revision remains available.",
            value["error"]["message"]
                .as_str()
                .unwrap_or("build or load failed")
        ),
        "changed_during_build" => {
            eprintln!("Source changed during build; rebuilding before loading.")
        }
        _ => {}
    }
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
