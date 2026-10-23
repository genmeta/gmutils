//! Build declared sources, collect immutable artifacts and sign Pishoo packages.
use std::{
    collections::{BTreeMap, HashSet},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use webc::v3::{
    SignatureAlgorithm, Timestamps,
    write::{DirEntry, Directory, FileEntry, Writer},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(super) async fn run(
    path: PathBuf,
    requested_output: Option<PathBuf>,
    id: Option<String>,
    overwrite: bool,
    machine: bool,
) -> crate::error::Result<Value> {
    use crate::error::Error;
    let (project, config) = crate::project::read(&path)?;
    let author =
        crate::identity::select(id.as_deref(), config.package.author.as_deref(), machine).await?;
    let (mut wapm, annotation) = config.metadata(&author)?;
    validate_metadata(&wapm, &annotation, config.backend.is_some())
        .map_err(|e| Error::new("E_CONFIG_INVALID", e))?;
    let id = text(&wapm, "name")
        .map_err(|e| Error::new("E_CONFIG_INVALID", e))?
        .to_owned();
    let name = &config.package.name;
    let version = &config.package.version;
    let default_output = requested_output.is_none();
    let output = requested_output.unwrap_or_else(|| {
        project
            .join(crate::project::BUILD_DIR)
            .join(format!("{name}-{version}.waz"))
    });
    reject_url(output.as_os_str()).map_err(|e| Error::new("E_CONFIG_INVALID", e))?;
    let output = resolved_output(&output).map_err(|e| Error::new("E_OUTPUT_CONFLICT", e))?;
    // Keep legacy build artifacts out of root-level static projects after upgrading.
    let excluded = [
        project.join(crate::project::BUILD_DIR),
        project.join(".jade"),
    ];
    let directory = match &config.frontend {
        Some(frontend) => Some(crate::project::frontend(&project, frontend).await?),
        None => None,
    };
    let backend = match &config.backend {
        Some(backend) => crate::project::backend(&project, backend, &config.package).await?,
        None => Vec::new(),
    };
    if !backend.is_empty() {
        crate::project::validate_component(&backend, version, &author, name)?;
    }
    let parent = output
        .parent()
        .ok_or_else(|| Error::new("E_OUTPUT_CONFLICT", "Missing output directory"))?;
    if let Some(directory) = &directory {
        if !excluded.iter().any(|path| output.starts_with(path)) {
            ensure_outside_mapping(&output, parent, directory)
                .map_err(|e| Error::new("E_OUTPUT_CONFLICT", e))?;
        }
        if excluded.iter().any(|path| directory.starts_with(path)) {
            return Err(Error::new(
                "E_ARTIFACT_INVALID",
                "Frontend resources cannot be in Jade's output directory",
            ));
        }
    }
    let mut count = 1;
    let mut remaining = 64 * 1024 * 1024 - backend.len();
    let mut documents = BTreeMap::new();
    let mut excluded_content = excluded.to_vec();
    for name in ["README.md", "CHANGELOG.md"] {
        let path = project.join(name);
        excluded_content.push(path.clone());
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(Error::new("E_ARTIFACT_INVALID", error)),
        }
        let bytes = read_bounded(&path, (16 * 1024 * 1024).min(remaining))
            .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
        remaining -= bytes.len();
        count += 1;
        documents.insert(
            name.parse().map_err(|e| Error::new("E_INTERNAL", e))?,
            DirEntry::File(FileEntry::owned(bytes, Timestamps::default())),
        );
        if name == "README.md" {
            wapm["readme"] = json!({"volume":"metadata","path":"/README.md"});
        }
    }
    let documents =
        (!documents.is_empty()).then(|| Directory::new(documents, Timestamps::default()));
    let content = directory
        .as_ref()
        .map(|directory| {
            public_directory(
                directory,
                "",
                &mut count,
                &mut remaining,
                0,
                &excluded_content,
            )
        })
        .transpose()
        .map_err(|e| Error::new("E_ARTIFACT_INVALID", e))?;
    let home = crate::identity::home()?;
    let (certificates, private_key) = crate::identity::credentials(&home, &author).await?;
    let owner = crate::package::owner_hash(&certificates)
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    let signing_key = qtls::default_provider()
        .key_provider
        .load_private_key(private_key)
        .map_err(|e| Error::new("E_IDENTITY_UNAVAILABLE", e))?;
    eprintln!("   Signing  {}", crate::display::identity(&author));
    let bytes = encode(
        &wapm,
        &annotation,
        &backend,
        content,
        documents,
        &certificates,
        &signing_key,
    )
    .map_err(|e| Error::new("E_SIGNATURE_INVALID", e))?;
    crate::package::inspect_package(&bytes).await?;
    std::fs::create_dir_all(parent)?;
    let parent = std::fs::canonicalize(parent)?;
    let output = parent.join(output.file_name().unwrap());
    // One stable inode per output directory also covers case-insensitive names.
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let lock = options
        .open(parent.join(".jade-write.lock"))
        .map_err(|e| Error::new("E_OUTPUT_CONFLICT", e))?;
    if !lock.metadata()?.is_file() {
        return Err(Error::new(
            "E_OUTPUT_CONFLICT",
            "Output lock is not a regular file",
        ));
    }
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(Error::new("E_OUTPUT_CONFLICT", error));
            }
        }
    }
    let replacing = match std::fs::symlink_metadata(&output) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(Error::new(
                    "E_OUTPUT_CONFLICT",
                    "Output is not a regular file",
                ));
            }
            if default_output {
                let existing = crate::package::read_snapshot(&output)
                    .await
                    .map_err(|e| Error::new("E_OUTPUT_CONFLICT", e))?;
                let previous = crate::package::inspect_package(&existing)
                    .await
                    .map_err(|e| {
                        Error::new("E_OUTPUT_CONFLICT", e)
                            .hint("Choose a different output file with -o")
                    })?;
                let old_owner = crate::package::package_certificates(&existing)
                    .and_then(|c| crate::package::owner_hash(&c))
                    .map_err(|e| Error::new("E_OUTPUT_CONFLICT", e))?;
                if previous["id"] != id || previous["version"] != *version || old_owner != owner {
                    return Err(Error::new(
                        "E_OUTPUT_CONFLICT",
                        "Existing output belongs to another package, version or owner",
                    )
                    .hint("Choose a different output file with -o"));
                }
            } else if !overwrite {
                return Err(Error::new(
                    "E_OUTPUT_CONFLICT",
                    format!("Output already exists: {}", output.display()),
                )
                .hint("Use --overwrite to replace this explicit output"));
            }
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let mut temporary = tempfile::NamedTempFile::new_in(&parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    if replacing {
        if !std::fs::symlink_metadata(&output)?.is_file() {
            return Err(Error::new(
                "E_OUTPUT_CONFLICT",
                "Output type changed before replacement",
            ));
        }
        temporary
            .persist(&output)
            .map_err(|e| Error::new("E_OUTPUT_CONFLICT", e.error))?;
    } else {
        temporary
            .persist_noclobber(&output)
            .map_err(|e| Error::new("E_OUTPUT_CONFLICT", e.error))?;
    }
    #[cfg(unix)]
    std::fs::File::open(&parent)?.sync_all()?;
    Ok(
        json!({"id":id,"version":version,"file":output,"size":bytes.len(),
        "package_sha256":crate::package::digest(&bytes),
        "payload_sha256":crate::package::payload_digest(&bytes).map_err(|e|Error::new("E_INTERNAL",e))?}),
    )
}

fn encode(
    wapm: &Value,
    annotation: &Value,
    backend: &[u8],
    content: Option<Directory<'static>>,
    documents: Option<Directory<'static>>,
    certificates: &[qtls::CertificateDer<'_>],
    signing_key: &std::sync::Arc<dyn rustls::sign::SigningKey>,
) -> Result<Vec<u8>> {
    let has_frontend = content.is_some();
    let mut manifest: webc::metadata::Manifest = serde_json::from_value(json!({
        "package":{"wapm":wapm,"pishoo":annotation,"fs":if has_frontend {json!([{"volume_name":"public","mount_path":"/public"}])} else {json!([])}},
        "atoms":{"backend":{"kind":"https://webc.org/kind/wasm","signature":format!("sha256:{}",STANDARD.encode(Sha256::digest(backend)))}}
    }))?;
    if backend.is_empty() {
        manifest.atoms.clear();
    }
    let atoms = || -> Result<_> {
        Ok(if backend.is_empty() {
            BTreeMap::new()
        } else {
            BTreeMap::from([(
                "backend".parse()?,
                FileEntry::borrowed(backend, Timestamps::default()),
            )])
        })
    };
    let mut writer = Writer::default()
        .write_manifest(&manifest)?
        .write_atoms(atoms()?)?;
    if let Some(content) = content {
        writer.write_volume("public", content)?;
    }
    if let Some(documents) = documents {
        writer.write_volume("metadata", documents)?;
    }
    let unsigned = writer.finish(SignatureAlgorithm::None)?;
    let container = webc::Container::from_bytes_and_version(unsigned.clone(), webc::Version::V3)?;
    let mut files = crate::archive::waz_export(&container)
        .map_err(|error| -> Box<dyn std::error::Error> { error })?;
    let digest = crate::archive::waz_payload(&files);
    let mut input = b"pishoo-waz-signature-v1\0".to_vec();
    for offset in (0..digest.len()).step_by(2) {
        input.push(u8::from_str_radix(&digest[offset..offset + 2], 16)?);
    }
    let mut signature = None;
    for scheme in [
        qtls::SignatureScheme::RSA_PSS_SHA512,
        qtls::SignatureScheme::ECDSA_NISTP256_SHA256,
        qtls::SignatureScheme::ECDSA_NISTP384_SHA384,
        qtls::SignatureScheme::ED25519,
    ] {
        if let Some(signer) = signing_key.choose_scheme(&[scheme]) {
            signature = Some(signer.sign(&input)?);
            break;
        }
    }
    let envelope = json!({"version":1,
        "certificates":certificates.iter().map(|c|STANDARD.encode(c.as_ref())).collect::<Vec<_>>(),
        "signature":STANDARD.encode(signature.ok_or("unsupported signing key")?)});
    files.insert(
        "signature.json".into(),
        serde_json::to_vec_pretty(&envelope)?,
    );
    let bytes = crate::archive::waz_write(&files)
        .map_err(|error| -> Box<dyn std::error::Error> { error })?;
    if crate::package::payload_digest(&bytes)? != digest {
        return Err("final package content differs from signed payload".into());
    }
    Ok(bytes)
}

pub(crate) fn embedded_openapi(mut backend: Vec<u8>, source: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut offset = 8;
    let mut embedded = None;
    while offset < backend.len() {
        let section = backend[offset];
        let (size, start) = wasm_length(&backend, offset + 1)?;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= backend.len())
            .ok_or("truncated WASM section")?;
        if section == 0 {
            let (length, name_start) = wasm_length(&backend[..end], start)?;
            let name_end = name_start
                .checked_add(length)
                .filter(|name_end| *name_end <= end)
                .ok_or("invalid WASM custom section name")?;
            let name = backend
                .get(name_start..name_end)
                .ok_or("truncated custom section name")?;
            if name == b"pishoo:signature" {
                return Err("backend must not contain a second publisher signature".into());
            }
            if name == b"pishoo:openapi" {
                if embedded.is_some() || end - name_end > 1024 * 1024 {
                    return Err("duplicate or oversized embedded OpenAPI".into());
                }
                embedded = Some(name_end..end);
            }
        }
        offset = end;
    }
    let document = embedded
        .as_ref()
        .map(|range| &backend[range.clone()])
        .or(source)
        .ok_or("missing build artifact: embedded OpenAPI or /metadata/openapi.json")?;
    if let (Some(range), Some(source)) = (embedded.as_ref(), source)
        && backend[range.clone()] != *source
    {
        return Err("embedded OpenAPI differs from metadata/openapi.json".into());
    }
    let parsed: Value = serde_json::from_slice(document)?;
    if document.len() > 1024 * 1024
        || !parsed["openapi"]
            .as_str()
            .is_some_and(|v| v.starts_with("3.1."))
        || !parsed["paths"].is_object()
    {
        return Err("OpenAPI must be a bounded 3.1.x document with paths".into());
    }
    if embedded.is_none() {
        let name = b"pishoo:openapi";
        let mut payload = Vec::new();
        wasm_write_length(name.len(), &mut payload);
        payload.extend_from_slice(name);
        payload.extend_from_slice(document);
        backend.push(0);
        wasm_write_length(payload.len(), &mut backend);
        backend.extend_from_slice(&payload);
    }
    if backend.len() > 64 * 1024 * 1024 {
        return Err("backend with embedded OpenAPI exceeds 64 MiB".into());
    }
    Ok(backend)
}

fn wasm_length(bytes: &[u8], mut offset: usize) -> Result<(usize, usize)> {
    let mut length = 0usize;
    for shift in (0..35).step_by(7) {
        let byte = *bytes.get(offset).ok_or("truncated WASM length")?;
        offset += 1;
        if shift == 28 && byte & 0xf0 != 0 {
            return Err("WASM length overflow".into());
        }
        length |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((length, offset));
        }
    }
    Err("WASM length overflow".into())
}

fn wasm_write_length(mut length: usize, bytes: &mut Vec<u8>) {
    while length >= 0x80 {
        bytes.push((length as u8 & 0x7f) | 0x80);
        length >>= 7;
    }
    bytes.push(length as u8);
}

pub(super) fn reject_url(value: &std::ffi::OsStr) -> Result<()> {
    let value = value
        .to_str()
        .ok_or("filesystem paths must be valid UTF-8")?;
    if value.contains("://")
        || value.split_once(':').is_some_and(|(scheme, _)| {
            scheme
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
                && !(cfg!(windows) && scheme.len() == 1)
        })
    {
        return Err("only local filesystem paths are accepted; URLs are unsupported".into());
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("missing or empty {key}").into())
}

fn valid_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u64>().is_ok()
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

pub(super) fn valid_id(id: &str) -> bool {
    id.split_once('/').is_some_and(|(publisher, name)| {
        dhttp_home::normalize_name(publisher).as_deref() == Some(publisher)
            && (1..=63).contains(&name.len())
            && name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

pub(crate) fn validate_metadata(wapm: &Value, annotation: &Value, has_backend: bool) -> Result<()> {
    let id = text(wapm, "name")?;
    if !valid_id(id) {
        return Err("invalid normalized author/name".into());
    }
    let (author, name) = id.split_once('/').unwrap();
    if name == "std" || (name == "app" && author != "std.dhttp.net" && has_backend) {
        return Err("package name conflicts with a host namespace".into());
    }
    if !valid_version(text(wapm, "version")?) {
        return Err("version must be MAJOR.MINOR.PATCH".into());
    }
    text(wapm, "description")?;
    text(wapm, "license")?;
    if let Some(repository) = wapm.get("repository") {
        let raw = repository
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or("repository must be a nonempty HTTPS URL")?;
        let url = url::Url::parse(raw).map_err(|e| format!("invalid repository URL: {e}"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !raw
                .get(..8)
                .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
            || raw[8..]
                .split(['/', '?', '#'])
                .next()
                .is_none_or(str::is_empty)
            || !url.username().is_empty()
            || url.password().is_some()
            || raw[8..]
                .split(['/', '?', '#'])
                .next()
                .is_some_and(|s| s.contains('@'))
            || raw.chars().any(char::is_whitespace)
        {
            return Err(
                "repository must be an HTTPS URL with a host and without credentials".into(),
            );
        }
    }
    text(annotation, "title")?;
    text(annotation, "changelog")?;
    // Ignore legacy host declarations; newly built packages omit the field.
    if annotation.as_object().is_none_or(|o| {
        o.keys().any(|k| {
            !matches!(
                k.as_str(),
                "title" | "dependencies" | "changelog" | "entry" | "host"
            )
        })
    }) {
        return Err("unknown package.pishoo field".into());
    }
    let deps = annotation["dependencies"]
        .as_array()
        .filter(|v| v.len() <= 100)
        .ok_or("dependencies requires an explicit array with at most 100 packages")?;
    let mut ids = HashSet::new();
    for dep in deps {
        let dep_id = format!("{}/{}", text(dep, "publisher")?, text(dep, "name")?);
        if dep.as_object().is_none_or(|o| o.len() != 3)
            || !valid_id(&dep_id)
            || !valid_version(text(dep, "version")?)
            || !ids.insert(dep_id.clone())
            || dep_id == id
        {
            return Err("invalid, duplicate or self package dependency".into());
        }
    }
    if let Some(entry) = annotation.get("entry")
        && entry != "/"
    {
        return Err("invalid entry".into());
    }
    Ok(())
}

pub(crate) fn local_content_path(project: &Path, source: &str) -> Result<PathBuf> {
    reject_url(std::ffi::OsStr::new(source))?;
    let source = project.join(source);
    let mut path = PathBuf::new();
    for component in source.components() {
        path.push(component);
        // A Windows drive/UNC prefix is not a filesystem root until RootDir follows.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        if std::fs::symlink_metadata(&path)
            .map_err(|e| format!("missing build artifact {}: {e}", path.display()))?
            .file_type()
            .is_symlink()
        {
            return Err(format!(
                "build artifact paths cannot contain symlinks: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(std::fs::canonicalize(source)?)
}

pub(crate) fn resolved_output(path: &Path) -> Result<PathBuf> {
    let absolute = std::env::current_dir()?.join(path);
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            _ => {
                resolved.push(component);
            }
        }
        // Do not query a partial verbatim drive path such as \\?\C:.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match std::fs::symlink_metadata(&resolved) {
            Ok(_) => {
                resolved = std::fs::canonicalize(&resolved)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if resolved.file_name().is_none() {
        return Err("output requires a filename".into());
    }
    Ok(resolved)
}

fn ensure_outside_mapping(output: &Path, parent: &Path, directory: &Path) -> Result<()> {
    if output.starts_with(directory) || parent.starts_with(directory) {
        return Err("output and staging directory are inside a content mapping; use an external -o FILE.waz".into());
    }
    Ok(())
}

pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("missing build artifact {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err("build artifacts must be regular files without symlinks".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Do not follow a replaced symlink or block if a source became a FIFO.
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err("build artifacts must be regular files".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(format!("build artifact exceeds size limit: {}", path.display()).into());
    }
    Ok(bytes)
}

fn public_directory(
    path: &Path,
    relative: &str,
    count: &mut usize,
    remaining: &mut usize,
    depth: usize,
    excluded: &[PathBuf],
) -> Result<Directory<'static>> {
    if depth > 32 || std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err("content must contain real directories, depth <= 32".into());
    }
    let mut children = BTreeMap::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if excluded.contains(&entry.path()) {
            continue;
        }
        *count += 1;
        if *count > 4096 {
            return Err("too many content entries".into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid UTF-8 content filename")?;
        let logical = format!("{relative}/{name}");
        if logical.len() > 1024
            || name.is_empty()
            || name == "."
            || name == ".."
            || name.contains(['?', '#', '%', '\\'])
            || name.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err("invalid content file path".into());
        }
        let kind = entry.file_type()?;
        let item = if kind.is_dir() {
            DirEntry::Dir(public_directory(
                &entry.path(),
                &logical,
                count,
                remaining,
                depth + 1,
                excluded,
            )?)
        } else if kind.is_file() {
            let bytes = read_bounded(&entry.path(), (16 * 1024 * 1024).min(*remaining))?;
            *remaining -= bytes.len();
            DirEntry::File(FileEntry::owned(bytes, Timestamps::default()))
        } else {
            return Err("content symlinks and special files are unsupported".into());
        };
        children.insert(name.parse()?, item);
    }
    Ok(Directory::new(children, Timestamps::default()))
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn canonical_windows_content_paths_wait_for_the_complete_root() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        assert!(matches!(
            root.components().next(),
            Some(Component::Prefix(_))
        ));
        std::fs::create_dir(root.join("public")).unwrap();
        assert_eq!(
            local_content_path(&root, "public").unwrap(),
            root.join("public")
        );
    }

    #[test]
    fn canonical_windows_output_can_have_missing_parent_directories() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let output = root.join("dist").join("nested").join("test.waz");
        assert_eq!(resolved_output(&output).unwrap(), output);
        assert!(!output.parent().unwrap().exists());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_one_openapi_before_package_signing() {
        let document = br#"{"openapi":"3.1.0","info":{"version":"1.0.0"},"paths":{}}"#;
        let original = b"\0asm\x0d\0\x01\0".to_vec();
        let embedded = embedded_openapi(original.clone(), Some(document)).unwrap();
        assert!(embedded.starts_with(&original));
        assert!(
            embedded
                .windows(document.len())
                .any(|bytes| bytes == document)
        );
        assert_eq!(embedded_openapi(embedded.clone(), None).unwrap(), embedded);
        assert_eq!(
            embedded_openapi(embedded.clone(), Some(document)).unwrap(),
            embedded
        );
        assert!(
            embedded_openapi(embedded, Some(br#"{"openapi":"3.1.0","paths":{"/x":{}}}"#)).is_err()
        );
        assert!(embedded_openapi(original, None).is_err());
    }

    #[test]
    fn rejects_duplicate_and_truncated_embedded_documents() {
        let document = br#"{"openapi":"3.1.0","paths":{}}"#;
        let original = b"\0asm\x0d\0\x01\0".to_vec();
        let mut embedded = embedded_openapi(original, Some(document)).unwrap();
        embedded.extend_from_within(8..);
        assert!(embedded_openapi(embedded, None).is_err());
        assert!(embedded_openapi(b"\0asm\x0d\0\x01\0\0\x80".to_vec(), None).is_err());
    }
}
