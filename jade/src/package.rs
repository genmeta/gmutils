//! Shared WEBC inspection and local signature verification.
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dhttp_identity::name::DhttpName;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use snafu::{FromString, OptionExt, ResultExt, Whatever, whatever};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const PACKAGE_LIMIT: usize = 64 * 1024 * 1024;
const JSON_LIMIT: usize = 1024 * 1024;

pub(crate) async fn read_snapshot(path: &Path) -> Result<Vec<u8>, Whatever> {
    // O_NONBLOCK prevents a replacement FIFO from blocking before fstat; use the
    // opened handle's metadata and never reopen the user's pathname afterwards.
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .whatever_context(format!("cannot open upload file {}", path.display()))?;
    let metadata = file
        .metadata()
        .whatever_context("cannot inspect upload file")?;
    if !metadata.is_file() {
        whatever!("upload requires one local regular file");
    }
    if metadata.len() > PACKAGE_LIMIT as u64 {
        whatever!("upload file exceeds 64 MiB");
    }
    bounded_read(
        tokio::fs::File::from_std(file),
        PACKAGE_LIMIT,
        "upload file",
    )
    .await
}

pub(crate) async fn bounded_read(
    reader: impl AsyncRead + Unpin,
    limit: usize,
    label: &str,
) -> Result<Vec<u8>, Whatever> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .whatever_context(format!("failed to read {label}"))?;
    if bytes.len() > limit {
        whatever!("{label} exceeds its size limit ({limit} bytes)");
    }
    Ok(bytes)
}

pub(crate) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, Whatever> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .whatever_context(format!("missing or invalid {key}"))
}

// Read only the bounded raw manifest for identity and request paths. The store
// verifies the uploaded release before registering or returning it.
pub(crate) fn manifest_identity(bytes: &[u8]) -> Result<Value, Whatever> {
    if bytes.get(..8) != Some(b"\0webc003") || bytes.get(8) != Some(&2) {
        whatever!("expected a signed WEBC v3 package; run jade build first");
    }
    let length = |offset: usize| -> Result<usize, Whatever> {
        let raw: [u8; 8] = bytes
            .get(offset..offset + 8)
            .whatever_context("truncated WEBC section length")?
            .try_into()
            .unwrap();
        usize::try_from(u64::from_le_bytes(raw)).whatever_context("WEBC section length overflow")
    };
    let mut offset = 17usize
        .checked_add(length(9)?)
        .filter(|end| *end <= bytes.len())
        .whatever_context("truncated WEBC index")?;
    if offset > JSON_LIMIT {
        whatever!("WEBC index exceeds 1 MiB");
    }
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(41)
            .filter(|end| *end <= bytes.len())
            .whatever_context("truncated WEBC section")?;
        let end = header_end
            .checked_add(length(offset + 33)?)
            .filter(|end| *end <= bytes.len())
            .whatever_context("truncated WEBC section body")?;
        if bytes[offset] == 1 {
            if end - offset > JSON_LIMIT {
                whatever!("WEBC manifest exceeds 1 MiB");
            }
            let section = webc::v3::read::Section::parse(
                1,
                Some(bytes[offset + 1..offset + 33].try_into().unwrap()),
                bytes[header_end..end].to_vec().into(),
            )
            .whatever_context("invalid WEBC manifest section")?;
            let manifest = section
                .as_manifest()
                .whatever_context("missing WEBC manifest")?
                .manifest()
                .whatever_context("invalid WEBC manifest")?;
            let document = serde_json::to_value(manifest)
                .whatever_context("invalid WEBC manifest annotations")?;
            let wapm = &document["package"]["wapm"];
            let annotation = &document["package"]["pishoo"];
            let id = text(wapm, "name")?;
            let (author, name) = id
                .split_once('/')
                .whatever_context("manifest name must be author/name")?;
            let version = text(wapm, "version")?;
            if annotation.get("kind").is_some() {
                whatever!("legacy App/Lib packages are unsupported");
            }
            let mut result = json!({"id":id,"author":author,"name":name,"version":version});
            if let Some(repository) = wapm.get("repository") {
                // Preserve it for comparison; the host validates its URL format.
                result["repository"] = repository.clone();
            }
            return Ok(result);
        }
        offset = end;
    }
    whatever!("missing WEBC manifest");
}

pub(crate) async fn inspect_package(bytes: &[u8]) -> crate::error::Result<Value> {
    use crate::error::Error;
    let package = container(bytes).map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    let mut metadata = manifest_identity(bytes).map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    let author = text(&metadata, "author").map_err(|e| Error::new("E_PACKAGE_INVALID", e))?;
    verify_signature(bytes, author).map_err(|e| Error::new("E_SIGNATURE_INVALID", e))?;
    (|| -> Result<Value, Whatever> {
        let document = serde_json::to_value(package.manifest())
            .whatever_context("invalid package manifest")?;
        for key in ["title", "dependencies", "changelog", "entry", "host"] {
            if let Some(value) = document["package"]["pishoo"].get(key) {
                metadata[key] = value.clone();
            }
        }
        if let Some(dependencies) = metadata["dependencies"].as_array_mut() {
            for dependency in dependencies {
                if let Some(fields) = dependency.as_object_mut()
                    && let Some(author) = fields.remove("publisher")
                {
                    fields.insert("author".into(), author);
                }
            }
        }
        for key in ["description", "license", "repository"] {
            if let Some(value) = document["package"]["wapm"].get(key) {
                metadata[key] = value.clone();
            }
        }
        crate::pack::validate_metadata(
            &document["package"]["wapm"],
            &document["package"]["pishoo"],
        )
        .map_err(|error| Whatever::without_source(error.to_string()))?;
        if let Some(backend) = package.get_atom("backend") {
            crate::project::validate_component(
                &backend,
                &document["package"]["pishoo"]["host"],
                text(&metadata, "version")?,
                text(&metadata, "author")?,
                text(&metadata, "name")?,
            )
            .map_err(|error| Whatever::without_source(error.to_string()))?;
        }
        version_path(&metadata)?;
        if package.get_atom("backend").is_none()
            && document["package"]["pishoo"].get("host").is_some()
        {
            whatever!("host capabilities require a backend");
        }
        if (package.get_volume("public").is_some() && document["package"]["pishoo"]["entry"] != "/")
            || (package.get_volume("public").is_none()
                && document["package"]["pishoo"].get("entry").is_some())
        {
            whatever!("entry must match the public mapping");
        }
        Ok(metadata)
    })()
    .map_err(|e| Error::new("E_PACKAGE_INVALID", e))
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// Extract the existing protocol digest after the host has validated these spans.
pub(crate) fn payload_digest(bytes: &[u8]) -> Result<String, Whatever> {
    let reader =
        webc::v3::read::OwnedReader::parse(bytes.to_vec()).whatever_context("cannot parse WEBC")?;
    let index = reader.index();
    let mut hasher = Sha256::new();
    hasher.update(b"\0webc003");
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
        let end = entry
            .span
            .start
            .checked_add(entry.span.len)
            .whatever_context("WEBC span overflow")?;
        hasher.update(
            bytes
                .get(entry.span.start..end)
                .whatever_context("WEBC span exceeds package")?,
        );
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) fn signature_envelope(bytes: &[u8]) -> Result<Value, Whatever> {
    let package = webc::Container::from_bytes_and_version(bytes.to_vec().into(), webc::Version::V3)
        .whatever_context("cannot parse package")?;
    let volume = package
        .get_volume("pishoo-signature")
        .whatever_context("missing package signature")?;
    let (data, _) = volume
        .read_file("/signature.json")
        .whatever_context("missing signature envelope")?;
    if data.len() > 64 * 1024 {
        whatever!("signature envelope exceeds 64 KiB");
    }
    serde_json::from_slice(&data).whatever_context("invalid signature envelope JSON")
}

pub(crate) fn package_certificates(
    bytes: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Whatever> {
    signature_envelope(bytes)?["certificates"]
        .as_array()
        .filter(|v| !v.is_empty())
        .whatever_context("missing package signer certificates")?
        .iter()
        .map(|value| {
            STANDARD
                .decode(
                    value
                        .as_str()
                        .whatever_context("invalid signer certificate")?,
                )
                .map(rustls::pki_types::CertificateDer::from)
                .whatever_context("invalid signer certificate encoding")
        })
        .collect()
}

pub(crate) fn owner_hash(
    certificates: &[rustls::pki_types::CertificateDer<'_>],
) -> Result<String, Whatever> {
    Ok(
        dhttp_home::certificate::extract_dhttp_subject_key_identifier(certificates)
            .whatever_context("invalid identity owner_hash")?
            .owner_hash()
            .as_str()
            .to_owned(),
    )
}

/// Local binding checks use public certificates only. Remote trust and current
/// revocation are checked by the authenticated DHTTP connection at publication.
pub(crate) fn check_certificates(
    certificates: &[rustls::pki_types::CertificateDer<'_>],
    author: &str,
) -> Result<(), Whatever> {
    let first = certificates
        .first()
        .whatever_context("missing signer certificates")?;
    for der in certificates {
        let (trailing, _) = x509_parser::parse_x509_certificate(der.as_ref())
            .whatever_context("invalid signer certificate")?;
        if !trailing.is_empty() {
            whatever!("trailing signer certificate data");
        }
    }
    let (_, certificate) = x509_parser::parse_x509_certificate(first.as_ref())
        .whatever_context("invalid signer certificate")?;
    owner_hash(certificates)?;
    if certificate
        .subject_alternative_name()
        .whatever_context("invalid signer names")?
        .is_none_or(|names| {
            !names.value.general_names.iter().any(|name|
            matches!(name, x509_parser::extensions::GeneralName::DNSName(name) if *name == author))
        })
    {
        whatever!("signer certificate and author disagree");
    }
    Ok(())
}

fn verify_signature(bytes: &[u8], author: &str) -> Result<(), Whatever> {
    let envelope = signature_envelope(bytes)?;
    if envelope.as_object().is_none_or(|object| object.len() != 3)
        || envelope["version"].as_u64() != Some(1)
    {
        whatever!("unsupported signature envelope");
    }
    let certificates = package_certificates(bytes)?;
    check_certificates(&certificates, author)?;
    let (_, certificate) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
        .whatever_context("invalid signer certificate")?;
    let signature = STANDARD
        .decode(text(&envelope, "signature")?)
        .whatever_context("invalid signature encoding")?;
    if signature.is_empty() || signature.len() > 8192 {
        whatever!("invalid signature size");
    }
    let input = signature_input(bytes)?;
    if !dhttp_home::certificate::verify_signature(certificate.public_key().raw, &input, &signature)
        .whatever_context("unsupported author signing key")?
    {
        whatever!("author signature verification failed");
    }
    Ok(())
}

pub(crate) fn version_path(metadata: &Value) -> Result<String, Whatever> {
    let author = text(metadata, "author")?;
    let normalized: DhttpName<'static> =
        author.parse().whatever_context("invalid package author")?;
    let name = text(metadata, "name")?;
    let version = text(metadata, "version")?;
    let valid_version = version.split('.').count() == 3
        && version.split('.').all(|part| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|c| c.is_ascii_digit())
                && part.parse::<u64>().is_ok()
        });
    if normalized.as_full() != author
        || name.len() > 63
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || !valid_version
    {
        whatever!("invalid normalized package identity or exact version");
    }
    Ok(format!(
        "/store/v1/packages/{author}/{name}/versions/{version}"
    ))
}

fn section_length(bytes: &[u8], offset: usize) -> Result<usize, Whatever> {
    let raw: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .whatever_context("truncated WEBC length")?
        .try_into()
        .unwrap();
    usize::try_from(u64::from_le_bytes(raw)).whatever_context("WEBC length overflow")
}

// Validate the index and all authenticated spans before using the lazy WEBC reader.
// This follows the Pishoo unified-package profile, including its entry budget.
fn container(bytes: &[u8]) -> Result<webc::Container, Whatever> {
    if bytes.len() > PACKAGE_LIMIT
        || bytes.get(..8) != Some(b"\0webc003")
        || bytes.get(8) != Some(&2)
    {
        whatever!("expected a bounded WEBC v3 package");
    }
    let end = 17usize
        .checked_add(section_length(bytes, 9)?)
        .filter(|end| *end <= bytes.len() && *end <= JSON_LIMIT)
        .whatever_context("invalid WEBC index size")?;
    let section = webc::v3::read::Section::parse(2, None, bytes[17..end].to_vec().into())
        .whatever_context("invalid WEBC index")?;
    let index = section
        .as_index()
        .whatever_context("missing WEBC index")?
        .index()
        .whatever_context("invalid WEBC index")?;
    if !index.signature.is_none() || !index.signature.value.is_empty() || index.volumes.len() > 2 {
        whatever!("unsupported WEBC signature or volumes");
    }
    let mut spans = BTreeMap::new();
    for (tag, name, entry) in std::iter::once((1, "", &index.manifest))
        .chain(std::iter::once((3, "", &index.atoms)))
        .chain(
            index
                .volumes
                .iter()
                .map(|(name, entry)| (4, name.as_str(), entry)),
        )
    {
        let stop = entry
            .span
            .start
            .checked_add(entry.span.len)
            .filter(|end| *end <= bytes.len())
            .whatever_context("WEBC span exceeds input")?;
        if entry.span.start < end
            || entry.span.len < 41
            || spans.insert(entry.span.start, stop).is_some()
        {
            whatever!("overlapping WEBC sections");
        }
        let raw = &bytes[entry.span.start..stop];
        if raw[0] != tag || section_length(raw, 33)? != raw.len() - 41 {
            whatever!("WEBC section disagrees with index");
        }
        let hash = Sha256::digest(&raw[41..]);
        if raw[1..33] != hash[..] || entry.checksum != webc::v3::Checksum::sha256(hash.into()) {
            whatever!("WEBC section checksum mismatch");
        }
        if tag == 1 && raw.len() > JSON_LIMIT {
            whatever!("WEBC manifest exceeds 1 MiB");
        }
        if tag == 4 {
            let name_end = 8usize
                .checked_add(section_length(&raw[41..], 0)?)
                .filter(|end| *end <= raw.len() - 41)
                .whatever_context("invalid WEBC volume name")?;
            if &raw[49..41 + name_end] != name.as_bytes() {
                whatever!("WEBC volume name disagrees with index");
            }
        }
    }
    let mut position = end;
    for (start, stop) in spans {
        if start != position {
            whatever!("unindexed or overlapping WEBC bytes");
        }
        position = stop;
    }
    if position != bytes.len() {
        whatever!("unindexed trailing WEBC bytes");
    }
    let container =
        webc::Container::from_bytes_and_version(bytes.to_vec().into(), webc::Version::V3)
            .whatever_context("malformed WEBC package")?;
    let manifest = container.manifest();
    if !manifest.use_map.is_empty()
        || !manifest.commands.is_empty()
        || manifest.entrypoint.is_some()
        || !manifest.bindings.is_empty()
        || manifest.atoms.len() > 1
        || manifest.atoms.keys().any(|name| name != "backend")
        || manifest.atoms.len() != container.atoms().len()
    {
        whatever!("package supports one backend atom without commands or bindings");
    }
    let mappings = manifest
        .filesystem()
        .whatever_context("invalid filesystem mapping")?
        .unwrap_or_default();
    if mappings.len() > 1
        || mappings.iter().any(|m| {
            m.mount_path != "/public"
                || m.volume_name != "public"
                || m.from.is_some()
                || m.host_path.as_deref().is_some_and(|p| p != "/")
        })
        || container
            .volumes()
            .keys()
            .any(|name| name != "pishoo-signature" && (name != "public" || mappings.is_empty()))
    {
        whatever!("only the public mapping and signature volume are supported");
    }
    let mut count = 0;
    for (name, volume) in container.volumes() {
        let before = count;
        let files = volume_files(&volume, &mut count)?;
        if name == "pishoo-signature"
            && (count - before != 1
                || files.len() != 1
                || files
                    .get("/signature.json")
                    .is_none_or(|size| *size > 64 * 1024))
        {
            whatever!("signature volume must contain one bounded signature.json");
        }
    }
    container
        .validate()
        .whatever_context("invalid package content digest or mapping")?;
    if mappings.is_empty() && container.get_atom("backend").is_none() {
        whatever!("package has no runtime content");
    }
    if !mappings.is_empty()
        && container
            .get_volume("public")
            .and_then(|v| v.read_file("/index.html"))
            .is_none()
    {
        whatever!("frontend requires public/index.html");
    }
    Ok(container)
}

fn volume_files(
    volume: &webc::Volume,
    count: &mut usize,
) -> Result<BTreeMap<String, usize>, Whatever> {
    let mut files = BTreeMap::new();
    let mut pending = vec![("/".to_owned(), 0)];
    while let Some((path, depth)) = pending.pop() {
        if depth > 32 {
            whatever!("WEBC directory depth exceeds 32");
        }
        let mut names = HashSet::new();
        for (name, _, metadata) in volume
            .read_dir(path.as_str())
            .whatever_context("unreadable WEBC directory")?
        {
            *count += 1;
            if *count > 4096 || !names.insert(name.to_string()) {
                whatever!("too many or duplicate WEBC entries");
            }
            let name = name.to_string();
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.contains(['/', '?', '#', '%', '\\'])
                || name.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                whatever!("invalid WEBC file path");
            }
            let child = format!("{}/{}", path.trim_end_matches('/'), name);
            if child.len() > 1024 {
                whatever!("WEBC path exceeds 1024 bytes");
            }
            match metadata {
                webc::Metadata::Dir { .. } => pending.push((child, depth + 1)),
                webc::Metadata::File { length, .. } => {
                    if length > 16 * 1024 * 1024 {
                        whatever!("WEBC file exceeds 16 MiB");
                    }
                    let (data, hash) = volume
                        .read_file(child.as_str())
                        .whatever_context("unreadable WEBC file")?;
                    if data.len() != length || hash != Some(Sha256::digest(&data).into()) {
                        whatever!("WEBC file checksum mismatch");
                    }
                    files.insert(child, length);
                }
                _ => whatever!("unsupported WEBC file type"),
            }
        }
    }
    Ok(files)
}

pub(crate) fn signature_input(bytes: &[u8]) -> Result<Vec<u8>, Whatever> {
    let digest = payload_digest(bytes)?;
    let mut input = b"pishoo-webc-signature-v1\0".to_vec();
    for offset in (0..digest.len()).step_by(2) {
        input.push(u8::from_str_radix(&digest[offset..offset + 2], 16).unwrap());
    }
    Ok(input)
}
