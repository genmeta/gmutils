//! WAZ v1: a standard ZIP containing a JSON manifest, runtime files and optional docs.
//! This stateless codec is mirrored in the independent host and registry validators.

type WazResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const WAZ_LIMIT: usize = 64 * 1024 * 1024;

pub(crate) fn waz_is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
}

fn waz_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.contains(['\\', ':', '?', '#', '%'])
        && !path.chars().any(|c| c.is_control() || c.is_whitespace())
        && path.split('/').count() <= 33
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
        && (matches!(
            path,
            "manifest.json" | "signature.json" | "backend.wasm" | "README.md" | "CHANGELOG.md"
        ) || path.starts_with("public/"))
}

pub(crate) fn waz_read(bytes: &[u8]) -> WazResult<std::collections::BTreeMap<String, Vec<u8>>> {
    use std::io::Read;

    if bytes.len() > WAZ_LIMIT || !waz_is_zip(bytes) || bytes.len() < 22 {
        return Err("expected a bounded standard ZIP package".into());
    }
    // This profile uses ordinary single-disk ZIP, without ZIP64, comments,
    // self-extracting prefixes or trailing data. Every byte belongs to the archive.
    let end = bytes.len() - 22;
    let eocd = &bytes[end..];
    let u16_at = |offset: usize| u16::from_le_bytes(eocd[offset..offset + 2].try_into().unwrap());
    let u32_at =
        |offset: usize| u32::from_le_bytes(eocd[offset..offset + 4].try_into().unwrap()) as usize;
    let count = u16_at(10) as usize;
    let directory_size = u32_at(12);
    let directory_start = u32_at(16);
    if eocd[..4] != *b"PK\x05\x06"
        || u16_at(4) != 0
        || u16_at(6) != 0
        || u16_at(20) != 0
        || u16_at(8) as usize != count
        || count == 0
        || count > 4096
        || directory_start.checked_add(directory_size) != Some(end)
    {
        return Err("invalid ZIP end record or entry budget".into());
    }
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    if archive.len() != count || archive.offset() != 0 {
        return Err("ZIP central directory disagrees with archive".into());
    }
    let mut files = std::collections::BTreeMap::new();
    let mut spans = std::collections::BTreeMap::new();
    let mut central_spans = std::collections::BTreeMap::new();
    let mut remaining = WAZ_LIMIT;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = std::str::from_utf8(entry.name_raw())?.to_owned();
        if !waz_path(&name)
            || entry.is_dir()
            || entry.encrypted()
            || !matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
            || entry
                .unix_mode()
                .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000))
            || files.contains_key(&name)
        {
            return Err(format!("invalid, duplicate or unsupported ZIP entry: {name}").into());
        }
        let limit = match name.as_str() {
            "manifest.json" => 1024 * 1024,
            "signature.json" => 64 * 1024,
            "backend.wasm" => WAZ_LIMIT,
            _ => 16 * 1024 * 1024,
        }
        .min(remaining);
        let size = usize::try_from(entry.size())?;
        if size > limit {
            return Err(format!("ZIP entry exceeds its decompressed size limit: {name}").into());
        }
        let start = usize::try_from(entry.header_start())?;
        let data = usize::try_from(entry.data_start())?;
        let stop = data
            .checked_add(usize::try_from(entry.compressed_size())?)
            .ok_or("ZIP span overflow")?;
        let header = bytes
            .get(start..start.checked_add(30).ok_or("ZIP header overflow")?)
            .ok_or("truncated ZIP local header")?;
        let name_length = u16::from_le_bytes(header[26..28].try_into().unwrap()) as usize;
        let extra_length = u16::from_le_bytes(header[28..30].try_into().unwrap()) as usize;
        let flags = u16::from_le_bytes(header[6..8].try_into().unwrap());
        let central_start = usize::try_from(entry.central_header_start())?;
        let central = bytes
            .get(
                central_start
                    ..central_start
                        .checked_add(46)
                        .ok_or("ZIP directory overflow")?,
            )
            .ok_or("truncated ZIP central header")?;
        let central_length = 46
            + u16::from_le_bytes(central[28..30].try_into().unwrap()) as usize
            + u16::from_le_bytes(central[30..32].try_into().unwrap()) as usize
            + u16::from_le_bytes(central[32..34].try_into().unwrap()) as usize;
        let central_end = central_start
            .checked_add(central_length)
            .ok_or("ZIP directory span overflow")?;
        if central[..4] != *b"PK\x01\x02"
            || central_start < directory_start
            || central_end > end
            || u16::from_le_bytes(central[8..10].try_into().unwrap()) != flags
            || central_spans.insert(central_start, central_end).is_some()
        {
            return Err("invalid ZIP central header".into());
        }
        if header[..4] != *b"PK\x03\x04"
            || flags & !0x0806 != 0 // UTF-8 and Deflate level hints only; no encryption/descriptors.
            || bytes.get(start + 30..start + 30 + name_length) != Some(name.as_bytes())
            || start + 30 + name_length + extra_length != data
            || u16::from_le_bytes(header[8..10].try_into().unwrap()) != if entry.compression() == zip::CompressionMethod::Stored { 0 } else { 8 }
            || u32::from_le_bytes(header[14..18].try_into().unwrap()) != entry.crc32()
            || u32::from_le_bytes(header[18..22].try_into().unwrap()) as u64 != entry.compressed_size()
            || u32::from_le_bytes(header[22..26].try_into().unwrap()) as u64 != entry.size()
            || stop > directory_start || spans.insert(start, stop).is_some()
        {
            return Err("ZIP local header disagrees with the central directory".into());
        }
        let mut content = Vec::new();
        entry
            .by_ref()
            .take(size as u64 + 1)
            .read_to_end(&mut content)?;
        if content.len() != size {
            return Err("ZIP decompressed size disagrees with header".into());
        }
        remaining -= content.len();
        files.insert(name, content);
    }
    let mut cursor = 0;
    for (start, stop) in spans {
        if start != cursor {
            return Err("overlapping or unindexed ZIP data".into());
        }
        cursor = stop;
    }
    if cursor != directory_start {
        return Err("unindexed ZIP data before directory".into());
    }
    for (start, stop) in central_spans {
        if start != cursor {
            return Err("overlapping or unindexed ZIP directory".into());
        }
        cursor = stop;
    }
    if cursor != end {
        return Err("unindexed ZIP directory data".into());
    }
    for name in files.keys() {
        let mut ancestor = name.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            if files.contains_key(parent) {
                return Err("ZIP file conflicts with a directory".into());
            }
            ancestor = parent;
        }
    }
    if !files.contains_key("manifest.json") {
        return Err("ZIP package requires manifest.json".into());
    }
    Ok(files)
}

pub(crate) fn waz_payload(files: &std::collections::BTreeMap<String, Vec<u8>>) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"pishoo-waz-payload-v1\0");
    for (name, bytes) in files
        .iter()
        .filter(|(name, _)| name.as_str() != "signature.json")
    {
        digest.update((name.len() as u32).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(Sha256::digest(bytes));
    }
    format!("{:x}", digest.finalize())
}

pub(crate) fn waz_write(files: &std::collections::BTreeMap<String, Vec<u8>>) -> WazResult<Vec<u8>> {
    use std::io::Write;
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(6))
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644);
    for (name, bytes) in files {
        writer.start_file(name, options)?;
        writer.write_all(bytes)?;
    }
    let bytes = writer.finish()?.into_inner();
    waz_read(&bytes)?;
    Ok(bytes)
}

fn waz_directory(
    files: &std::collections::BTreeMap<String, Vec<u8>>,
    prefix: &str,
) -> WazResult<webc::v3::write::Directory<'static>> {
    use webc::v3::{
        Timestamps,
        write::{DirEntry, Directory, FileEntry},
    };
    let mut children = std::collections::BTreeMap::new();
    for (name, bytes) in files {
        let Some(relative) = name.strip_prefix(prefix) else {
            continue;
        };
        if let Some((directory, _)) = relative.split_once('/') {
            let key = directory.parse()?;
            if let std::collections::btree_map::Entry::Vacant(entry) = children.entry(key) {
                entry.insert(DirEntry::Dir(waz_directory(
                    files,
                    &format!("{prefix}{directory}/"),
                )?));
            }
        } else {
            children.insert(
                relative.parse()?,
                DirEntry::File(FileEntry::owned(bytes.clone(), Timestamps::default())),
            );
        }
    }
    Ok(Directory::new(children, Timestamps::default()))
}

pub(crate) fn waz_convert(bytes: &[u8]) -> WazResult<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use webc::v3::{
        SignatureAlgorithm, Timestamps,
        write::{Directory, FileEntry, Writer},
    };

    let files = waz_read(bytes)?;
    let document: Value = serde_json::from_slice(&files["manifest.json"])?;
    if document["format"] != "waz/1"
        || document.as_object().is_none_or(|v| {
            v.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "format" | "package" | "dependencies" | "frontend" | "backend"
                )
            })
        })
    {
        return Err("unsupported WAZ manifest format or field".into());
    }
    let package = document["package"]
        .as_object()
        .ok_or("manifest package requires an object")?;
    if package.keys().any(|k| {
        !matches!(
            k.as_str(),
            "author"
                | "name"
                | "version"
                | "title"
                | "description"
                | "license"
                | "release-notes"
                | "repository"
        )
    }) {
        return Err("unknown WAZ package field".into());
    }
    let field = |name: &str| {
        package
            .get(name)
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| format!("missing WAZ package {name}"))
    };
    let mut wapm = json!({"name":format!("{}/{}", field("author")?, field("name")?),
        "version":field("version")?,"description":field("description")?,"license":field("license")?});
    if let Some(repository) = package.get("repository") {
        wapm["repository"] = repository.clone();
    }
    if files.contains_key("README.md") {
        wapm["readme"] = json!({"volume":"metadata","path":"/README.md"});
    }
    let dependencies = document["dependencies"]
        .as_array()
        .filter(|v| v.len() <= 100)
        .ok_or("WAZ dependencies requires an array with at most 100 packages")?;
    let mut dependencies_out = Vec::new();
    for dependency in dependencies {
        if dependency.as_object().is_none_or(|v| {
            v.len() != 3
                || !v.contains_key("author")
                || !v.contains_key("name")
                || !v.contains_key("version")
        }) {
            return Err("WAZ dependency requires author, name and version".into());
        }
        dependencies_out.push(json!({"publisher":dependency["author"],"name":dependency["name"],"version":dependency["version"]}));
    }
    let has_frontend = document.get("frontend").is_some();
    let has_backend = document.get("backend").is_some();
    if (has_frontend && document["frontend"] != "public")
        || (has_backend && document["backend"] != "backend.wasm")
        || has_backend != files.contains_key("backend.wasm")
        || has_frontend != files.keys().any(|name| name.starts_with("public/"))
        || (has_frontend && !files.contains_key("public/index.html"))
        || (!has_frontend && !has_backend)
    {
        return Err("WAZ manifest runtime paths disagree with package files".into());
    }
    let mut annotation = json!({"title":field("title")?,"changelog":field("release-notes")?,"dependencies":dependencies_out});
    if has_frontend {
        annotation["entry"] = "/".into();
    }
    let mut manifest = json!({"package":{"wapm":wapm,"pishoo":annotation,
        "fs":if has_frontend {json!([{"volume_name":"public","mount_path":"/public"}])} else {json!([])}}});
    let mut atoms = std::collections::BTreeMap::new();
    if let Some(backend) = files.get("backend.wasm") {
        manifest["atoms"] = json!({"backend":{"kind":"https://webc.org/kind/wasm","signature":format!("sha256:{}", STANDARD.encode(Sha256::digest(backend)))}});
        atoms.insert(
            "backend".parse()?,
            FileEntry::owned(backend.clone(), Timestamps::default()),
        );
    }
    let manifest: webc::metadata::Manifest = serde_json::from_value(manifest)?;
    let mut writer = Writer::default()
        .write_manifest(&manifest)?
        .write_atoms(atoms)?;
    if has_frontend {
        writer.write_volume("public", waz_directory(&files, "public/")?)?;
    }
    let documents = files
        .iter()
        .filter(|(name, _)| matches!(name.as_str(), "README.md" | "CHANGELOG.md"))
        .map(|(name, data)| Ok((name.parse()?, data.clone().into())))
        .collect::<WazResult<std::collections::BTreeMap<_, _>>>()?;
    if !documents.is_empty() {
        writer.write_volume("metadata", Directory::new(documents, Timestamps::default()))?;
    }
    if let Some(signature) = files.get("signature.json") {
        writer.write_volume(
            "pishoo-signature",
            Directory::new(
                std::collections::BTreeMap::from([(
                    "signature.json".parse()?,
                    signature.clone().into(),
                )]),
                Timestamps::default(),
            ),
        )?;
    }
    // Keep the existing in-memory resource API and installation snapshots. These
    // bytes are an internal projection, never a signed archive or published file.
    Ok(writer.finish(SignatureAlgorithm::None)?.to_vec())
}

pub(crate) fn waz_export(
    container: &webc::Container,
) -> WazResult<std::collections::BTreeMap<String, Vec<u8>>> {
    use serde_json::json;
    let old = serde_json::to_value(container.manifest())?;
    let wapm = &old["package"]["wapm"];
    let annotation = &old["package"]["pishoo"];
    let (author, name) = wapm["name"]
        .as_str()
        .and_then(|v| v.split_once('/'))
        .ok_or("package requires author/name")?;
    let mut package = json!({"author":author,"name":name,"version":wapm["version"],"description":wapm["description"],
        "license":wapm["license"],"title":annotation["title"],"release-notes":annotation["changelog"]});
    if let Some(repository) = wapm.get("repository") {
        package["repository"] = repository.clone();
    }
    let dependencies = annotation["dependencies"]
        .as_array()
        .ok_or("missing dependencies")?
        .iter()
        .map(|v| json!({"author":v["publisher"],"name":v["name"],"version":v["version"]}))
        .collect::<Vec<_>>();
    let mut manifest = json!({"format":"waz/1","package":package,"dependencies":dependencies});
    let mut files = std::collections::BTreeMap::new();
    if let Some(backend) = container.get_atom("backend") {
        manifest["backend"] = "backend.wasm".into();
        files.insert("backend.wasm".into(), backend.to_vec());
    }
    if let Some(volume) = container.get_volume("public") {
        manifest["frontend"] = "public".into();
        let mut pending = vec!["/".to_owned()];
        while let Some(directory) = pending.pop() {
            for (name, _, metadata) in volume
                .read_dir(directory.as_str())
                .ok_or("unreadable resource directory")?
            {
                let path = format!("{directory}{name}");
                match metadata {
                    webc::Metadata::Dir { .. } => pending.push(format!("{path}/")),
                    webc::Metadata::File { .. } => {
                        files.insert(
                            format!("public{path}"),
                            volume
                                .read_file(path.as_str())
                                .ok_or("unreadable resource")?
                                .0
                                .to_vec(),
                        );
                    }
                    _ => return Err("unsupported resource type".into()),
                }
            }
        }
    }
    if let Some(volume) = container.get_volume("metadata") {
        for name in ["README.md", "CHANGELOG.md"] {
            if let Some((data, _)) = volume.read_file(format!("/{name}")) {
                files.insert(name.into(), data.to_vec());
            }
        }
    }
    files.insert(
        "manifest.json".into(),
        serde_json::to_vec_pretty(&manifest)?,
    );
    Ok(files)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::{Cursor, Write},
    };

    use super::*;

    fn files() -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([
            ("manifest.json".into(), serde_json::to_vec(&serde_json::json!({
                "format":"waz/1", "package":{"author":"alice.dhttp.net","name":"demo","version":"1.0.0",
                    "title":"Demo","description":"Test","license":"MIT","release-notes":"Initial"},
                "dependencies":[], "frontend":"public"
            })).unwrap()),
            ("public/index.html".into(), b"<h1>Hello</h1>".to_vec()),
            ("README.md".into(), b"# Demo".to_vec()),
            ("CHANGELOG.md".into(), b"# 1.0.0".to_vec()),
        ])
    }

    #[test]
    fn standard_zip_roundtrip_preserves_files_and_manifest() {
        let files = files();
        let bytes = waz_write(&files).unwrap();
        assert!(bytes.starts_with(b"PK\x03\x04"));
        assert_eq!(waz_read(&bytes).unwrap(), files);
        let container = webc::Container::from_bytes_and_version(
            waz_convert(&bytes).unwrap().into(),
            webc::Version::V3,
        )
        .unwrap();
        assert_eq!(
            waz_export(&container).unwrap().keys().collect::<Vec<_>>(),
            files.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            container
                .get_volume("metadata")
                .unwrap()
                .read_file("/README.md")
                .unwrap()
                .0
                .as_ref(),
            b"# Demo"
        );
        let mut changed = files.clone();
        changed.insert("CHANGELOG.md".into(), b"# Changed".to_vec());
        assert_ne!(waz_payload(&changed), waz_payload(&files));
        changed = files.clone();
        changed.insert("signature.json".into(), b"signature is separate".to_vec());
        assert_eq!(waz_payload(&changed), waz_payload(&files));
        assert!(waz_read(b"\0webc003").is_err());
    }

    #[test]
    fn zip_rejects_ambiguous_paths_symlinks_and_oversized_entries() {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for name in [
            "../README.md",
            "/README.md",
            "public/../index.html",
            "public\\index.html",
            "public/a/",
            "unlisted.txt",
        ] {
            let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
            writer.start_file("manifest.json", options).unwrap();
            writer.write_all(b"{}").unwrap();
            writer.start_file(name, options).unwrap();
            writer.write_all(b"content").unwrap();
            let bytes = writer.finish().unwrap().into_inner();
            assert!(waz_read(&bytes).is_err(), "{name}");
        }
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer.start_file("manifest.json", options).unwrap();
        writer.write_all(b"{}").unwrap();
        writer
            .add_symlink("README.md", "/etc/passwd", options)
            .unwrap();
        assert!(waz_read(&writer.finish().unwrap().into_inner()).is_err());
        let mut files = files();
        files.insert("README.md".into(), vec![0; 16 * 1024 * 1024 + 1]);
        assert!(waz_write(&files).is_err());
    }

    #[test]
    fn zip_rejects_trailing_data_header_disagreement_and_missing_runtime() {
        let bytes = waz_write(&files()).unwrap();
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(waz_read(&changed).is_err());
        changed = bytes.clone();
        changed[30] ^= 1;
        assert!(waz_read(&changed).is_err());
        changed = bytes;
        changed[6] |= 1;
        assert!(waz_read(&changed).is_err());
        let mut files = files();
        files.remove("public/index.html");
        assert!(waz_convert(&waz_write(&files).unwrap()).is_err());
    }
}
