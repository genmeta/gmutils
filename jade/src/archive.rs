//! WAZ v2 TOML releases and historical WAZ v1 JSON releases in bounded ZIP archives.
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
        ) || path == "manifest.toml"
            || path.starts_with("public/")
            || path.starts_with("wasm/")
            || path.starts_with("web/")
            || path.starts_with("docs/"))
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
            "manifest.json" | "manifest.toml" => 1024 * 1024,
            "signature.json" => 64 * 1024,
            "backend.wasm" => WAZ_LIMIT,
            _ if name.starts_with("wasm/") => WAZ_LIMIT,
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
    if files.contains_key("manifest.json") == files.contains_key("manifest.toml") {
        return Err("ZIP package requires exactly one manifest.json or manifest.toml".into());
    }
    if let Some(manifest) = files.get("manifest.toml") {
        waz_toml(manifest)?;
    }
    Ok(files)
}

pub(crate) fn waz_payload(
    files: &std::collections::BTreeMap<String, Vec<u8>>,
) -> WazResult<String> {
    use sha2::{Digest, Sha256};
    let modern = files.contains_key("manifest.toml");
    let mut digest = Sha256::new();
    digest.update(if modern {
        b"pishoo-waz-payload-v2\0"
    } else {
        b"pishoo-waz-payload-v1\0"
    });
    for (name, bytes) in files
        .iter()
        .filter(|(name, _)| modern || name.as_str() != "signature.json")
    {
        let content = if name == "manifest.toml" {
            &bytes[..waz_toml(bytes)?.1]
        } else {
            bytes.as_slice()
        };
        digest.update((name.len() as u32).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((content.len() as u64).to_le_bytes());
        digest.update(Sha256::digest(content));
    }
    Ok(format!("{:x}", digest.finalize()))
}

// These stateless boundary helpers are mirrored in Jade, Pishoo and the store.
fn waz_toml(bytes: &[u8]) -> WazResult<(serde_json::Value, usize)> {
    use serde_json::Value;
    let source = std::str::from_utf8(bytes)?;
    let document: Value = toml::from_str(source)?;
    if document.get("signature").is_none() {
        return Ok((document, bytes.len()));
    }
    let positions: std::collections::BTreeMap<String, toml::Spanned<Value>> =
        toml::from_str(source)?;
    let span = positions
        .get("signature")
        .ok_or("missing signature table")?
        .span();
    let boundary = span.start;
    let after_header = &source[span.end..];
    if source.get(span) != Some("[signature]")
        || (boundary != 0 && bytes[boundary - 1] != b'\n')
        || !(after_header.is_empty()
            || after_header.starts_with('\n')
            || after_header.starts_with("\r\n"))
    {
        return Err("signature must use a final [signature] table on its own line".into());
    }
    if bytes.len() - boundary > 64 * 1024 {
        return Err("publisher signature exceeds 64 KiB".into());
    }
    let unsigned: Value = toml::from_str(&source[..boundary])?;
    let suffix: Value = toml::from_str(&source[boundary..])?;
    let mut expected = document.clone();
    expected
        .as_object_mut()
        .ok_or("manifest must be a table")?
        .remove("signature");
    if unsigned != expected
        || suffix.as_object().is_none_or(|fields| fields.len() != 1)
        || suffix["signature"] != document["signature"]
    {
        return Err("signature must be last and contain only its own fields".into());
    }
    Ok((document, boundary))
}

pub(crate) fn waz_manifest(
    files: &std::collections::BTreeMap<String, Vec<u8>>,
) -> WazResult<serde_json::Value> {
    if let Some(bytes) = files.get("manifest.toml") {
        let (mut manifest, _) = waz_toml(bytes)?;
        let author = manifest["package"]["author"]
            .as_str()
            .ok_or("missing package author")?;
        if !author.ends_with(".dhttp.net") {
            manifest["package"]["author"] = format!("{author}.dhttp.net").into();
        }
        Ok(manifest)
    } else {
        Ok(serde_json::from_slice(
            files
                .get("manifest.json")
                .ok_or("missing package manifest")?,
        )?)
    }
}

pub(crate) fn waz_signature(
    files: &std::collections::BTreeMap<String, Vec<u8>>,
) -> WazResult<serde_json::Value> {
    if files.contains_key("manifest.toml") {
        let mut signature = waz_manifest(files)?["signature"].clone();
        let fields = signature
            .as_object_mut()
            .ok_or("missing publisher signature")?;
        if fields.len() != 3
            || !fields.contains_key("version")
            || !fields.contains_key("certificates")
        {
            return Err("unsupported signature envelope".into());
        }
        let value = fields.remove("value").ok_or("missing signature value")?;
        fields.insert("signature".into(), value);
        Ok(signature)
    } else {
        Ok(serde_json::from_slice(
            files
                .get("signature.json")
                .ok_or("missing publisher signature")?,
        )?)
    }
}

pub(crate) fn waz_backend(files: &std::collections::BTreeMap<String, Vec<u8>>) -> Option<&Vec<u8>> {
    files.get("backend.wasm").or_else(|| {
        files
            .iter()
            .find(|(name, _)| name.starts_with("wasm/"))
            .map(|(_, bytes)| bytes)
    })
}

fn waz_layout(
    files: &std::collections::BTreeMap<String, Vec<u8>>,
    document: &serde_json::Value,
) -> WazResult<()> {
    let modern = files.contains_key("manifest.toml");
    let format = if modern { "waz/2" } else { "waz/1" };
    let (wasm_key, web_key) =
        if modern && (document.get("wasm").is_some() || document.get("web").is_some()) {
            ("wasm", "web")
        } else {
            ("backend", "frontend")
        };
    if document["format"] != format
        || document.as_object().is_none_or(|fields| {
            fields.keys().any(|key| {
                !(matches!(key.as_str(), "format" | "package" | "dependencies")
                    || key == wasm_key
                    || key == web_key
                    || modern && matches!(key.as_str(), "docs" | "signature"))
            })
        })
    {
        return Err("unsupported WAZ manifest format or field".into());
    }
    if modern
        && document["package"]["name"]
            .as_str()
            .is_some_and(|name| name.starts_with("std/"))
        && !matches!(
            document["package"]["author"].as_str(),
            Some("std.dhttp.net" | "dev.genmeta.tech.dhttp.net")
        )
    {
        return Err("std/ package names require a standard publisher".into());
    }
    let backend = if modern {
        format!(
            "wasm/{}.wasm",
            document["package"]["name"]
                .as_str()
                .ok_or("missing package name")?
        )
    } else {
        "backend.wasm".to_owned()
    };
    let frontend = if modern { "web" } else { "public" };
    let prefix = format!("{frontend}/");
    let has_frontend = document.get(web_key).is_some();
    let has_backend = document.get(wasm_key).is_some();
    if (has_backend && document[wasm_key] != backend)
        || (has_frontend && document[web_key] != frontend)
        || has_backend != files.contains_key(&backend)
        || has_frontend != files.keys().any(|name| name.starts_with(&prefix))
        || (has_frontend && !files.contains_key(&format!("{prefix}index.html")))
        || (!has_backend && !has_frontend)
        || files
            .keys()
            .any(|name| name.starts_with("wasm/") && name != &backend)
    {
        return Err("WAZ manifest runtime paths disagree with package files".into());
    }
    if modern {
        if files.keys().any(|name| {
            matches!(
                name.as_str(),
                "manifest.json" | "signature.json" | "backend.wasm" | "README.md" | "CHANGELOG.md"
            ) || name.starts_with("public/")
        }) {
            return Err("WAZ v2 contains legacy package entries".into());
        }
        if let Some(docs) = document.get("docs") {
            let fields = docs.as_object().ok_or("docs must be a table")?;
            for (key, value) in fields {
                let path = value.as_str().ok_or("document locations must be strings")?;
                match key.as_str() {
                    "manual" if path == "docs/manual.md" && files.contains_key(path) => {}
                    "readme" | "changelog" => {
                        let url = url::Url::parse(path)?;
                        if url.scheme() != "https"
                            || url.host_str().is_none()
                            || !url.username().is_empty()
                            || url.password().is_some()
                            || path.chars().any(char::is_whitespace)
                        {
                            return Err(
                                "external document links require HTTPS URLs without credentials"
                                    .into(),
                            );
                        }
                    }
                    _ => return Err("unknown document field or missing docs/manual.md".into()),
                }
            }
        }
        for (name, bytes) in files.iter().filter(|(name, _)| name.starts_with("docs/")) {
            if !name.ends_with(".md") {
                return Err("package manuals must be Markdown files".into());
            }
            std::str::from_utf8(bytes)?;
        }
    } else if files.keys().any(|name| {
        name == "manifest.toml"
            || name.starts_with("wasm/")
            || name.starts_with("web/")
            || name.starts_with("docs/")
    }) {
        return Err("WAZ v1 contains unsupported package entries".into());
    }
    Ok(())
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
    let document = waz_manifest(&files)?;
    waz_layout(&files, &document)?;
    let modern = files.contains_key("manifest.toml");
    let frontend_prefix = if modern { "web/" } else { "public/" };
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
            v.len() != 2 + usize::from(v.contains_key("author"))
                || !v.contains_key("name")
                || !v.contains_key("version")
        }) {
            return Err(
                "WAZ dependency requires name and version (legacy author is optional)".into(),
            );
        }
        let mut item = json!({"name":dependency["name"],"version":dependency["version"]});
        if let Some(author) = dependency.get("author") {
            item["publisher"] = author.clone();
        }
        dependencies_out.push(item);
    }
    let has_frontend = document.get("web").is_some() || document.get("frontend").is_some();
    let mut annotation = json!({"title":field("title")?,"changelog":field("release-notes")?,"dependencies":dependencies_out});
    if let Some(docs) = document.get("docs") {
        annotation["docs"] = docs.clone();
    }
    if has_frontend {
        annotation["entry"] = "/".into();
    }
    let mut manifest = json!({"package":{"wapm":wapm,"pishoo":annotation,
        "fs":if has_frontend {json!([{"volume_name":"public","mount_path":"/public"}])} else {json!([])}}});
    let mut atoms = std::collections::BTreeMap::new();
    if let Some(backend) = waz_backend(&files) {
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
        writer.write_volume("public", waz_directory(&files, frontend_prefix)?)?;
    }
    let documents = files
        .iter()
        .filter(|(name, _)| {
            matches!(name.as_str(), "README.md" | "CHANGELOG.md") || name.starts_with("docs/")
        })
        .map(|(name, bytes)| (format!("metadata/{name}"), bytes.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    if !documents.is_empty() {
        writer.write_volume("metadata", waz_directory(&documents, "metadata/")?)?;
    }
    if document.get("signature").is_some() || files.contains_key("signature.json") {
        let signature = serde_json::to_vec(&waz_signature(&files)?)?;
        writer.write_volume(
            "pishoo-signature",
            Directory::new(
                std::collections::BTreeMap::from([("signature.json".parse()?, signature.into())]),
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
        .map(|v| {
            let mut item = json!({"name":v["name"],"version":v["version"]});
            if let Some(author) = v.get("publisher") {
                item["author"] = author.clone();
            }
            item
        })
        .collect::<Vec<_>>();
    let mut manifest = json!({"format":"waz/2","package":package,"dependencies":dependencies});
    let mut files = std::collections::BTreeMap::new();
    if let Some(backend) = container.get_atom("backend") {
        let path = format!("wasm/{name}.wasm");
        manifest["wasm"] = path.clone().into();
        files.insert(path, backend.to_vec());
    }
    if let Some(volume) = container.get_volume("public") {
        manifest["web"] = "web".into();
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
                            format!("web{path}"),
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
    if let Some(docs) = annotation.get("docs") {
        manifest["docs"] = docs.clone();
    }
    if let Some(volume) = container.get_volume("metadata") {
        let mut pending = vec!["/".to_owned()];
        while let Some(directory) = pending.pop() {
            for (entry, _, metadata) in volume
                .read_dir(directory.as_str())
                .ok_or("unreadable document directory")?
            {
                let path = format!("{directory}{entry}");
                match metadata {
                    webc::Metadata::Dir { .. } => pending.push(format!("{path}/")),
                    webc::Metadata::File { .. } if path.starts_with("/docs/") => {
                        files.insert(
                            path[1..].to_owned(),
                            volume
                                .read_file(path.as_str())
                                .ok_or("unreadable document")?
                                .0
                                .to_vec(),
                        );
                    }
                    webc::Metadata::File { .. } => {}
                    _ => return Err("unsupported document type".into()),
                }
            }
        }
    }
    files.insert(
        "manifest.toml".into(),
        toml::to_string_pretty(&manifest)?.into_bytes(),
    );
    Ok(files)
}

#[cfg(test)]
#[path = "../tests/unit/archive.rs"]
mod tests;
