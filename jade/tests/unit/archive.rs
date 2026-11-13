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
    let exported = waz_export(&container).unwrap();
    assert_eq!(waz_manifest(&exported).unwrap()["format"], "waz/2");
    assert_eq!(exported["web/index.html"], files["public/index.html"]);
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
    assert_ne!(waz_payload(&changed).unwrap(), waz_payload(&files).unwrap());
    changed = files.clone();
    changed.insert("signature.json".into(), b"signature is separate".to_vec());
    assert_eq!(waz_payload(&changed).unwrap(), waz_payload(&files).unwrap());
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

#[test]
fn waz_v2_toml_signature_boundary_and_payload_match_the_shared_vector() {
    let source = r#"format = "waz/2"
dependencies = []
frontend = "web"

[package]
author = "alice.dhttp.net"
name = "comm/demo"
version = "1.0.0"
title = "Demo"
description = "Signed documentation"
license = "MIT"
release-notes = "Initial"

[docs]
manual = "docs/manual.md"
readme = "https://example.com/readme"
"#;
    let mut files = std::collections::BTreeMap::from([
        ("manifest.toml".to_owned(), source.as_bytes().to_vec()),
        ("web/index.html".to_owned(), b"<h1>Demo</h1>".to_vec()),
        ("docs/manual.md".to_owned(), b"# Demo\n".to_vec()),
    ]);
    waz_layout(&files, &waz_manifest(&files).unwrap()).unwrap();
    assert_eq!(
        waz_payload(&files).unwrap(),
        "d59bc128cfbd4d8735c597f9c284d2a89365110287c6efb5d24ef6c594cad9e2"
    );
    let signature = b"[signature]\nversion = 1\ncertificates = ['certificate']\nvalue = 'first'\n";
    files
        .get_mut("manifest.toml")
        .unwrap()
        .extend_from_slice(signature);
    let signed_payload = waz_payload(&files).unwrap();
    assert_eq!(
        signed_payload,
        "d59bc128cfbd4d8735c597f9c284d2a89365110287c6efb5d24ef6c594cad9e2"
    );
    let mut changed = files.clone();
    changed.insert(
        "manifest.toml".into(),
        [
            source.as_bytes(),
            b"[signature]\nversion = 1\ncertificates = ['other']\nvalue = 'second'\n",
        ]
        .concat(),
    );
    assert_eq!(waz_payload(&changed).unwrap(), signed_payload);
    changed = files.clone();
    changed.insert("docs/manual.md".into(), b"# Changed\n".to_vec());
    assert_ne!(waz_payload(&changed).unwrap(), signed_payload);
    changed = files.clone();
    changed.insert(
        "manifest.toml".into(),
        [
            b"# Added comment\n".as_slice(),
            files["manifest.toml"].as_slice(),
        ]
        .concat(),
    );
    assert_ne!(waz_payload(&changed).unwrap(), signed_payload);
    assert_eq!(waz_signature(&files).unwrap()["signature"], "first");
    for suffix in ["[extra]\nvalue = 1\n", "[package]\nname = 'forged'\n"] {
        let mut bytes = files["manifest.toml"].clone();
        bytes.extend_from_slice(suffix.as_bytes());
        assert!(waz_toml(&bytes).is_err());
    }
    // Parser source spans distinguish a header-looking line inside a signed string.
    let multiline = source.replace(
        "description = \"Signed documentation\"",
        "description = '''\nLiteral text\n[signature]\ninside the description\n'''",
    );
    let multiline = [multiline.as_bytes(), signature].concat();
    let (document, boundary) = waz_toml(&multiline).unwrap();
    assert!(
        document["package"]["description"]
            .as_str()
            .unwrap()
            .contains("[signature]")
    );
    assert_eq!(&multiline[boundary..], signature);
    let dotted = format!("signature.value = 'forged'\n{source}");
    assert!(waz_toml(dotted.as_bytes()).is_err());
    let duplicated = format!("{source}format = 'waz/2'\nformat = 'waz/2'\n");
    assert!(waz_toml(duplicated.as_bytes()).is_err());
    files.insert("signature.json".into(), b"{}".to_vec());
    assert!(waz_layout(&files, &waz_manifest(&files).unwrap()).is_err());
}

#[test]
fn waz_v2_runtime_paths_document_links_and_format_are_checked() {
    let source = r#"format = "waz/2"
dependencies = []
frontend = "web"

[package]
author = "alice.dhttp.net"
name = "comm/demo"
version = "1.0.0"
title = "Demo"
description = "Signed documentation"
license = "MIT"
release-notes = "Initial"

[docs]
manual = "docs/manual.md"
readme = "https://example.com/readme"
"#;
    let mut files = std::collections::BTreeMap::from([
        ("manifest.toml".to_owned(), source.as_bytes().to_vec()),
        ("web/index.html".to_owned(), b"<h1>Demo</h1>".to_vec()),
        ("docs/manual.md".to_owned(), b"# Demo\n".to_vec()),
    ]);
    let document = waz_manifest(&files).unwrap();
    for (field, value) in [
        ("format", "waz/3"),
        ("backend", "wasm/other.wasm"),
        ("frontend", "public"),
    ] {
        let mut changed = document.clone();
        changed[field] = value.into();
        assert!(waz_layout(&files, &changed).is_err());
    }
    for url in [
        "http://example.com/readme",
        "https://user:password@example.com/readme",
        "javascript:alert(1)",
    ] {
        let mut changed = document.clone();
        changed["docs"]["readme"] = url.into();
        assert!(waz_layout(&files, &changed).is_err());
    }
    let mut standard = document.clone();
    standard["package"]["name"] = "std/comm/demo".into();
    assert!(waz_layout(&files, &standard).is_err());
    standard["package"]["author"] = "dev.genmeta.tech.dhttp.net".into();
    waz_layout(&files, &standard).unwrap();
    files.remove("docs/manual.md");
    assert!(waz_layout(&files, &document).is_err());
    files.insert("docs/manual.md".into(), vec![0xff]);
    assert!(waz_layout(&files, &document).is_err());
}
