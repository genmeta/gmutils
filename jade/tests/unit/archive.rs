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
