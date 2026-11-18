use super::*;

#[test]
fn package_labels_preserve_the_actual_author() {
    for (canonical, displayed) in [
        (
            "dev.genmeta.tech.dhttp.net/workspace",
            "dev.genmeta.tech~/workspace",
        ),
        ("std.dhttp.net/workspace", "std~/workspace"),
        ("alice.smith.dhttp.net/hello", "alice.smith~/hello"),
        (
            "alice.dhttp.net/std/comm/message",
            "alice~/std/comm/message",
        ),
    ] {
        assert_eq!(package_id(canonical), displayed);
    }
}

#[test]
fn identity_labels_abbreviate_urls_and_error_text_at_domain_boundaries() {
    assert_eq!(
        identity("https://dev.alice.dhttp.net/app/workspace/"),
        "https://dev.alice~/app/workspace/"
    );
    assert_eq!(
        identity("Cannot connect to alice.dhttp.net (peer bob.dhttp.net)"),
        "Cannot connect to alice~ (peer bob~)"
    );
    for value in ["alice.dhttp.net.example", "alice.dhttp.network", "Alice"] {
        assert_eq!(identity(value), value);
    }
}

#[test]
fn json_output_abbreviates_identity_fields_without_changing_artifact_paths() {
    let canonical = json!({"id":"alice.dhttp.net/std/comm/message", "author":"alice.dhttp.net",
        "file":"/tmp/alice.dhttp.net/package.waz", "description":"alice.dhttp.net",
        "app":"https://alice.dhttp.net/app/workspace/",
        "context":{"author":"alice.dhttp.net", "message":"Cannot reach bob.dhttp.net"}});
    let displayed = output(canonical.clone());
    assert_eq!(displayed["id"], "alice~/std/comm/message");
    assert_eq!(displayed["author"], "alice~");
    assert_eq!(displayed["app"], "https://alice~/app/workspace/");
    assert_eq!(displayed["context"]["author"], "alice~");
    assert_eq!(displayed["context"]["message"], "Cannot reach bob~");
    assert_eq!(displayed["file"], canonical["file"]);
    assert_eq!(displayed["description"], canonical["description"]);
    for (value, expected) in [
        ("Alice.DHTTP.NET", "Alice~"),
        ("https://dhttp.net/", "https://~/"),
        ("not-dhttp.net", "not-dhttp.net"),
        ("alice.dhttp.net.evil", "alice.dhttp.net.evil"),
    ] {
        assert_eq!(identity(value), expected);
    }
}
