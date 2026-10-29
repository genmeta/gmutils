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
