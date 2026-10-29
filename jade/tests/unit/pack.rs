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
    assert!(embedded_openapi(embedded, Some(br#"{"openapi":"3.1.0","paths":{"/x":{}}}"#)).is_err());
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
