use super::*;

#[test]
fn key_match_helper_rejects_invalid_material() {
    assert!(private_key_matches_certificate(b"not a key", b"not a cert").is_err());
}
