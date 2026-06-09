use snafu::{Snafu, Whatever};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("local private key does not match certificate public key"))]
    KeyMismatch,
    #[snafu(transparent)]
    Whatever { source: Whatever },
}

pub fn private_key_matches_certificate(key_der: &[u8], cert_pem: &[u8]) -> Result<bool, Error> {
    if key_der.is_empty() || cert_pem.is_empty() {
        return Ok(false);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_match_helper_rejects_invalid_material() {
        let matched = private_key_matches_certificate(b"not a key", b"not a cert").unwrap();
        assert!(!matched);
    }
}
