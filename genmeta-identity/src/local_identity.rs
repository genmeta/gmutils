use pkcs8::{DecodePrivateKey, EncodePublicKey};
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to parse certificate PEM"))]
    ParseCertificatePem,
    #[snafu(display("failed to parse X.509 certificate"))]
    ParseCertificate,
    #[snafu(display("failed to parse private key"))]
    ParsePrivateKey { source: pkcs8::Error },
    #[snafu(display("failed to encode private key public key"))]
    EncodePublicKey { source: pkcs8::spki::Error },
}

pub fn private_key_matches_certificate(key_der: &[u8], cert_pem: &[u8]) -> Result<bool, Error> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(cert_pem).map_err(|_| Error::ParseCertificatePem)?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&pem.contents).map_err(|_| Error::ParseCertificate)?;
    let cert_spki = cert.public_key().raw;

    let signing_key =
        p384::ecdsa::SigningKey::from_pkcs8_der(key_der).context(ParsePrivateKeySnafu)?;
    let verifying_key = signing_key.verifying_key();
    let key_spki = verifying_key
        .to_public_key_der()
        .context(EncodePublicKeySnafu)?;

    Ok(cert_spki == key_spki.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_match_helper_rejects_invalid_material() {
        assert!(private_key_matches_certificate(b"not a key", b"not a cert").is_err());
    }
}
