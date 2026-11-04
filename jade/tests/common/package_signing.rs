use snafu::ResultExt;

pub(super) fn verify_certificates(
    certificates: &[rustls::pki_types::CertificateDer<'_>],
    author: &str,
) -> Result<(), snafu::Whatever> {
    use rustls::pki_types::pem::PemObject;
    let test_root = rustls::pki_types::CertificateDer::from_pem_slice(include_bytes!(
        "../../../genmeta-identity/tests/fixtures/code-signing/root.cert.pem"
    ))
    .whatever_context("invalid isolated test root")?;
    genmeta_identity::code_signing::verify_chain_with_root(
        certificates,
        author,
        rustls::pki_types::UnixTime::now(),
        test_root.as_ref(),
    )?;
    Ok(())
}
