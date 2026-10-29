//! Independent developer credentials. TLS files under `ssl/` are never changed.
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use dhttp_home::identity::IdentityProfile;
use p384::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::{FromString, ResultExt, Whatever, whatever};
use x509_cert::{
    builder::{Builder, RequestBuilder},
    der::EncodePem,
};

/// Verify at the caller's trusted time. `now` may be Registry's persisted verified_at.
/// Optional issuer-signed revocation snapshots are verified separately without issuer requests.
pub fn verify_chain(
    chain: &[CertificateDer<'_>],
    domain: &str,
    now: UnixTime,
) -> Result<(), Whatever> {
    verify_chain_with_root(chain, domain, now, dhttp::trust::DHTTP_ROOT_CA_DER)
}

/// Validate against an explicitly configured trust anchor; never accept a root from the package.
pub fn verify_chain_with_root(
    chain: &[CertificateDer<'_>],
    domain: &str,
    now: UnixTime,
    root: &[u8],
) -> Result<(), Whatever> {
    if !(2..=3).contains(&chain.len()) || (chain.len() == 3 && chain[2].as_ref() != root) {
        whatever!("developer certificate requires a bounded trusted issuer chain");
    }
    for (index, der) in chain.iter().enumerate() {
        let (rest, cert) = x509_parser::parse_x509_certificate(der.as_ref())
            .whatever_context("invalid signing chain")?;
        if !rest.is_empty() {
            whatever!("trailing signing certificate data");
        }
        if index > 1 {
            continue;
        }
        if cert.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.3"
            || cert.public_key().algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
            || cert
                .public_key()
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .is_none_or(|o| o.to_id_string() != "1.3.132.0.34")
        {
            whatever!("developer chain requires P-384 and ECDSA-SHA384");
        }
        let bc = cert
            .basic_constraints()
            .whatever_context("invalid basic constraints")?
            .ok_or_else(|| Whatever::without_source("missing basic constraints".into()))?;
        let ku = cert
            .key_usage()
            .whatever_context("invalid key usage")?
            .ok_or_else(|| Whatever::without_source("missing key usage".into()))?;
        let eku = cert
            .extended_key_usage()
            .whatever_context("invalid extended key usage")?
            .ok_or_else(|| Whatever::without_source("missing codeSigning usage".into()))?;
        if !eku.value.code_signing
            || eku.value.any
            || eku.value.server_auth
            || eku.value.client_auth
            || eku.value.email_protection
            || eku.value.time_stamping
            || eku.value.ocsp_signing
            || !eku.value.other.is_empty()
        {
            whatever!("developer chain must have only codeSigning extended key usage");
        }
        if !bc.critical || !ku.critical {
            whatever!("developer chain constraints must be critical");
        }
        if index == 0 {
            let common_names = cert.subject().iter_common_name().collect::<Vec<_>>();
            if common_names.len() != 1 || common_names[0].as_str().ok() != Some(domain) {
                whatever!("developer subject differs from canonical author");
            }
            if bc.value.ca || bc.value.path_len_constraint.is_some() || ku.value.flags != 1 {
                whatever!("developer leaf must be CA:false and digitalSignature only");
            }
            let names = cert
                .subject_alternative_name()
                .whatever_context("invalid developer SAN")?
                .ok_or_else(|| Whatever::without_source("missing developer SAN".into()))?;
            if names.value.general_names.len() != 1
                || !matches!(&names.value.general_names[0],x509_parser::extensions::GeneralName::DNSName(name) if name.as_bytes()==domain.as_bytes())
            {
                whatever!("developer SAN differs from canonical author");
            }
        } else if !bc.value.ca
            || bc.value.path_len_constraint != Some(0)
            || !matches!(ku.value.flags, 33 | 97)
        {
            whatever!("developer issuer requires CA:true,pathLen:0 and keyCertSign");
        }
    }
    let ski = dhttp_home::certificate::extract_dhttp_subject_key_identifier(chain)
        .whatever_context("invalid developer SKI")?;
    if ski.chain().usage() != dhttp_home::certificate::CertificateUsage::ClientAndServer {
        whatever!("developer certificate requires primary kind");
    }
    let root = CertificateDer::from(root);
    let anchor = webpki::anchor_from_trusted_cert(&root)
        .whatever_context("invalid compiled signing root")?;
    let leaf =
        webpki::EndEntityCert::try_from(&chain[0]).whatever_context("invalid developer leaf")?;
    leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[anchor],
        &chain[1..2],
        now,
        webpki::KeyUsage::required(&[0x2b, 6, 1, 5, 5, 7, 3, 3]),
        None,
        None,
    )
    .whatever_context("untrusted developer certificate chain")?;
    leaf.verify_is_valid_for_subject_name(
        &rustls::pki_types::ServerName::try_from(domain)
            .whatever_context("invalid developer name")?,
    )
    .whatever_context("developer name mismatch")?;
    Ok(())
}

pub fn fingerprint(chain: &[CertificateDer<'_>]) -> Result<String, Whatever> {
    let leaf = chain
        .first()
        .ok_or_else(|| Whatever::without_source("missing developer leaf".into()))?;
    Ok(format!("{:x}", Sha256::digest(leaf.as_ref())))
}

pub fn parse_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>, Whatever> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .whatever_context("invalid developer certificate PEM")
}

/// Check an independently imported issuer CRL, if one is available. Never contacts CertServer.
pub fn check_local_revocations(
    chain: &[CertificateDer<'_>],
    directory: &Path,
) -> Result<(), Whatever> {
    use x509_parser::prelude::FromDer;
    let issuer_der = chain
        .get(1)
        .ok_or_else(|| Whatever::without_source("missing developer issuer".into()))?;
    let path = directory.join(format!("{:x}.crl", Sha256::digest(issuer_der.as_ref())));
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(Whatever::with_source(
                Box::new(e),
                "failed to read developer CRL".into(),
            ));
        }
    };
    if bytes.len() > 4 * 1024 * 1024 {
        whatever!("developer CRL exceeds size limit");
    }
    let (rest, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(&bytes)
        .whatever_context("invalid developer CRL")?;
    let (_, issuer) = x509_parser::parse_x509_certificate(issuer_der.as_ref())
        .whatever_context("invalid developer issuer")?;
    let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].as_ref())
        .whatever_context("invalid developer leaf")?;
    if !rest.is_empty()
        || crl.issuer() != issuer.subject()
        || crl.crl_number().is_none()
        || issuer
            .key_usage()
            .whatever_context("invalid issuer key usage")?
            .is_none_or(|ku| !ku.value.crl_sign())
        || crl.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.3"
        || crl.tbs_cert_list.signature != crl.signature_algorithm
        || crl.tbs_cert_list.extensions_map().is_err()
        || crl.extensions().iter().any(|e| e.critical)
        || crl
            .iter_revoked_certificates()
            .any(|e| e.extensions().iter().any(|x| x.critical))
        || !dhttp_home::certificate::verify_signature(
            issuer.public_key().raw,
            crl.tbs_cert_list.as_ref(),
            crl.signature_value.data.as_ref(),
        )
        .whatever_context("invalid CRL signature")?
    {
        whatever!("untrusted developer CRL");
    }
    if crl
        .iter_revoked_certificates()
        .any(|e| e.raw_serial() == leaf.raw_serial())
    {
        whatever!("developer certificate is revoked");
    }
    let now = UnixTime::now().as_secs() as i64;
    if crl.last_update().timestamp() > now
        || crl
            .next_update()
            .is_none_or(|t| t.timestamp() <= now || t.timestamp() <= crl.last_update().timestamp())
    {
        whatever!("developer CRL has expired; import a fresh signed list");
    }
    Ok(())
}

/// Bind a freshly fetched exact status response to the public leaf, not just its sequence.
pub fn verify_status(
    status: &crate::cert_server::SigningCertificateStatus,
    chain: &[CertificateDer<'_>],
    domain: &str,
    require_publication: bool,
) -> Result<(), Whatever> {
    let now = UnixTime::now().as_secs() as i64;
    let leaf = chain
        .first()
        .ok_or_else(|| Whatever::without_source("missing developer leaf".into()))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .whatever_context("invalid developer leaf")?;
    let serial = parsed
        .raw_serial_as_string()
        .replace(':', "")
        .to_ascii_lowercase();
    let issuer = chain
        .get(1)
        .map(|c| format!("{:x}", Sha256::digest(c.as_ref())));
    let supplied = parse_chain(&status.cert_pem)?;
    let ski = dhttp_home::certificate::extract_dhttp_subject_key_identifier(chain)
        .whatever_context("invalid developer SKI")?;
    if status.domain != domain
        || status.purpose != "code_signing"
        || status.kind != "primary"
        || status.sequence != ski.chain().sequence().get()
        || status.ski.as_deref() != Some(ski.to_string().as_str())
        || fingerprint(chain)? != status.fingerprint_sha256
        || supplied.first() != chain.first()
        || status.issuer_id != issuer
        || status.serial_number.as_deref().is_none_or(|s| {
            s.replace(':', "")
                .trim_start_matches('0')
                .to_ascii_lowercase()
                != serial.trim_start_matches('0')
        })
        || status.issuer_status != "trusted"
        || status.revocation_status != "good"
        || status.revoked_at.is_some()
        || status.checked_at > now + 5
        || now - status.checked_at > 30
        || (require_publication && !status.publication_allowed)
    {
        whatever!("developer certificate status is unavailable or does not permit publication");
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub cert_pem: String,
    key_pem: String,
}

impl Credentials {
    pub fn chain(&self) -> Result<Vec<CertificateDer<'static>>, Whatever> {
        parse_chain(&self.cert_pem)
    }
    pub fn key(&self) -> Result<PrivateKeyDer<'static>, Whatever> {
        PrivateKeyDer::from_pem_slice(self.key_pem.as_bytes())
            .whatever_context("invalid developer private key")
    }
    pub fn validate(&self, domain: &str) -> Result<(), Whatever> {
        self.validate_with_root(domain, dhttp::trust::DHTTP_ROOT_CA_DER)
    }
    fn validate_with_root(&self, domain: &str, root: &[u8]) -> Result<(), Whatever> {
        let chain = self.chain()?;
        verify_chain_with_root(&chain, domain, UnixTime::now(), root)?;
        let key = p384::ecdsa::SigningKey::from_pkcs8_pem(&self.key_pem)
            .whatever_context("invalid developer key")?;
        use p384::ecdsa::signature::Signer;
        let signature: p384::ecdsa::DerSignature = key.sign(b"genmeta-developer-key-check-v1");
        let (_, cert) = x509_parser::parse_x509_certificate(chain[0].as_ref())
            .whatever_context("invalid developer leaf")?;
        if !dhttp_home::certificate::verify_signature(
            cert.public_key().raw,
            b"genmeta-developer-key-check-v1",
            signature.as_bytes(),
        )
        .whatever_context("invalid developer public key")?
        {
            whatever!("developer key does not match certificate");
        }
        Ok(())
    }
}

pub fn directory(profile: &IdentityProfile) -> PathBuf {
    profile.join("code-signing")
}

fn private_directory(path: &Path) -> Result<(), Whatever> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && (!meta.is_dir() || meta.file_type().is_symlink())
    {
        whatever!("developer credential directory must not be a symlink");
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => {
            return Err(Whatever::with_source(
                Box::new(e),
                "cannot create developer directory".into(),
            ));
        }
    }
    Ok(())
}

fn read_private(path: &Path) -> Result<Vec<u8>, Whatever> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .whatever_context("cannot read developer credentials")?;
    let meta = file
        .metadata()
        .whatever_context("cannot inspect developer credentials")?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        whatever!("invalid developer credential file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            whatever!("developer credential permissions must be 0600");
        }
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .whatever_context("cannot read developer credentials")?;
    Ok(bytes)
}

fn save_private(path: &Path, bytes: &[u8]) -> Result<(), Whatever> {
    let temp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&temp)
        .whatever_context("cannot stage developer credentials")?;
    if let Err(e) = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temp, path))
    {
        let _ = fs::remove_file(&temp);
        return Err(Whatever::with_source(
            Box::new(e),
            "cannot save developer credentials".into(),
        ));
    }
    fs::File::open(path.parent().unwrap())
        .and_then(|f| f.sync_all())
        .whatever_context("cannot sync developer directory")?;
    Ok(())
}

/// The smallest usable code_signing sequence is selected; TLS credentials are never a fallback.
pub fn load(profile: &IdentityProfile, sequence: Option<u32>) -> Result<Credentials, Whatever> {
    let root = directory(profile);
    private_directory(&root)?;
    let explicit = sequence.is_some();
    let mut sequences = if let Some(sequence) = sequence {
        vec![sequence]
    } else {
        fs::read_dir(&root).whatever_context("developer credentials missing; run genmeta identity developer purchase, then apply")?.filter_map(Result::ok).filter(|e|e.file_type().is_ok_and(|t|t.is_dir())).filter_map(|e|e.file_name().to_str()?.parse::<u32>().ok()).collect()
    };
    sequences.sort_unstable();
    let mut last_error = None;
    for sequence in sequences {
        let dir = root.join(sequence.to_string());
        private_directory(&dir)?;
        let result = (|| {
            let credentials: Credentials =
                serde_json::from_slice(&read_private(&dir.join("credentials.json"))?)
                    .whatever_context("invalid developer credentials")?;
            credentials.validate(profile.name())?;
            Ok(credentials)
        })();
        match result {
            Ok(c) => return Ok(c),
            Err(e) if explicit => return Err(e),
            Err(error) => last_error = Some(error),
        }
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    whatever!(
        "no usable developer credentials; run genmeta identity developer purchase, then apply or renew"
    );
}

#[derive(Serialize, Deserialize)]
pub struct Pending {
    domain: String,
    sequence: Option<u32>,
    operation_key: String,
    key_pem: String,
    csr_pem: String,
    #[serde(default)]
    issuance_submitted: bool,
}

impl Pending {
    pub fn prepare(profile: &IdentityProfile, sequence: Option<u32>) -> Result<Self, Whatever> {
        let root = directory(profile);
        private_directory(&root)?;
        let path = root.join(match sequence {
            Some(s) => format!("renew-{s}.pending.json"),
            None => "apply.pending.json".into(),
        });
        if path.exists() {
            let pending: Self = serde_json::from_slice(&read_private(&path)?)
                .whatever_context("invalid pending developer request")?;
            if pending.domain != profile.name() || pending.sequence != sequence {
                whatever!("pending developer request identity mismatch");
            }
            return Ok(pending);
        }
        let key = p384::ecdsa::SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
        let key_pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .whatever_context("cannot generate developer key")?
            .to_string();
        let subject = format!("CN={}", profile.name())
            .parse()
            .whatever_context("invalid developer subject")?;
        let mut builder =
            RequestBuilder::new(subject, &key).whatever_context("cannot build developer CSR")?;
        builder
            .add_extension(&x509_cert::ext::pkix::SubjectAltName(vec![
                x509_cert::ext::pkix::name::GeneralName::DnsName(
                    x509_cert::der::asn1::Ia5String::new(profile.name())
                        .whatever_context("invalid developer name")?,
                ),
            ]))
            .whatever_context("cannot build developer CSR SAN")?;
        let csr_pem = builder
            .build::<p384::ecdsa::DerSignature>()
            .whatever_context("cannot sign developer CSR")?
            .to_pem(LineEnding::LF)
            .whatever_context("cannot encode developer CSR")?;
        let pending = Self {
            domain: profile.name().into(),
            sequence,
            operation_key: format!("developer-{:x}", Sha256::digest(key_pem.as_bytes())),
            key_pem,
            csr_pem,
            issuance_submitted: false,
        };
        save_private(
            &path,
            &serde_json::to_vec(&pending)
                .whatever_context("cannot encode pending developer request")?,
        )?;
        Ok(pending)
    }
    /// Caller holds the profile lock for this complete recovery/request/install operation.
    pub async fn request_certificate(
        &mut self,
        profile: &IdentityProfile,
        server: &crate::cert_server::CertServer,
        token: &str,
        device: &str,
    ) -> Result<crate::cert_server::DeveloperCertificate, crate::cert_server::Error> {
        if let Some(sequence) = self.sequence {
            return server
                .renew_developer_certificate(
                    token,
                    &self.domain,
                    sequence,
                    &self.csr_pem,
                    &self.operation_key,
                )
                .await;
        }
        let mut page = 1;
        loop {
            let list = server
                .code_signing_certificates(token, &self.domain, page)
                .await?;
            for item in &list.list {
                if let Some(serial) = &item.serial_number {
                    let detail = server.developer_certificate_detail(token, serial).await?;
                    if detail.certificate.csr.trim() == self.csr_pem.trim() {
                        return Ok(detail);
                    }
                }
            }
            if list.pagination.page_size == 0
                || page.saturating_mul(list.pagination.page_size) >= list.pagination.total
            {
                break;
            }
            page += 1;
        }
        if self.issuance_submitted {
            return Err(crate::cert_server::Error::without_source("Developer issuance outcome is pending; retry the same command later to recover its original CSR. No second issuance was submitted.".into()));
        }
        self.issuance_submitted = true;
        self.persist(profile)
            .map_err(crate::cert_server::Error::from)?;
        let result = server
            .issue_developer_certificate(token, &self.domain, device, &self.csr_pem)
            .await;
        if result
            .as_ref()
            .err()
            .is_some_and(issuance_definitely_rejected)
        {
            self.issuance_submitted = false;
            self.persist(profile)
                .map_err(crate::cert_server::Error::from)?;
        }
        result
    }
    fn persist(&self, profile: &IdentityProfile) -> Result<(), Whatever> {
        if self.domain != profile.name() {
            whatever!("pending developer profile mismatch");
        }
        save_private(
            &directory(profile).join(match self.sequence {
                Some(s) => format!("renew-{s}.pending.json"),
                None => "apply.pending.json".into(),
            }),
            &serde_json::to_vec(self)
                .whatever_context("cannot encode pending developer request")?,
        )
    }
    pub fn csr(&self) -> &str {
        &self.csr_pem
    }
    pub fn operation_key(&self) -> &str {
        &self.operation_key
    }
    pub fn install(
        self,
        profile: &IdentityProfile,
        detail: &crate::cert_server::DeveloperCertificate,
    ) -> Result<(), Whatever> {
        self.install_with_root(profile, detail, dhttp::trust::DHTTP_ROOT_CA_DER)
    }
    fn install_with_root(
        self,
        profile: &IdentityProfile,
        detail: &crate::cert_server::DeveloperCertificate,
        root: &[u8],
    ) -> Result<(), Whatever> {
        let cert = &detail.certificate;
        if detail.purpose != "code_signing"
            || cert.domain != self.domain
            || cert.kind != "primary"
            || self.sequence.is_some_and(|s| s != cert.sequence)
            || cert.csr.trim() != self.csr_pem.trim()
        {
            whatever!("developer certificate response does not match pending request");
        }
        let credentials = Credentials {
            cert_pem: cert.cert_pem.clone(),
            key_pem: self.key_pem,
        };
        credentials.validate_with_root(profile.name(), root)?;
        let chain = credentials.chain()?;
        let ski = dhttp_home::certificate::extract_dhttp_subject_key_identifier(&chain)
            .whatever_context("invalid developer SKI")?;
        if ski.chain().sequence().get() != cert.sequence
            || cert.ski.as_deref() != Some(ski.to_string().as_str())
        {
            whatever!("developer certificate sequence mismatch");
        }
        let root = directory(profile);
        let dir = root.join(cert.sequence.to_string());
        private_directory(&dir)?;
        save_private(
            &dir.join("credentials.json"),
            &serde_json::to_vec(&credentials)
                .whatever_context("cannot encode developer credentials")?,
        )?;
        fs::remove_file(root.join(match self.sequence {
            Some(s) => format!("renew-{s}.pending.json"),
            None => "apply.pending.json".into(),
        }))
        .whatever_context("cannot clear completed developer request")?;
        Ok(())
    }
}

/// Serialize local operations across processes; do not issue concurrent CSRs for one profile.
pub fn lock(profile: &IdentityProfile) -> Result<fs::File, Whatever> {
    let root = directory(profile);
    private_directory(&root)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(root.join(".lock"))
        .whatever_context("cannot open developer credential lock")?;
    file.try_lock()
        .whatever_context("another developer credential operation is in progress")?;
    Ok(file)
}

#[cfg(test)]
#[path = "../tests/unit/code_signing.rs"]
mod tests;

// The current initial-issuance endpoint has no server idempotency key. A 5xx can
// occur after tx.commit while reloading the response, so it never authorizes a
// new POST. Only documented precommit client refusals, or a connect failure
// before an HTTP request was sent, can reopen the same pending CSR for submit.
fn issuance_definitely_rejected(error: &crate::cert_server::Error) -> bool {
    match error {
        crate::cert_server::Error::Request { source } => source.is_connect(),
        crate::cert_server::Error::Api { status, code, .. } => {
            status.is_client_error()
                && matches!(
                    code.as_str(),
                    "1001"
                        | "1002"
                        | "1008"
                        | "1110"
                        | "1201"
                        | "1202"
                        | "1203"
                        | "1204"
                        | "1206"
                        | "1401"
                        | "1402"
                        | "1403"
                        | "1404"
                        | "1405"
                        | "1406"
                        | "1410"
                        | "1425"
                        | "1428"
                        | "1429"
                )
        }
        _ => false,
    }
}
