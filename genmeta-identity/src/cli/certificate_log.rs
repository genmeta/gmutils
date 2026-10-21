use std::path::PathBuf;

use dhttp::log::cert::{CertificateAction, CertificateLogRecord, DefaultCertificateFormatter};
use dhttp_home::identity::IdentityProfile;
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub(crate) enum WriteCertificateLogError {
    #[snafu(display("failed to load committed identity {}", profile.name()))]
    LoadIdentity {
        profile: Box<IdentityProfile>,
        source: dhttp_home::identity::ssl::LoadIdentityError,
    },
    #[snafu(display("committed identity {} has no leaf certificate", profile.name()))]
    MissingLeaf { profile: Box<IdentityProfile> },
    #[snafu(display(
        "failed to extract DHTTP certificate chain key from committed identity {}",
        profile.name()
    ))]
    Chain {
        profile: Box<IdentityProfile>,
        source: dhttp_home::certificate::ExtractDhttpSubjectKeyIdentifierError,
    },
    #[snafu(display("failed to construct certificate log record for {}", profile.name()))]
    BuildRecord {
        profile: Box<IdentityProfile>,
        source: dhttp::log::cert::CertificateLogRecordFromLeafDerError,
    },
    #[snafu(display("failed to format certificate log record for {}", profile.name()))]
    Format {
        profile: Box<IdentityProfile>,
        source: dhttp::log::FormatError,
    },
    #[snafu(display("failed to create certificate log directory {}", path.display()))]
    CreateDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("failed to open certificate log {}", path.display()))]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("failed to append certificate log {}", path.display()))]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

pub(crate) async fn write_after_commit(
    profile: &IdentityProfile,
    action: CertificateAction,
) -> Result<(), WriteCertificateLogError> {
    let identity =
        profile
            .load_identity()
            .await
            .context(write_certificate_log_error::LoadIdentitySnafu {
                profile: Box::new(profile.clone()),
            })?;
    let leaf = identity
        .certs()
        .first()
        .context(write_certificate_log_error::MissingLeafSnafu {
            profile: Box::new(profile.clone()),
        })?;
    let chain = dhttp_home::certificate::extract_dhttp_subject_key_identifier(identity.certs())
        .context(write_certificate_log_error::ChainSnafu {
            profile: Box::new(profile.clone()),
        })?
        .chain()
        .clone();
    let record = CertificateLogRecord::from_leaf_der(
        chrono::Local::now().fixed_offset(),
        action,
        chain,
        leaf.as_ref(),
    )
    .context(write_certificate_log_error::BuildRecordSnafu {
        profile: Box::new(profile.clone()),
    })?;
    let formatted = DefaultCertificateFormatter::format(&record).context(
        write_certificate_log_error::FormatSnafu {
            profile: Box::new(profile.clone()),
        },
    )?;

    let directory = profile.join("log");
    let legacy = profile.logs_dir();
    if !directory.exists() && legacy.exists() {
        let metadata = tokio::fs::symlink_metadata(&legacy)
            .await
            .context(write_certificate_log_error::CreateDirectorySnafu { path: &legacy })?;
        if !metadata.file_type().is_dir() {
            return Err(WriteCertificateLogError::CreateDirectory {
                path: legacy,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "legacy log directory must be a real directory",
                ),
            });
        }
        tokio::fs::rename(&legacy, &directory)
            .await
            .context(write_certificate_log_error::CreateDirectorySnafu { path: &directory })?;
    }
    tokio::fs::create_dir_all(&directory)
        .await
        .context(write_certificate_log_error::CreateDirectorySnafu { path: &directory })?;
    let path = profile.join("log/cert.log");
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .context(write_certificate_log_error::OpenSnafu { path: &path })?;
    file.write_all(formatted.as_bytes())
        .await
        .context(write_certificate_log_error::WriteSnafu { path: &path })
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use base64::Engine as _;
    use dhttp::log::cert::CertificateAction;
    use dhttp_home::{DhttpHome, identity::IdentityProfile};
    use dhttp_identity::name::DhttpName;

    use super::write_after_commit;

    struct CommittedIdentityFixture {
        profile: IdentityProfile,
        home_path: PathBuf,
    }

    impl Drop for CommittedIdentityFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.home_path);
        }
    }

    async fn committed_identity_fixture(label: &str) -> CommittedIdentityFixture {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home_path = std::env::temp_dir().join(format!(
            "genmeta-identity-certificate-log-{label}-{}-{nonce}",
            std::process::id()
        ));
        let home = DhttpHome::new(home_path.clone());
        let name: DhttpName<'static> = "fixture.example".parse().unwrap();
        let profile = home
            .identity_profile((name).as_full())
            .expect("validated identity name");
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(include_bytes!("../../tests/fixtures/valid.der"));
        let mut cert_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            cert_pem.push_str(std::str::from_utf8(line).unwrap());
            cert_pem.push('\n');
        }
        cert_pem.push_str("-----END CERTIFICATE-----\n");
        use p384::pkcs8::EncodePrivateKey;
        let key_pem = p384::ecdsa::SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng)
            .to_pkcs8_pem(p384::pkcs8::LineEnding::LF)
            .unwrap();
        profile
            .save_identity(cert_pem.as_bytes(), key_pem.as_bytes())
            .await
            .unwrap();
        CommittedIdentityFixture { profile, home_path }
    }

    #[tokio::test]
    async fn committed_identity_appends_one_complete_record() {
        let fixture = committed_identity_fixture("writes-record").await;
        write_after_commit(&fixture.profile, CertificateAction::Apply)
            .await
            .unwrap();
        let bytes = tokio::fs::read(fixture.profile.join("log/cert.log"))
            .await
            .unwrap();
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert!(
            bytes
                .windows(b" APPLY ".len())
                .any(|window| window == b" APPLY ")
        );
    }

    #[tokio::test]
    async fn logging_failure_does_not_remove_committed_material() {
        let fixture = committed_identity_fixture("log-failure").await;
        tokio::fs::create_dir_all(fixture.profile.join("log/cert.log"))
            .await
            .unwrap();
        assert!(
            write_after_commit(&fixture.profile, CertificateAction::Renew)
                .await
                .is_err()
        );
        assert!(fixture.profile.ssl_dir().join("fullchain.crt").exists());
        assert!(fixture.profile.ssl_dir().join("privkey.pem").exists());
    }

    #[tokio::test]
    async fn legacy_logs_move_to_log_without_losing_history() {
        let fixture = committed_identity_fixture("legacy-logs").await;
        let legacy = fixture.profile.logs_dir();
        tokio::fs::create_dir_all(&legacy).await.unwrap();
        tokio::fs::write(legacy.join("cert.log"), b"previous record\n")
            .await
            .unwrap();
        write_after_commit(&fixture.profile, CertificateAction::Renew)
            .await
            .unwrap();
        assert!(!legacy.exists());
        let content = tokio::fs::read_to_string(fixture.profile.join("log/cert.log"))
            .await
            .unwrap();
        assert!(content.starts_with("previous record\n"));
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains(" RENEW "));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_log_symlink_is_rejected_without_moving_its_target() {
        let fixture = committed_identity_fixture("legacy-log-link").await;
        let target = fixture.home_path.join("other-logs");
        tokio::fs::create_dir(&target).await.unwrap();
        tokio::fs::write(target.join("keep"), b"unchanged")
            .await
            .unwrap();
        let legacy = fixture.profile.logs_dir();
        std::os::unix::fs::symlink(&target, &legacy).unwrap();
        assert!(
            write_after_commit(&fixture.profile, CertificateAction::Renew)
                .await
                .is_err()
        );
        assert!(
            tokio::fs::symlink_metadata(legacy)
                .await
                .unwrap()
                .is_symlink()
        );
        assert_eq!(
            tokio::fs::read(target.join("keep")).await.unwrap(),
            b"unchanged"
        );
        assert!(!fixture.profile.join("log").exists());
    }
}
