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
#[path = "../../tests/unit/cli/certificate_log.rs"]
mod tests;
