use std::{io::ErrorKind, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dhttp_home::DhttpHome;
use dhttp_identity::name::DhttpName;
use p384::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use snafu::{FromString, ResultExt};
use tokio::io::AsyncWriteExt;
use x509_cert::{
    builder::{Builder, RequestBuilder},
    der::EncodePem,
};

use crate::cli::{EncodeCsrSnafu, Error, GenerateCsrSnafu, GenerateKeySnafu};

pub(crate) trait KeyMaterialGenerator {
    fn generate_key(&self) -> Result<String, Error>;
    fn generate_csr(&self, key_pem: &str, full_name: &str) -> Result<String, Error>;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct P384Generator;

impl KeyMaterialGenerator for P384Generator {
    fn generate_key(&self) -> Result<String, Error> {
        p384::ecdsa::SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng)
            .to_pkcs8_pem(LineEnding::LF)
            .map(|key| key.to_string())
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            .context(GenerateKeySnafu)
    }

    fn generate_csr(&self, key_pem: &str, full_name: &str) -> Result<String, Error> {
        let request = (|| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
            let key = p384::ecdsa::SigningKey::from_pkcs8_pem(key_pem)?;
            let subject = format!("CN={full_name},C=CN").parse()?;
            let mut builder = RequestBuilder::new(subject, &key)?;
            builder.add_extension(&x509_cert::ext::pkix::SubjectAltName(vec![
                x509_cert::ext::pkix::name::GeneralName::DnsName(
                    x509_cert::der::asn1::Ia5String::new(full_name)?,
                ),
            ]))?;
            Ok(builder.build::<p384::ecdsa::DerSignature>()?)
        })()
        .context(GenerateCsrSnafu)?;
        request
            .to_pem(LineEnding::LF)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            .context(EncodeCsrSnafu)
    }
}

pub(crate) struct LazyKeyMaterial<G = P384Generator> {
    name: DhttpName<'static>,
    generator: G,
    key_pem: Option<String>,
    csr_pem: Option<String>,
}

impl<G> LazyKeyMaterial<G>
where
    G: KeyMaterialGenerator,
{
    pub(crate) fn new(name: DhttpName<'_>, generator: G) -> Self {
        Self {
            name: name.into_owned(),
            generator,
            key_pem: None,
            csr_pem: None,
        }
    }

    pub(crate) fn ensure_key(&mut self) -> Result<&str, Error> {
        if self.key_pem.is_none() {
            self.key_pem = Some(super::progress::run_sync(
                super::progress::GENERATE_KEY,
                || self.generator.generate_key(),
            )?);
        }
        Ok(self
            .key_pem
            .as_deref()
            .expect("key material was generated above"))
    }

    pub(crate) fn csr_pem(&mut self) -> Result<&str, Error> {
        self.ensure_key()?;
        if self.csr_pem.is_none() {
            let csr = self.generator.generate_csr(
                self.key_pem
                    .as_deref()
                    .expect("key material was generated above"),
                self.name.as_full(),
            )?;
            self.csr_pem = Some(csr);
        }
        Ok(self
            .csr_pem
            .as_deref()
            .expect("CSR material was generated above"))
    }

    pub(crate) fn key_pem(&self) -> Option<&str> {
        self.key_pem.as_deref()
    }
}

impl LazyKeyMaterial<P384Generator> {
    pub(crate) fn for_name(name: DhttpName<'_>) -> Self {
        Self::new(name, P384Generator)
    }
}

const PENDING_RENEWAL_FILE: &str = ".renew-pending.json";

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PendingRenewal {
    target: String,
    kind: String,
    sequence: u32,
    device_name: String,
    operation_key: String,
    key_pem: String,
    csr_pem: String,
}

impl PendingRenewal {
    pub(crate) async fn load(
        dhttp_home: &DhttpHome,
        name: DhttpName<'_>,
        kind: &str,
        sequence: u32,
    ) -> Result<Option<Self>, Error> {
        let path = pending_path(dhttp_home, name.clone());
        let contents = match tokio::fs::read(&path).await {
            Ok(contents) => contents,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(pending_error(format!(
                    "failed to read pending renewal material at {}: {error}",
                    path.display()
                )));
            }
        };
        ensure_restricted_permissions(&path).await?;
        let pending: Self = serde_json::from_slice(&contents).map_err(|error| {
            pending_error(format!(
                "pending renewal material at {} is invalid: {error}",
                path.display()
            ))
        })?;
        pending.validate(name.as_full(), kind, sequence, &path)?;
        Ok(Some(pending))
    }

    pub(crate) async fn create(
        dhttp_home: &DhttpHome,
        name: DhttpName<'_>,
        kind: &str,
        sequence: u32,
        device_name: &str,
    ) -> Result<Self, Error> {
        let generator = P384Generator;
        let key_pem =
            super::progress::run_sync(super::progress::GENERATE_KEY, || generator.generate_key())?;
        let csr_pem = generator.generate_csr(&key_pem, name.as_full())?;
        let pending = Self {
            target: name.as_full().to_string(),
            kind: kind.to_string(),
            sequence,
            device_name: device_name.to_string(),
            operation_key: operation_key_from_private_key(&key_pem)?,
            key_pem,
            csr_pem,
        };
        let path = pending_path(dhttp_home, name.clone());
        let bytes = serde_json::to_vec(&pending).map_err(|error| {
            pending_error(format!(
                "failed to encode pending renewal material: {error}"
            ))
        })?;
        let temp_path = path.with_extension(format!("renew-pending.tmp-{}", pending.operation_key));

        let mut options = tokio::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path).await.map_err(|error| {
            pending_error(format!(
                "failed to create pending renewal material at {}: {error}",
                temp_path.display()
            ))
        })?;
        if let Err(error) = async {
            file.write_all(&bytes).await?;
            file.flush().await?;
            file.sync_all().await
        }
        .await
        {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(pending_error(format!(
                "failed to persist pending renewal material at {}: {error}",
                temp_path.display()
            )));
        }
        drop(file);

        match tokio::fs::hard_link(&temp_path, &path).await {
            Ok(()) => {
                sync_parent_directory(&path).await?;
                tokio::fs::remove_file(&temp_path).await.map_err(|error| {
                    pending_error(format!(
                        "failed to remove temporary renewal material at {}: {error}",
                        temp_path.display()
                    ))
                })?;
                sync_parent_directory(&path).await?;
                Ok(pending)
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                tokio::fs::remove_file(&temp_path).await.map_err(|error| {
                    pending_error(format!(
                        "failed to remove temporary renewal material at {}: {error}",
                        temp_path.display()
                    ))
                })?;
                sync_parent_directory(&path).await?;
                Self::load(dhttp_home, name, kind, sequence)
                    .await?
                    .ok_or_else(|| pending_error("pending renewal material disappeared"))
            }
            Err(error) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                Err(pending_error(format!(
                    "failed to commit pending renewal material at {}: {error}",
                    path.display()
                )))
            }
        }
    }

    pub(crate) async fn remove(
        &self,
        dhttp_home: &DhttpHome,
        name: DhttpName<'_>,
    ) -> Result<(), Error> {
        Self::remove_for_name(dhttp_home, name).await
    }

    pub(crate) async fn remove_for_name(
        dhttp_home: &DhttpHome,
        name: DhttpName<'_>,
    ) -> Result<(), Error> {
        let path = pending_path(dhttp_home, name);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => sync_parent_directory(&path).await,
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(pending_error(format!(
                "failed to remove pending renewal material at {}: {error}",
                path.display()
            ))),
        }
    }

    pub(crate) fn device_name(&self) -> &str {
        &self.device_name
    }

    pub(crate) fn operation_key(&self) -> &str {
        &self.operation_key
    }

    pub(crate) fn key_pem(&self) -> &str {
        &self.key_pem
    }

    pub(crate) fn csr_pem(&self) -> &str {
        &self.csr_pem
    }

    fn validate(
        &self,
        target: &str,
        kind: &str,
        sequence: u32,
        path: &std::path::Path,
    ) -> Result<(), Error> {
        if self.target != target || self.kind != kind || self.sequence != sequence {
            return Err(pending_error(format!(
                "pending renewal material at {} belongs to another certificate chain",
                path.display()
            )));
        }
        if self.operation_key.len() < 8
            || self.operation_key.len() > 200
            || !self.operation_key.is_ascii()
            || http::HeaderValue::from_str(&self.operation_key).is_err()
            || self.key_pem.is_empty()
            || self.csr_pem.is_empty()
        {
            return Err(pending_error(format!(
                "pending renewal material at {} is incomplete",
                path.display()
            )));
        }
        Ok(())
    }
}

fn pending_path(dhttp_home: &DhttpHome, name: DhttpName<'_>) -> PathBuf {
    dhttp_home
        .identity_profile((name).as_full())
        .expect("validated identity name")
        .join(PENDING_RENEWAL_FILE)
}

#[cfg(unix)]
async fn ensure_restricted_permissions(path: &std::path::Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;

    let mode = tokio::fs::metadata(path)
        .await
        .map_err(|error| {
            pending_error(format!(
                "failed to inspect pending renewal material at {}: {error}",
                path.display()
            ))
        })?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(pending_error(format!(
            "pending renewal material at {} grants unsafe group or other access",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
async fn ensure_restricted_permissions(_path: &std::path::Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
async fn sync_parent_directory(path: &std::path::Path) -> Result<(), Error> {
    let parent = path.parent().ok_or_else(|| {
        pending_error(format!(
            "pending renewal path {} has no parent directory",
            path.display()
        ))
    })?;
    let directory = tokio::fs::File::open(parent).await.map_err(|error| {
        pending_error(format!(
            "failed to open pending renewal directory {}: {error}",
            parent.display()
        ))
    })?;
    directory.sync_all().await.map_err(|error| {
        pending_error(format!(
            "failed to sync pending renewal directory {}: {error}",
            parent.display()
        ))
    })
}

#[cfg(not(unix))]
async fn sync_parent_directory(_path: &std::path::Path) -> Result<(), Error> {
    Ok(())
}

fn pending_error(message: impl Into<String>) -> Error {
    Error::without_source(message.into())
}

fn operation_key_from_private_key(key_pem: &str) -> Result<String, Error> {
    let key = p384::SecretKey::from_pkcs8_pem(key_pem).map_err(|error| {
        pending_error(format!(
            "failed to parse generated private key for renewal key: {error}"
        ))
    })?;
    let public_key = key.public_key().to_public_key_der().map_err(|error| {
        pending_error(format!(
            "failed to encode generated public key for renewal key: {error}"
        ))
    })?;
    Ok(format!(
        "renew-v1-{}",
        URL_SAFE_NO_PAD.encode(public_key.as_bytes())
    ))
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/flow/key_material.rs"]
mod tests;
