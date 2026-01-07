use std::path::{Path, PathBuf};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use snafu::{IntoError, OptionExt, ResultExt, Snafu, ensure};
use tokio::{
    fs,
    io::{self, AsyncWriteExt},
};
use x509_parser::prelude::Pem;

use crate::home::identity::{Identities, Identity, Name};

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadIdentityError {
    #[snafu(display("Identity not found in directory {}", io.display()))]
    NotFound { io: PathBuf, source: io::Error },

    #[snafu(display("Provided name is not a valid DNS name"))]
    InvalidDnsName,

    #[snafu(display("Failed to load identity certificates"))]
    LoadCerts {
        path: PathBuf,
        source: LoadCertError,
    },

    #[snafu(display("Failed to load identity private key at {}", path.display()))]
    LoadKey { path: PathBuf, source: LoadKeyError },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadCertError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(display("Failed to parse pem block"))]
    Pem {
        source: x509_parser::error::PEMError,
    },
    #[snafu(display("Failed to parse certificate"))]
    Nom {
        source: x509_parser::nom::Err<x509_parser::error::X509Error>,
    },
    #[snafu(display("Failed to parse certificate SAN extension"))]
    Ext {
        source: x509_parser::error::X509Error,
    },
    #[snafu(display("Certificate does not contain SAN extension"))]
    MissingSan {},
    #[snafu(display("Certificate SAN does not contain expected DNS name"))]
    NotExistInSan {},
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadKeyError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(display("Private key file permissions are too open (expected to be 600 or stricter)"))]
    PermissionsTooOpen {},
    #[snafu(display("Failed to parse certificate"))]
    Parse {
        source: rustls::pki_types::pem::Error,
    },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum SaveIdentityError {
    #[snafu(display("Failed to create identity directory at {}", path.display()))]
    CreateIdentityIo { path: PathBuf, source: io::Error },
    #[snafu(display("Failed to get metadata for path {}", path.display()))]
    Metadata { path: PathBuf, source: io::Error },
    #[snafu(display("Failed to delete old file at {}", path.display()))]
    Delete { path: PathBuf, source: io::Error },
    #[snafu(display("Failed to create file at {}", path.display()))]
    Create { path: PathBuf, source: io::Error },
    #[snafu(display("Failed to write to file at {}", path.display()))]
    Write { path: PathBuf, source: io::Error },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum ListIdentitiesError {
    #[snafu(display("Failed to list identities in directory {}", path.display()))]
    ReadDir { path: PathBuf, source: io::Error },
    #[snafu(display("Failed to read filetype of  {}", path.display()))]
    ReadFty { path: PathBuf, source: io::Error },
}

impl<'i> Identity<'i> {
    pub(crate) const CERT_FILE_NAME: &'static str = "certs.pem";
    pub(crate) const KEY_FILE_NAME: &'static str = "key.pem";

    async fn valid_cert_for_name(pem: &Pem, name: &str) -> Result<(), LoadCertError> {
        let cert = pem.parse_x509().context(load_cert_error::NomSnafu)?;
        let san = cert
            .subject_alternative_name()
            .context(load_cert_error::ExtSnafu)?
            .context(load_cert_error::MissingSanSnafu {})?;
        let found = san.value.general_names.iter().any(|gn| match gn {
            x509_parser::prelude::GeneralName::DNSName(dn) => *dn == name,
            _ => false,
        });
        ensure!(found, load_cert_error::NotExistInSanSnafu {});
        Ok(())
    }

    async fn load_certs_file(
        path: &Path,
        name: &str,
    ) -> Result<Vec<CertificateDer<'static>>, LoadCertError> {
        let mut data = std::io::Cursor::new(fs::read(path).await?);
        let (end_entity_pem, _read) = Pem::read(&mut data).context(load_cert_error::PemSnafu)?;
        // TOOD: less/more validation?
        Self::valid_cert_for_name(&end_entity_pem, name).await?;
        let mut certs = vec![CertificateDer::from(end_entity_pem.contents)];
        loop {
            match Pem::read(&mut data) {
                Ok((pem, _read)) => {
                    certs.push(CertificateDer::from(pem.contents));
                }
                Err(x509_parser::error::PEMError::MissingHeader) => break,
                result => _ = result.context(load_cert_error::PemSnafu)?,
            }
        }

        Ok(certs)
    }

    async fn load_key_file(
        path: &Path,
        _cert: &CertificateDer<'_>,
    ) -> Result<PrivateKeyDer<'static>, LoadKeyError> {
        let metadata = fs::metadata(path).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            use snafu::ensure;
            ensure!(
                metadata.mode() & 0o077 == 0,
                load_key_error::PermissionsTooOpenSnafu
            )
        }

        let data = fs::read(path).await?;
        // todo: check is public key matches certificate
        rustls::pki_types::pem::PemObject::from_pem_slice(&data).context(load_key_error::ParseSnafu)
    }

    pub async fn load_from_io(
        io: &Path,
        name: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), LoadIdentityError> {
        let _metadata = fs::metadata(io)
            .await
            .context(load_identity_error::NotFoundSnafu { io })?;

        let certs_path = io.join(Self::CERT_FILE_NAME);
        let certs = Self::load_certs_file(certs_path.as_path(), name)
            .await
            .context(load_identity_error::LoadCertsSnafu { path: certs_path })?;

        let key_path = io.join(Self::KEY_FILE_NAME);
        let key = Self::load_key_file(key_path.as_path(), &certs[0])
            .await
            .context(load_identity_error::LoadKeySnafu { path: key_path })?;

        Ok((certs, key))
    }
}

impl Identities {
    pub async fn locate_exactly(&self, name: Name<'_>) -> io::Result<PathBuf> {
        let identity_io = self.join_name(name);
        fs::metadata(identity_io.as_path())
            .await
            .map(|_| identity_io)
    }

    pub async fn locate_wildcard(&self, name: Name<'_>) -> io::Result<PathBuf> {
        let wildcard_name = name.to_wildcard_name();

        let identity_io = self.path.join(wildcard_name.as_partial_name());
        fs::metadata(identity_io.as_path())
            .await
            .map(|_| identity_io)
    }

    pub async fn locate<'a>(&self, name: Name<'a>) -> io::Result<(PathBuf, Name<'a>)> {
        match self.locate_exactly(name.borrow()).await {
            Ok(location) => Ok((location, name)),
            Err(error) => {
                let wildcard_name = name.to_wildcard_name();
                match self.locate_wildcard(wildcard_name.borrow()).await {
                    Ok(location) => Ok((location, wildcard_name)),
                    Err(_) => Err(error),
                }
            }
        }
    }

    pub async fn list(&self) -> Result<Vec<Name<'static>>, ListIdentitiesError> {
        use list_identities_error::*;
        let path = self.path.as_path();
        let mut read_io = fs::read_dir(path).await.context(ReadDirSnafu { path })?;

        let mut list = Vec::new();
        while let Some(e) = read_io.next_entry().await.context(ReadDirSnafu { path })?
            && let (path, name) = (e.path(), e.file_name())
            && e.file_type().await.context(ReadFtySnafu { path })?.is_dir()
            && let Ok(name) = Name::try_from_str_partial(name.to_string_lossy())
        {
            list.push(name);
        }
        Ok(list)
    }

    pub async fn exist_exactly(&self, name: Name<'_>) -> bool {
        self.locate_exactly(name).await.is_ok()
    }

    pub async fn exist_wildcard(&self, name: Name<'_>) -> bool {
        self.locate_wildcard(name).await.is_ok()
    }

    pub async fn exists(&self, name: Name<'_>) -> bool {
        self.locate(name).await.is_ok()
    }

    pub async fn load_exactly(
        &self,
        name: Name<'_>,
    ) -> Result<Identity<'static>, LoadIdentityError> {
        let identity_io = self
            .locate_exactly(name.borrow())
            .await
            .context(load_identity_error::NotFoundSnafu { io: self.as_path() })?;
        let (certs, key) = Identity::load_from_io(identity_io.as_path(), name.as_ref()).await?;
        let name = name.to_owned();
        Ok(Identity { name, certs, key })
    }

    pub async fn load_wildcard(
        &self,
        name: Name<'_>,
    ) -> Result<Identity<'static>, LoadIdentityError> {
        let wildcard_name = name.to_wildcard_name();
        let identity_io = self
            .locate_wildcard(wildcard_name.borrow())
            .await
            .context(load_identity_error::NotFoundSnafu { io: self.as_path() })?;
        let (certs, key) =
            Identity::load_from_io(identity_io.as_path(), wildcard_name.as_ref()).await?;
        let name = wildcard_name.to_owned();
        Ok(Identity { name, certs, key })
    }

    pub async fn load(&self, name: Name<'_>) -> Result<Identity<'static>, LoadIdentityError> {
        let (identity_io, name) = self
            .locate(name)
            .await
            .context(load_identity_error::NotFoundSnafu { io: self.as_path() })?;
        let (certs, key) = Identity::load_from_io(identity_io.as_path(), name.as_ref()).await?;
        let name = name.to_owned();
        Ok(Identity { name, certs, key })
    }

    pub async fn save(
        &self,
        name: Name<'_>,
        cert: &[u8],
        key: &[u8],
    ) -> Result<(), SaveIdentityError> {
        // create identity io
        let identity_io = self.join_name(name);
        fs::create_dir_all(identity_io.as_path()).await.context(
            save_identity_error::CreateIdentityIoSnafu {
                path: identity_io.clone(),
            },
        )?;

        // prepare open options for create then write files
        let mut open_options = fs::OpenOptions::new();
        open_options.create_new(true).write(true);
        #[cfg(unix)]
        open_options.mode(0o600);

        // remove old file if any
        let path = identity_io.join(Identity::CERT_FILE_NAME);
        if let Err(error) = fs::remove_file(path.as_path()).await
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(save_identity_error::DeleteSnafu { path }.into_error(error));
        }

        // create then write new cert file
        open_options
            .open(path.as_path())
            .await
            .context(save_identity_error::CreateSnafu { path: path.clone() })?
            .write_all(cert)
            .await
            .context(save_identity_error::WriteSnafu { path: path.clone() })?;

        // remove old file if any
        let path = identity_io.join(Identity::KEY_FILE_NAME);
        if let Err(error) = fs::remove_file(path.as_path()).await
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(save_identity_error::DeleteSnafu { path }.into_error(error));
        }

        // create then write new key file
        open_options
            .open(path.as_path())
            .await
            .context(save_identity_error::CreateSnafu { path: path.clone() })?
            .write_all(key)
            .await
            .context(save_identity_error::WriteSnafu { path: path.clone() })?;

        Ok(())
    }
}
