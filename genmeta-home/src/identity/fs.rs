use std::{
    iter,
    path::{Path, PathBuf},
};

use futures::{Stream, StreamExt, stream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use snafu::{IntoError, ResultExt, Snafu};
use tokio::{
    fs::{self, ReadDir},
    io::{self, AsyncWriteExt},
};
use x509_parser::prelude::Pem;

use crate::{
    GenmetaHome,
    identity::{Identity, IdentityHome, Name},
};

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadIdentityError {
    #[snafu(display("identity not found in directory {}", io.display()))]
    NotFound { io: PathBuf, source: io::Error },

    #[snafu(display("provided name is not a valid DNS name"))]
    InvalidDnsName,
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadCertError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(display("failed to parse pem block"))]
    Pem {
        source: x509_parser::error::PEMError,
    },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadKeyError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(display(
        "Private key file permissions are too open (current {current:o}, expected to be 400)"
    ))]
    PermissionsTooOpen { current: u32 },
    #[snafu(display("failed to parse certificate"))]
    Parse {
        source: rustls::pki_types::pem::Error,
    },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadIdentitySslError {
    #[snafu(display("failed to load identity certificates at {}", path.display()))]
    LoadCerts {
        path: PathBuf,
        source: LoadCertError,
    },

    #[snafu(display("failed to load identity private key at {}", path.display()))]
    LoadKey { path: PathBuf, source: LoadKeyError },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum SaveIdentityError {
    #[snafu(display("failed to create identity directory at {}", path.display()))]
    CreateIdentityDir { path: PathBuf, source: io::Error },
    #[snafu(display("failed to get metadata for path {}", path.display()))]
    Metadata { path: PathBuf, source: io::Error },
    #[snafu(display("failed to delete old file at {}", path.display()))]
    Delete { path: PathBuf, source: io::Error },
    #[snafu(display("failed to create file at {}", path.display()))]
    Create { path: PathBuf, source: io::Error },
    #[snafu(display("failed to write to file at {}", path.display()))]
    Write { path: PathBuf, source: io::Error },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum ListIdentitiesError {
    #[snafu(display("failed to list identities in directory {}", path.display()))]
    ReadDir { path: PathBuf, source: io::Error },
    #[snafu(display("failed to read filetype of {}", path.display()))]
    ReadFty { path: PathBuf, source: io::Error },
}

impl IdentityHome {
    pub(crate) const CERT_FILE_NAME: &'static str = "fullchain.crt";
    pub(crate) const KEY_FILE_NAME: &'static str = "privkey.pem";
}

impl IdentityHome {
    pub async fn certs(&self) -> Result<Vec<CertificateDer<'static>>, LoadCertError> {
        let certs_path = self.ssl_path().join(IdentityHome::CERT_FILE_NAME);
        let mut data = std::io::Cursor::new(fs::read(certs_path.as_path()).await?);
        let (end_entity_pem, _read) = Pem::read(&mut data).context(load_cert_error::PemSnafu)?;
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

    pub async fn key(&self) -> Result<PrivateKeyDer<'static>, LoadKeyError> {
        let key_path = self.ssl_path().join(IdentityHome::KEY_FILE_NAME);
        let metadata = fs::metadata(key_path.as_path()).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            use snafu::ensure;
            let permissions = metadata.mode() & 0o777;
            ensure!(
                permissions == 0o400,
                load_key_error::PermissionsTooOpenSnafu {
                    current: permissions
                }
            )
        }

        let data = fs::read(key_path.as_path()).await?;
        rustls::pki_types::pem::PemObject::from_pem_slice(&data).context(load_key_error::ParseSnafu)
    }

    pub async fn ssl(&self) -> Result<Identity, LoadIdentitySslError> {
        let certs_path = self.ssl_path().join(IdentityHome::CERT_FILE_NAME);
        let certs = self
            .certs()
            .await
            .context(load_identity_ssl_error::LoadCertsSnafu { path: certs_path })?;

        let key_path = self.ssl_path().join(IdentityHome::KEY_FILE_NAME);
        let key = self
            .key()
            .await
            .context(load_identity_ssl_error::LoadKeySnafu { path: key_path })?;

        Ok(Identity {
            name: self.name.clone(),
            certs,
            key,
        })
    }
}

impl GenmetaHome {
    pub async fn locate_identity_exactly(&self, name: Name<'_>) -> io::Result<PathBuf> {
        let identity_io = self.join_identity_name(name);
        fs::metadata(identity_io.as_path())
            .await
            .map(|_| identity_io)
    }

    pub async fn locate_identity_wildcard(&self, name: Name<'_>) -> io::Result<PathBuf> {
        let wildcard_name = name.to_wildcard_name();

        let identity_io = self.join(wildcard_name.as_partial());
        fs::metadata(identity_io.as_path())
            .await
            .map(|_| identity_io)
    }

    pub async fn locate_identity<'a>(&self, name: Name<'a>) -> io::Result<(PathBuf, Name<'a>)> {
        match self.locate_identity_exactly(name.borrow()).await {
            Ok(location) => Ok((location, name)),
            Err(error) => {
                let wildcard_name = name.to_wildcard_name();
                match self.locate_identity_wildcard(wildcard_name.borrow()).await {
                    Ok(location) => Ok((location, wildcard_name)),
                    Err(_) => Err(error),
                }
            }
        }
    }

    pub fn identities(&self) -> impl Stream<Item = Result<Name<'static>, ListIdentitiesError>> {
        use list_identities_error::*;
        async fn next_identity(
            read_dir: &mut ReadDir,
            path: &Path,
        ) -> Result<Option<Name<'static>>, ListIdentitiesError> {
            loop {
                let Some(e) = read_dir.next_entry().await.context(ReadDirSnafu { path })? else {
                    return Ok(None);
                };
                if let (entry_path, name) = (e.path(), e.file_name())
                    && e.file_type()
                        .await
                        .context(ReadFtySnafu {
                            path: entry_path.clone(),
                        })?
                        .is_dir()
                    && let Ok(name) = Name::try_from_str_partial(name.to_string_lossy())
                    && fs::metadata(entry_path.join(IdentityHome::SSL_DIR_NAME))
                        .await
                        .is_ok()
                {
                    return Ok(Some(name));
                }
            }
        }

        let path = self.as_path();
        stream::once(fs::read_dir(path)).flat_map(move |result| {
            match result.context(ReadDirSnafu { path }) {
                Err(error) => stream::iter(iter::once(Err(error))).right_stream(),
                Ok(read_dir) => stream::unfold(read_dir, move |mut read_dir| async move {
                    match next_identity(&mut read_dir, path).await {
                        Ok(Some(name)) => Some((Ok(name), read_dir)),
                        Ok(None) => None,
                        Err(e) => Some((Err(e), read_dir)),
                    }
                })
                .left_stream(),
            }
        })
    }

    pub async fn identity_exists_exactly(&self, name: Name<'_>) -> bool {
        self.locate_identity_exactly(name).await.is_ok()
    }

    pub async fn identity_exists_wildcard(&self, name: Name<'_>) -> bool {
        self.locate_identity_wildcard(name).await.is_ok()
    }

    pub async fn identity_exists(&self, name: Name<'_>) -> bool {
        self.locate_identity(name).await.is_ok()
    }

    pub async fn load_identity_exactly(
        &self,
        name: Name<'_>,
    ) -> Result<IdentityHome, LoadIdentityError> {
        let identity_io = self
            .locate_identity_exactly(name.borrow())
            .await
            .context(load_identity_error::NotFoundSnafu { io: self.as_path() })?;
        Ok(IdentityHome {
            path: identity_io,
            name: name.to_owned(),
        })
    }

    pub async fn load_identity_wildcard(
        &self,
        name: Name<'_>,
    ) -> Result<IdentityHome, LoadIdentityError> {
        let wildcard_name = name.to_wildcard_name();
        let identity_io = self
            .locate_identity_wildcard(wildcard_name.borrow())
            .await
            .context(load_identity_error::NotFoundSnafu { io: self.as_path() })?;
        Ok(IdentityHome {
            path: identity_io,
            name: wildcard_name.to_owned(),
        })
    }

    pub async fn load_identity(&self, name: Name<'_>) -> Result<IdentityHome, LoadIdentityError> {
        let (identity_io, name) = self
            .locate_identity(name)
            .await
            .context(load_identity_error::NotFoundSnafu { io: self.as_path() })?;
        Ok(IdentityHome {
            path: identity_io,
            name: name.to_owned(),
        })
    }

    pub async fn save_identity(
        &self,
        name: Name<'_>,
        cert: &[u8],
        key: &[u8],
    ) -> Result<(), SaveIdentityError> {
        // create identity dir and ssl subdir
        let identity_dir = self.join_identity_name(name);
        let ssl_dir = identity_dir.join(IdentityHome::SSL_DIR_NAME);
        fs::create_dir_all(ssl_dir.as_path()).await.context(
            save_identity_error::CreateIdentityDirSnafu {
                path: ssl_dir.clone(),
            },
        )?;

        // prepare open options for create then write files
        let mut open_options = fs::OpenOptions::new();
        open_options.create_new(true).write(true);
        #[cfg(unix)]
        // TODO: test 400 permission
        open_options.mode(0o400);

        // remove old file if any
        let path = ssl_dir.join(IdentityHome::CERT_FILE_NAME);
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
        let path = ssl_dir.join(IdentityHome::KEY_FILE_NAME);
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
