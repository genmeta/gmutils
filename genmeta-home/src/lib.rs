pub mod identity;

use std::path::{Path, PathBuf};

#[cfg(any(unix, windows))]
use snafu::OptionExt;
use snafu::Snafu;

use crate::identity::Identities;

#[derive(Debug, Clone)]
pub struct GenmetaHome {
    path: PathBuf,
}

// AsRef<Path>

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LocateGenmetaHomeError {
    #[snafu(display("failed to locate GENMETA_HOME: no home directory found"))]
    NoHome {},
    #[snafu(display("GENMETA_HOME cannot be auto located on this platform"))]
    UnsupportedPlatform {},
}

impl GenmetaHome {
    pub fn new(pathbuf: PathBuf) -> Self {
        Self { path: pathbuf }
    }

    pub fn load_from_environment() -> Result<Self, LocateGenmetaHomeError> {
        #[cfg(any(unix, windows))]
        return Ok(Self::new(
            dirs::home_dir()
                .context(locate_genmeta_home_error::NoHomeSnafu)?
                .join(".genmeta"),
        ));

        #[allow(unreachable_code)]
        locate_genmeta_home_error::UnsupportedPlatformSnafu.fail()
    }

    pub fn as_path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path)
    }

    pub fn identities(&self) -> Identities {
        Identities::from(self)
    }
}
