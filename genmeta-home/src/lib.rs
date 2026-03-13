pub mod identity;

use std::path::{Path, PathBuf};

#[cfg(any(unix, windows))]
use snafu::OptionExt;
use snafu::Snafu;

#[derive(Debug, Clone)]
pub struct GenmetaHome {
    path: PathBuf,
}

// AsRef<Path>

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LocateGenmetaHomeError {
    #[cfg(any(unix, windows))]
    #[snafu(display("cannot locate home directory"))]
    NoHome {},
    #[snafu(display(
        "GENMETA_HOME cannot be automatically located on this platform, try setting GENMETA_HOME environment variable"
    ))]
    UnsupportedPlatform {},
}

impl GenmetaHome {
    pub fn new(pathbuf: PathBuf) -> Self {
        Self { path: pathbuf }
    }

    pub fn load_from_environment() -> Result<Self, LocateGenmetaHomeError> {
        if let Some(path) = std::env::var_os("GENMETA_HOME") {
            return Ok(Self::new(PathBuf::from(path)));
        }

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
}
