pub mod identity;

use std::path::{Path, PathBuf};

use crate::home::identity::Identities;

#[derive(Debug, Clone)]
pub struct GenmetaHome {
    path: PathBuf,
}

impl GenmetaHome {
    pub fn new(pathbuf: PathBuf) -> Self {
        Self { path: pathbuf }
    }

    pub fn load_from_environment() -> Option<Self> {
        #[cfg(any(unix, windows))]
        return Some(Self::new(dirs::home_dir()?.join(".genmeta")));

        #[allow(unreachable_code)]
        None
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
