#![allow(dead_code)]

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use snafu::{OptionExt, ResultExt, Whatever};

use crate::target_dir;

#[derive(Debug, Clone)]
pub struct CommonPaths {
    pub root: PathBuf,
    pub homebrew: PathBuf,
    pub scoop: PathBuf,
    pub ppa: PathBuf,
    pub manifest: PathBuf,
}

impl CommonPaths {
    pub fn new(root: PathBuf) -> Self {
        Self {
            homebrew: root.join("homebrew"),
            scoop: root.join("scoop"),
            ppa: root.join("ppa"),
            manifest: root.join("manifest.toml"),
            root,
        }
    }
}

pub fn common_paths() -> Result<CommonPaths, Whatever> {
    Ok(CommonPaths::new(target_dir()?.join("common")))
}

pub async fn recreate_dir(path: &Path) -> Result<(), Whatever> {
    tokio::fs::remove_dir_all(path)
        .await
        .or_else(|error| {
            if error.kind() == ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        })
        .whatever_context(format!("failed to remove {}", path.display()))?;
    tokio::fs::create_dir_all(path)
        .await
        .whatever_context(format!("failed to create {}", path.display()))
}

pub async fn ensure_dir(path: &Path) -> Result<(), Whatever> {
    tokio::fs::create_dir_all(path)
        .await
        .whatever_context(format!("failed to create {}", path.display()))
}

pub fn normalize_s3_key(path: &Path) -> Result<String, Whatever> {
    Ok(path
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .whatever_context("failed to convert path component to utf-8")
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("/"))
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{normalize_s3_key, recreate_dir};

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gmutils-xtask-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn normalize_s3_key_uses_forward_slashes() {
        let path = Path::new("ppa")
            .join("pool")
            .join("main")
            .join("g")
            .join("gmutils.deb");
        assert_eq!(
            normalize_s3_key(&path).unwrap(),
            "ppa/pool/main/g/gmutils.deb"
        );
    }

    #[cfg(unix)]
    #[test]
    fn normalize_s3_key_rejects_non_utf8_components() {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

        let path = Path::new("ppa").join(OsStr::from_bytes(b"\xff"));

        let error = normalize_s3_key(&path).expect_err("non-utf8 path should fail");

        assert!(
            error
                .to_string()
                .starts_with("failed to convert path component to utf-8")
        );
    }

    #[tokio::test]
    async fn recreate_dir_accepts_missing_directory() {
        let path = temp_path("missing-dir");

        recreate_dir(&path).await.unwrap();

        assert!(path.is_dir());
        tokio::fs::remove_dir_all(path).await.unwrap();
    }

    #[tokio::test]
    async fn recreate_dir_reports_remove_errors() {
        let path = temp_path("file");
        tokio::fs::write(&path, b"not a directory").await.unwrap();

        let error = recreate_dir(&path)
            .await
            .expect_err("file path should fail removal as a directory");

        assert!(error.to_string().starts_with("failed to remove "));
        tokio::fs::remove_file(path).await.unwrap();
    }
}
