use std::path::{Path, PathBuf};

use genmeta_network::{home::DhttpHome, name::DhttpName};
use snafu::{IntoError, ResultExt, Snafu};
use tokio::{fs, io::AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WelcomeServiceCreated {
    pub(crate) config_db_path: PathBuf,
    pub(crate) welcome_page_path: PathBuf,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WelcomeServiceError {
    #[snafu(display("failed to initialize Pishoo configuration: {source}"))]
    Configuration {
        source: crate::cli::flow::site::Error,
    },

    #[snafu(display("failed to create identity profile directory at {}", path.display()))]
    CreateProfileDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to create welcome page directory at {}", path.display()))]
    CreateWelcomePageDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to inspect welcome service file {}", path.display()))]
    Metadata {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to create welcome service file {}", path.display()))]
    CreateFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to write welcome service file {}", path.display()))]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to roll back incomplete welcome service file {}", path.display()))]
    RollbackDelete {
        path: PathBuf,
        source: std::io::Error,
    },
}

const WELCOME_PAGE_PATH: &str = "file/welcome/index.html";

pub(crate) async fn maybe_create_welcome_service(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
) -> Result<Option<WelcomeServiceCreated>, WelcomeServiceError> {
    let profile = dhttp_home.identity_profile(name.borrow());
    let config_db_path = profile.config_db_path();
    let welcome_page_path = profile.join(WELCOME_PAGE_PATH);

    if path_exists(&config_db_path).await? || path_exists(&welcome_page_path).await? {
        return Ok(None);
    }

    fs::create_dir_all(profile.path()).await.context(
        welcome_service_error::CreateProfileDirSnafu {
            path: profile.path().to_path_buf(),
        },
    )?;

    let welcome_page_dir = welcome_page_path
        .parent()
        .expect("welcome page path should have a parent directory");
    fs::create_dir_all(welcome_page_dir).await.context(
        welcome_service_error::CreateWelcomePageDirSnafu {
            path: welcome_page_dir.to_path_buf(),
        },
    )?;

    write_new_file(&welcome_page_path, render_welcome_page().as_bytes()).await?;
    if let Err(source) = super::site::ServerConfig::for_profile(&profile)
        .create_disabled()
        .await
    {
        fs::remove_file(&welcome_page_path).await.context(
            welcome_service_error::RollbackDeleteSnafu {
                path: &welcome_page_path,
            },
        )?;
        return Err(WelcomeServiceError::Configuration { source });
    }

    Ok(Some(WelcomeServiceCreated {
        config_db_path,
        welcome_page_path,
    }))
}

pub(crate) fn format_welcome_service_created(name: &str) -> String {
    format!("Pishoo configuration and welcome page created for {name}; listening is disabled.")
}

fn render_welcome_page() -> &'static str {
    "<!DOCTYPE html>\n\
<html lang=\"en\">\n\
  <head>\n\
    <meta charset=\"utf-8\">\n\
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
    <title>Hello from DHTTP</title>\n\
    <style>\n\
      body {\n\
        margin: 0;\n\
        min-height: 100vh;\n\
        display: grid;\n\
        place-items: center;\n\
        font-family: system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif;\n\
        color: #172033;\n\
        background: #f7f8fb;\n\
      }\n\
\n\
      main {\n\
        width: min(40rem, calc(100vw - 3rem));\n\
        padding: 3rem;\n\
        border-radius: 1.5rem;\n\
        background: #ffffff;\n\
        box-shadow: 0 24px 80px rgba(23, 32, 51, 0.08);\n\
      }\n\
\n\
      h1 {\n\
        margin: 0 0 0.75rem;\n\
        font-size: clamp(2rem, 5vw, 3.5rem);\n\
        line-height: 1;\n\
      }\n\
\n\
      p {\n\
        margin: 0.75rem 0;\n\
        color: #4d5a73;\n\
        font-size: 1rem;\n\
        line-height: 1.6;\n\
      }\n\
\n\
      h2 {\n\
        margin: 2rem 0 0.75rem;\n\
        font-size: 0.9rem;\n\
        letter-spacing: 0.08em;\n\
        text-transform: uppercase;\n\
      }\n\
\n\
      ul {\n\
        margin: 0;\n\
        padding-left: 1.25rem;\n\
        color: #4d5a73;\n\
        line-height: 1.7;\n\
      }\n\
\n\
      .note {\n\
        margin-top: 2rem;\n\
        font-size: 0.875rem;\n\
        color: #7a8499;\n\
      }\n\
    </style>\n\
  </head>\n\
  <body>\n\
    <main>\n\
      <h1>Hello from DHTTP.</h1>\n\
      <p>This identity is ready to serve.</p>\n\
\n\
      <h2>Next steps</h2>\n\
      <ul>\n\
        <li>Replace this page with your own site.</li>\n\
        <li>Use pishoo proxy to configure local services; place files in the identity file directory.</li>\n\
        <li>Reload pishoo after changing your service configuration.</li>\n\
      </ul>\n\
\n\
      <p class=\"note\">Generated by genmeta identity.</p>\n\
    </main>\n\
  </body>\n\
</html>\n"
}

async fn path_exists(path: &Path) -> Result<bool, WelcomeServiceError> {
    match fs::try_exists(path).await {
        Ok(exists) => Ok(exists),
        Err(source) => Err(welcome_service_error::MetadataSnafu {
            path: path.to_path_buf(),
        }
        .into_error(source)),
    }
}

async fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), WelcomeServiceError> {
    write_new_file_transaction(path, contents, || Ok(())).await
}

async fn write_new_file_transaction(
    path: &Path,
    contents: &[u8],
    before_finish: impl FnOnce() -> std::io::Result<()>,
) -> Result<(), WelcomeServiceError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(path)
        .await
        .context(welcome_service_error::CreateFileSnafu {
            path: path.to_path_buf(),
        })?;
    let write_result = async {
        file.write_all(contents).await?;
        before_finish()?;
        file.flush().await
    }
    .await;
    if let Err(source) = write_result {
        drop(file);
        if let Err(source) = fs::remove_file(path).await {
            return Err(welcome_service_error::RollbackDeleteSnafu {
                path: path.to_path_buf(),
            }
            .into_error(source));
        }
        return Err(welcome_service_error::WriteFileSnafu {
            path: path.to_path_buf(),
        }
        .into_error(source));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use genmeta_network::home::DhttpHome;

    use super::*;

    #[tokio::test]
    async fn creates_pishoo_database_with_listening_disabled_and_a_served_file() {
        let root = tempfile::tempdir().unwrap();
        let home = DhttpHome::new(root.path().to_path_buf());
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();
        let profile = home.identity_profile(name.borrow());
        let created = maybe_create_welcome_service(&home, name.borrow())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(created.config_db_path, profile.config_db_path());
        assert_eq!(
            created.welcome_page_path,
            profile.join("file/welcome/index.html")
        );
        assert_eq!(
            super::super::site::ServerConfig::for_profile(&profile)
                .state()
                .await
                .unwrap(),
            super::super::site::ServerConfigState::Disabled
        );
        assert!(
            fs::read_to_string(created.welcome_page_path)
                .await
                .unwrap()
                .contains("<h1>Hello from DHTTP.</h1>")
        );
        assert!(
            maybe_create_welcome_service(&home, name.borrow())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn existing_welcome_file_is_preserved_without_creating_configuration() {
        let root = tempfile::tempdir().unwrap();
        let home = DhttpHome::new(root.path().to_path_buf());
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();
        let profile = home.identity_profile(name.borrow());
        let path = profile.join(WELCOME_PAGE_PATH);
        fs::create_dir_all(path.parent().unwrap()).await.unwrap();
        fs::write(&path, "existing").await.unwrap();
        assert!(
            maybe_create_welcome_service(&home, name.borrow())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "existing");
        assert!(!profile.config_db_path().exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_page_creation_does_not_leave_a_database() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let home = DhttpHome::new(root.path().to_path_buf());
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();
        let profile = home.identity_profile(name.borrow());
        let path = profile.join(WELCOME_PAGE_PATH);
        fs::create_dir_all(path.parent().unwrap()).await.unwrap();
        symlink(profile.join("missing-target"), &path).unwrap();
        assert!(
            maybe_create_welcome_service(&home, name.borrow())
                .await
                .is_err()
        );
        assert!(!profile.config_db_path().exists());
    }

    #[tokio::test]
    async fn write_failure_removes_the_new_partial_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("index.html");
        assert!(
            super::write_new_file_transaction(&path, b"partial", || {
                Err(std::io::Error::other("injected write failure"))
            })
            .await
            .is_err()
        );
        assert!(!path.exists());
    }
}
