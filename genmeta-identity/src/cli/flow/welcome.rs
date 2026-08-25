use std::path::{Path, PathBuf};

use dhttp::{home::DhttpHome, name::DhttpName};
use snafu::{IntoError, ResultExt, Snafu};
use tokio::{fs, io::AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WelcomeServiceCreated {
    pub(crate) server_conf_backup_path: PathBuf,
    pub(crate) welcome_page_path: PathBuf,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WelcomeServiceError {
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

const SERVER_CONF_TEMPLATE: &str = "server {
    listen all 0;

    sshd on;

    location /welcome {
        root templates;
        index index.html;
    }
}
";

const WELCOME_PAGE_PATH: &str = "templates/welcome/index.html";

pub(crate) async fn maybe_create_welcome_service(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
) -> Result<Option<WelcomeServiceCreated>, WelcomeServiceError> {
    let profile = dhttp_home.identity_profile(name.borrow());
    let server_conf_path = profile.server_conf_path();
    let server_conf_backup_path = profile.join(super::site::SERVER_CONF_BACKUP_FILE);
    let welcome_page_path = profile.join(WELCOME_PAGE_PATH);

    if path_exists(&server_conf_path).await?
        || path_exists(&server_conf_backup_path).await?
        || path_exists(&welcome_page_path).await?
    {
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

    write_new_file(&server_conf_backup_path, SERVER_CONF_TEMPLATE.as_bytes()).await?;

    let welcome_page = render_welcome_page();

    if let Err(error) = write_new_file(&welcome_page_path, welcome_page.as_bytes()).await {
        if let Err(source) = fs::remove_file(&server_conf_backup_path).await {
            return Err(welcome_service_error::RollbackDeleteSnafu {
                path: server_conf_backup_path.clone(),
            }
            .into_error(source));
        }
        return Err(error);
    }

    Ok(Some(WelcomeServiceCreated {
        server_conf_backup_path,
        welcome_page_path,
    }))
}

pub(crate) fn format_welcome_service_created(name: &str) -> String {
    format!("Sample server configuration created for {name}.")
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
        <li>Add routes in server.conf to serve files or proxy services.</li>\n\
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
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use dhttp::{home::DhttpHome, name::DhttpName};

    use super::{
        SERVER_CONF_TEMPLATE, format_welcome_service_created, maybe_create_welcome_service,
    };

    fn unique_test_home_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "genmeta-identity-welcome-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn user_scope_creates_welcome_onboarding_without_pishoo_group() {
        let home = DhttpHome::new(unique_test_home_path("user-scope-new-identity"));
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();

        let created = maybe_create_welcome_service(&home, name.borrow())
            .await
            .unwrap();

        let created = created.expect("new user identity should create welcome files");
        assert!(created.server_conf_backup_path.exists());
        assert!(created.welcome_page_path.exists());
    }

    #[tokio::test]
    async fn creates_welcome_files_for_new_identity() {
        let home = DhttpHome::new(unique_test_home_path("new-identity"));
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();

        let created = maybe_create_welcome_service(&home, name.borrow())
            .await
            .unwrap();

        let created = created.expect("new identity should create welcome files");
        let profile = home.identity_profile(name.borrow());
        assert!(created.server_conf_backup_path.exists());
        assert_eq!(
            created.server_conf_backup_path,
            profile.join(crate::cli::flow::site::SERVER_CONF_BACKUP_FILE)
        );
        assert!(!profile.server_conf_path().exists());
        assert!(created.welcome_page_path.exists());
        assert_eq!(
            created.welcome_page_path,
            profile.join("templates/welcome/index.html")
        );
        assert!(!profile.join("index.html").exists());

        let server_conf = tokio::fs::read_to_string(&created.server_conf_backup_path)
            .await
            .unwrap();
        assert!(server_conf.contains("sshd on;"), "{server_conf}");
        assert!(server_conf.contains("location /welcome {"), "{server_conf}");
        assert!(server_conf.contains("root templates;"), "{server_conf}");
        assert!(!server_conf.contains("location / {"), "{server_conf}");
        assert!(
            !server_conf.contains("root templates/welcome;"),
            "{server_conf}"
        );

        let welcome_page = tokio::fs::read_to_string(&created.welcome_page_path)
            .await
            .unwrap();
        assert!(
            welcome_page.contains("<h1>Hello from DHTTP.</h1>"),
            "{welcome_page}"
        );
        assert!(
            welcome_page.contains("This identity is ready to serve."),
            "{welcome_page}"
        );
        assert!(
            welcome_page.contains("Add routes in server.conf"),
            "{welcome_page}"
        );
        assert!(
            !welcome_page.contains("templates/welcome"),
            "{welcome_page}"
        );
    }

    #[tokio::test]
    async fn skips_pair_creation_when_server_conf_already_exists() {
        let home = DhttpHome::new(unique_test_home_path("server-conf-exists"));
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();
        let profile = home.identity_profile(name.borrow());
        tokio::fs::create_dir_all(profile.path()).await.unwrap();
        tokio::fs::write(profile.server_conf_path(), "server { listen all 0; }")
            .await
            .unwrap();

        let created = maybe_create_welcome_service(&home, name.borrow())
            .await
            .unwrap();

        assert!(created.is_none());
        assert!(!profile.join("templates/welcome/index.html").exists());
    }

    #[tokio::test]
    async fn skips_pair_creation_when_server_conf_backup_already_exists() {
        let home = DhttpHome::new(unique_test_home_path("server-conf-backup-exists"));
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();
        let profile = home.identity_profile(name.borrow());
        let backup = profile.join(crate::cli::flow::site::SERVER_CONF_BACKUP_FILE);
        tokio::fs::create_dir_all(profile.path()).await.unwrap();
        tokio::fs::write(&backup, "edited server config")
            .await
            .unwrap();

        let created = maybe_create_welcome_service(&home, name.borrow())
            .await
            .unwrap();

        assert!(created.is_none());
        assert_eq!(
            tokio::fs::read_to_string(&backup).await.unwrap(),
            "edited server config"
        );
        assert!(!profile.server_conf_path().exists());
        assert!(!profile.join("templates/welcome/index.html").exists());
    }

    #[tokio::test]
    async fn skips_pair_creation_when_welcome_page_already_exists() {
        let home = DhttpHome::new(unique_test_home_path("welcome-page-exists"));
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();
        let profile = home.identity_profile(name.borrow());
        let welcome_page = profile.join("templates/welcome/index.html");
        tokio::fs::create_dir_all(welcome_page.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&welcome_page, "existing page")
            .await
            .unwrap();

        let created = maybe_create_welcome_service(&home, name.borrow())
            .await
            .unwrap();

        assert!(created.is_none());
        assert!(!profile.server_conf_path().exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rolls_back_server_conf_when_index_html_creation_fails() {
        use std::os::unix::fs::symlink;

        let home = DhttpHome::new(unique_test_home_path("rollback"));
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();
        let profile = home.identity_profile(name.borrow());
        tokio::fs::create_dir_all(profile.path()).await.unwrap();
        tokio::fs::create_dir_all(profile.join("templates/welcome"))
            .await
            .unwrap();
        symlink(
            profile.join("missing-index-html-target"),
            profile.join("templates/welcome/index.html"),
        )
        .unwrap();

        let error = maybe_create_welcome_service(&home, name.borrow())
            .await
            .expect_err("index.html directory should make file creation fail");

        let rendered = error.to_string();
        assert!(rendered.contains("welcome service"), "{rendered}");
        assert!(!profile.server_conf_path().exists());
        assert!(
            !profile
                .join(crate::cli::flow::site::SERVER_CONF_BACKUP_FILE)
                .exists()
        );
    }

    #[tokio::test]
    async fn write_failure_removes_the_new_partial_file() {
        let home_path = unique_test_home_path("partial-file-rollback");
        tokio::fs::create_dir_all(&home_path).await.unwrap();
        let path = home_path.join("server.conf");

        let error = super::write_new_file_transaction(&path, b"partial", || {
            Err(std::io::Error::other("injected write failure"))
        })
        .await
        .unwrap_err();

        assert!(
            error.to_string().contains("welcome service file"),
            "{error}"
        );
        assert!(!path.exists(), "partial welcome file was not removed");
    }

    #[test]
    fn welcome_service_is_mounted_at_welcome() {
        assert!(SERVER_CONF_TEMPLATE.contains("sshd on;"));
        assert!(SERVER_CONF_TEMPLATE.contains("location /welcome {"));
        assert!(SERVER_CONF_TEMPLATE.contains("root templates;"));
        assert!(SERVER_CONF_TEMPLATE.contains("index index.html;"));
        assert!(!SERVER_CONF_TEMPLATE.contains("location / {"));
        assert!(!SERVER_CONF_TEMPLATE.contains("root templates/welcome;"));
    }

    #[test]
    fn welcome_success_copy_reports_created_identity() {
        assert_eq!(
            format_welcome_service_created("alice.smith"),
            "Sample server configuration created for alice.smith."
        );
    }
}
