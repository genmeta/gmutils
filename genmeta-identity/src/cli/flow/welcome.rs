use std::path::{Path, PathBuf};

use dhttp::{
    home::{DhttpHome, HomeScope},
    name::DhttpName,
};
use snafu::{IntoError, ResultExt, Snafu};
use tokio::{fs, io::AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WelcomeServiceCreated {
    pub(crate) server_conf_path: PathBuf,
    pub(crate) welcome_page_path: PathBuf,
    pub(crate) url: String,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WelcomeServiceError {
    #[cfg(unix)]
    #[snafu(display("failed to determine whether welcome service onboarding is allowed"))]
    EligibilityLookup { source: nix::errno::Errno },

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

    location / {
        root templates/welcome;
        index index.html;
    }
}
";

const WELCOME_PAGE_PATH: &str = "templates/welcome/index.html";

pub(crate) async fn maybe_create_welcome_service(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
    home_scope: HomeScope,
) -> Result<Option<WelcomeServiceCreated>, WelcomeServiceError> {
    maybe_create_welcome_service_with_probe(dhttp_home, name, home_scope, user_in_pishoo_group)
        .await
}

pub(crate) async fn maybe_create_welcome_service_with_probe<F>(
    dhttp_home: &DhttpHome,
    name: DhttpName<'_>,
    home_scope: HomeScope,
    user_in_pishoo_group: F,
) -> Result<Option<WelcomeServiceCreated>, WelcomeServiceError>
where
    F: Fn() -> Result<bool, WelcomeServiceError>,
{
    if !welcome_onboarding_allowed(home_scope, &user_in_pishoo_group)? {
        return Ok(None);
    }

    let profile = dhttp_home.identity_profile(name.borrow());
    let server_conf_path = profile.server_conf_path();
    let welcome_page_path = profile.join(WELCOME_PAGE_PATH);

    if path_exists(&server_conf_path).await? || path_exists(&welcome_page_path).await? {
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

    write_new_file(&server_conf_path, SERVER_CONF_TEMPLATE.as_bytes()).await?;

    let welcome_page = render_welcome_page();

    if let Err(error) = write_new_file(&welcome_page_path, welcome_page.as_bytes()).await {
        if let Err(source) = fs::remove_file(&server_conf_path).await {
            return Err(welcome_service_error::RollbackDeleteSnafu {
                path: server_conf_path.clone(),
            }
            .into_error(source));
        }
        return Err(error);
    }

    Ok(Some(WelcomeServiceCreated {
        server_conf_path,
        welcome_page_path,
        url: format!("https://{}/", name.as_partial()),
    }))
}

pub(crate) fn format_welcome_service_created(created: &WelcomeServiceCreated) -> String {
    format!(
        "Welcome service created\n  Created server.conf at {}\n  Created welcome page at {}\n  Open {} after pishoo starts or reloads",
        created.server_conf_path.display(),
        created.welcome_page_path.display(),
        created.url,
    )
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

fn welcome_onboarding_allowed<F>(
    home_scope: HomeScope,
    user_in_pishoo_group: &F,
) -> Result<bool, WelcomeServiceError>
where
    F: Fn() -> Result<bool, WelcomeServiceError>,
{
    #[cfg(unix)]
    {
        match home_scope {
            HomeScope::Global => Ok(true),
            HomeScope::User => user_in_pishoo_group(),
        }
    }

    #[cfg(not(unix))]
    {
        let _ = home_scope;
        let _ = user_in_pishoo_group;
        Ok(false)
    }
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn user_in_pishoo_group() -> Result<bool, WelcomeServiceError> {
    use nix::unistd::{Group, getegid, getgroups};

    let Some(group) =
        Group::from_name("pishoo").context(welcome_service_error::EligibilityLookupSnafu)?
    else {
        return Ok(false);
    };

    if getegid() == group.gid {
        return Ok(true);
    }

    let groups = getgroups().context(welcome_service_error::EligibilityLookupSnafu)?;
    Ok(groups.into_iter().any(|gid| gid == group.gid))
}

#[cfg(all(unix, target_vendor = "apple"))]
fn user_in_pishoo_group() -> Result<bool, WelcomeServiceError> {
    Ok(false)
}

#[cfg(not(unix))]
fn user_in_pishoo_group() -> Result<bool, WelcomeServiceError> {
    Ok(false)
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
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(path)
        .await
        .context(welcome_service_error::CreateFileSnafu {
            path: path.to_path_buf(),
        })?;
    file.write_all(contents)
        .await
        .context(welcome_service_error::WriteFileSnafu {
            path: path.to_path_buf(),
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use dhttp::{
        home::{DhttpHome, HomeScope},
        name::DhttpName,
    };

    use super::{format_welcome_service_created, maybe_create_welcome_service_with_probe};

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
    async fn user_scope_requires_pishoo_group_for_welcome_onboarding() {
        let home = DhttpHome::new(unique_test_home_path("user-scope-no-group"));
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();

        let created =
            maybe_create_welcome_service_with_probe(&home, name.borrow(), HomeScope::User, || {
                Ok(false)
            })
            .await
            .unwrap();

        assert!(created.is_none());
        assert!(
            !home
                .identity_profile(name.borrow())
                .server_conf_path()
                .exists()
        );
    }

    #[tokio::test]
    async fn global_scope_bypasses_group_gate() {
        let home = DhttpHome::new(unique_test_home_path("global-scope"));
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();

        let created = maybe_create_welcome_service_with_probe(
            &home,
            name.borrow(),
            HomeScope::Global,
            || Ok(false),
        )
        .await
        .unwrap();

        let created = created.expect("global scope should create welcome files");
        let profile = home.identity_profile(name.borrow());
        assert!(created.server_conf_path.exists());
        assert!(created.welcome_page_path.exists());
        assert_eq!(
            created.welcome_page_path,
            profile.join("templates/welcome/index.html")
        );
        assert!(!profile.join("index.html").exists());

        let server_conf = tokio::fs::read_to_string(&created.server_conf_path)
            .await
            .unwrap();
        assert!(
            server_conf.contains("root templates/welcome;"),
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

        let created = maybe_create_welcome_service_with_probe(
            &home,
            name.borrow(),
            HomeScope::Global,
            || Ok(true),
        )
        .await
        .unwrap();

        assert!(created.is_none());
        assert!(!profile.join("templates/welcome/index.html").exists());
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

        let error = maybe_create_welcome_service_with_probe(
            &home,
            name.borrow(),
            HomeScope::Global,
            || Ok(true),
        )
        .await
        .expect_err("index.html directory should make file creation fail");

        let rendered = error.to_string();
        assert!(rendered.contains("welcome service"), "{rendered}");
        assert!(!profile.server_conf_path().exists());
    }

    #[test]
    fn renders_welcome_service_created_block() {
        let created = super::WelcomeServiceCreated {
            server_conf_path: PathBuf::from("/tmp/alice/server.conf"),
            welcome_page_path: PathBuf::from("/tmp/alice/templates/welcome/index.html"),
            url: "https://alice.smith/".to_string(),
        };

        let expected = "Welcome service created\n  Created server.conf at /tmp/alice/server.conf\n  Created welcome page at /tmp/alice/templates/welcome/index.html\n  Open https://alice.smith/ after pishoo starts or reloads";

        assert_eq!(format_welcome_service_created(&created), expected);
    }
}
