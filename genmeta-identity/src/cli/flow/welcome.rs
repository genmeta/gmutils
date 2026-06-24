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
    pub(crate) index_html_path: PathBuf,
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
        root .;
        index index.html;
    }
}
";

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
    let index_html_path = profile.join("index.html");

    if path_exists(&server_conf_path).await? || path_exists(&index_html_path).await? {
        return Ok(None);
    }

    fs::create_dir_all(profile.path()).await.context(
        welcome_service_error::CreateProfileDirSnafu {
            path: profile.path().to_path_buf(),
        },
    )?;

    write_new_file(&server_conf_path, SERVER_CONF_TEMPLATE.as_bytes()).await?;

    let index_html = render_index_html(name.as_partial());

    if let Err(error) = write_new_file(&index_html_path, index_html.as_bytes()).await {
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
        index_html_path,
        url: format!("https://{}/", name.as_partial()),
    }))
}

pub(crate) fn format_welcome_service_created(created: &WelcomeServiceCreated) -> String {
    format!(
        "Welcome service created\n  Created server.conf at {}\n  Created index.html at {}\n  Open {} after pishoo starts or reloads",
        created.server_conf_path.display(),
        created.index_html_path.display(),
        created.url,
    )
}

fn render_index_html(name: &str) -> String {
    format!(
        "<!DOCTYPE html>\n\
<html lang=\"en\">\n\
  <head>\n\
    <meta charset=\"utf-8\">\n\
    <title>{name}</title>\n\
  </head>\n\
  <body>\n\
    <h1>Welcome to {name}</h1>\n\
    <p>This page was created by genmeta identity.</p>\n\
    <p>If you can open this page, pishoo is serving this identity.</p>\n\
  </body>\n\
</html>\n"
    )
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

#[cfg(unix)]
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
        assert!(created.server_conf_path.exists());
        assert!(created.index_html_path.exists());
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
        assert!(!profile.join("index.html").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rolls_back_server_conf_when_index_html_creation_fails() {
        use std::os::unix::fs::symlink;

        let home = DhttpHome::new(unique_test_home_path("rollback"));
        let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();
        let profile = home.identity_profile(name.borrow());
        tokio::fs::create_dir_all(profile.path()).await.unwrap();
        symlink(
            profile.join("missing-index-html-target"),
            profile.join("index.html"),
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
            index_html_path: PathBuf::from("/tmp/alice/index.html"),
            url: "https://alice.smith/".to_string(),
        };

        let expected = "Welcome service created\n  Created server.conf at /tmp/alice/server.conf\n  Created index.html at /tmp/alice/index.html\n  Open https://alice.smith/ after pishoo starts or reloads";

        assert_eq!(format_welcome_service_created(&created), expected);
    }
}
