use std::path::{Path, PathBuf};

use dhttp::home::{
    DhttpHome,
    identity::{IdentityProfile, ssl::ResolveIdentityProfileError},
};
use snafu::{IntoError, ResultExt, Snafu};
use tokio::fs;

use crate::cli::SiteCommand;

pub(crate) const SERVER_CONF_BACKUP_FILE: &str = "server.conf.bak";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerConfigState {
    Enabled,
    Disabled,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigChange {
    Changed,
    Unchanged,
}

#[derive(Debug)]
pub(crate) struct ServerConfig {
    active: PathBuf,
    backup: PathBuf,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(transparent)]
    ResolveIdentityProfile { source: ResolveIdentityProfileError },
    #[snafu(display("failed to inspect server configuration {}", path.display()))]
    Inspect {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("server configuration path is not a regular file: {}", path.display()))]
    NotRegularFile { path: PathBuf },
    #[snafu(display(
        "server configuration is missing: neither {} nor {} exists",
        active.display(),
        backup.display()
    ))]
    MissingConfiguration { active: PathBuf, backup: PathBuf },
    #[snafu(display(
        "cannot disable server because a backup already exists at {}; back it up or move it before retrying",
        path.display()
    ))]
    BackupExists { path: PathBuf },
    #[snafu(display(
        "failed to rename server configuration from {} to {}",
        source_path.display(),
        target_path.display()
    ))]
    Rename {
        source_path: PathBuf,
        target_path: PathBuf,
        source: std::io::Error,
    },
}

impl ServerConfig {
    pub(crate) fn for_profile(profile: &IdentityProfile) -> Self {
        Self {
            active: profile.server_conf_path(),
            backup: profile.join(SERVER_CONF_BACKUP_FILE),
        }
    }

    pub(crate) async fn state(&self) -> Result<ServerConfigState, Error> {
        if regular_file_exists(&self.active).await? {
            return Ok(ServerConfigState::Enabled);
        }
        if regular_file_exists(&self.backup).await? {
            return Ok(ServerConfigState::Disabled);
        }
        Ok(ServerConfigState::Missing)
    }

    pub(crate) async fn enable(&self) -> Result<ConfigChange, Error> {
        match self.state().await? {
            ServerConfigState::Enabled => Ok(ConfigChange::Unchanged),
            ServerConfigState::Disabled => {
                rename(&self.backup, &self.active).await?;
                Ok(ConfigChange::Changed)
            }
            ServerConfigState::Missing => error::MissingConfigurationSnafu {
                active: self.active.clone(),
                backup: self.backup.clone(),
            }
            .fail(),
        }
    }

    pub(crate) async fn disable(&self) -> Result<ConfigChange, Error> {
        match self.state().await? {
            ServerConfigState::Enabled => {
                if regular_file_exists(&self.backup).await? {
                    return error::BackupExistsSnafu {
                        path: self.backup.clone(),
                    }
                    .fail();
                }
                rename(&self.active, &self.backup).await?;
                Ok(ConfigChange::Changed)
            }
            ServerConfigState::Disabled => Ok(ConfigChange::Unchanged),
            ServerConfigState::Missing => error::MissingConfigurationSnafu {
                active: self.active.clone(),
                backup: self.backup.clone(),
            }
            .fail(),
        }
    }
}

async fn regular_file_exists(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => error::NotRegularFileSnafu {
            path: path.to_path_buf(),
        }
        .fail(),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(error::InspectSnafu {
            path: path.to_path_buf(),
        }
        .into_error(source)),
    }
}

async fn rename(source: &Path, target: &Path) -> Result<(), Error> {
    fs::rename(source, target)
        .await
        .context(error::RenameSnafu {
            source_path: source.to_path_buf(),
            target_path: target.to_path_buf(),
        })
}

#[cfg(target_os = "macos")]
pub(crate) const RELOAD_HINT: &str = "Run `sudo brew services reload pishoo` to apply the change.";

#[cfg(not(target_os = "macos"))]
pub(crate) const RELOAD_HINT: &str = "Run `sudo systemctl reload pishoo` to apply the change.";

pub(crate) fn print_enable_result(identity: &str, change: ConfigChange) {
    match change {
        ConfigChange::Changed => {
            super::transcript::print_line(format!("Server enabled for {identity}."));
            super::transcript::print_line(RELOAD_HINT);
        }
        ConfigChange::Unchanged => {
            super::transcript::print_line(format!("Server is already enabled for {identity}."));
        }
    }
}

fn print_disable_result(identity: &str, change: ConfigChange) {
    match change {
        ConfigChange::Changed => {
            super::transcript::print_line(format!("Server disabled for {identity}."));
            super::transcript::print_line(RELOAD_HINT);
        }
        ConfigChange::Unchanged => {
            super::transcript::print_line(format!("Server is already disabled for {identity}."));
        }
    }
}

pub(crate) async fn run_ensite(
    command: &SiteCommand,
    dhttp_home: &DhttpHome,
) -> Result<(), crate::cli::Error> {
    let identity = super::target::IdentityTarget::parse(&command.id)?.into_dhttp_name();
    let profile = dhttp_home
        .resolve_identity_profile_exactly(identity.borrow())
        .await?;
    let change = ServerConfig::for_profile(&profile).enable().await?;
    print_enable_result(identity.as_partial(), change);
    Ok(())
}

pub(crate) async fn run_dissite(
    command: &SiteCommand,
    dhttp_home: &DhttpHome,
) -> Result<(), crate::cli::Error> {
    let identity = super::target::IdentityTarget::parse(&command.id)?.into_dhttp_name();
    let profile = dhttp_home
        .resolve_identity_profile_exactly(identity.borrow())
        .await?;
    let change = ServerConfig::for_profile(&profile).disable().await?;
    print_disable_result(identity.as_partial(), change);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use dhttp::{home::DhttpHome, name::DhttpName};
    use tokio::fs;

    use super::{
        ConfigChange, Error, RELOAD_HINT, SERVER_CONF_BACKUP_FILE, ServerConfig, ServerConfigState,
    };

    struct Fixture {
        root: PathBuf,
        home: DhttpHome,
        name: DhttpName<'static>,
    }

    impl Fixture {
        async fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "genmeta-identity-site-{label}-{}-{nonce}",
                std::process::id()
            ));
            let home = DhttpHome::new(root.clone());
            let name = DhttpName::try_from("alice.smith".to_owned()).unwrap();
            fs::create_dir_all(home.identity_profile(name.borrow()).path())
                .await
                .unwrap();
            Self { root, home, name }
        }

        fn profile(&self) -> dhttp::home::identity::IdentityProfile {
            self.home.identity_profile(self.name.borrow())
        }

        fn config(&self) -> ServerConfig {
            ServerConfig::for_profile(&self.profile())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[tokio::test]
    async fn state_prefers_active_configuration_over_backup() {
        let fixture = Fixture::new("state-matrix").await;
        let profile = fixture.profile();
        let active = profile.server_conf_path();
        let backup = profile.join(SERVER_CONF_BACKUP_FILE);
        let config = fixture.config();

        assert_eq!(config.state().await.unwrap(), ServerConfigState::Missing);

        fs::write(&backup, "disabled").await.unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);

        fs::rename(&backup, &active).await.unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Enabled);

        fs::write(&backup, "stale backup").await.unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Enabled);
    }

    #[tokio::test]
    async fn enable_promotes_backup_and_is_idempotent() {
        let fixture = Fixture::new("enable").await;
        let profile = fixture.profile();
        let active = profile.server_conf_path();
        let backup = profile.join(SERVER_CONF_BACKUP_FILE);
        fs::write(&backup, "edited config").await.unwrap();

        assert_eq!(
            fixture.config().enable().await.unwrap(),
            ConfigChange::Changed
        );
        assert_eq!(fs::read_to_string(&active).await.unwrap(), "edited config");
        assert!(!backup.exists());
        assert_eq!(
            fixture.config().enable().await.unwrap(),
            ConfigChange::Unchanged
        );
    }

    #[tokio::test]
    async fn disable_preserves_active_as_backup_and_is_idempotent() {
        let fixture = Fixture::new("disable").await;
        let profile = fixture.profile();
        let active = profile.server_conf_path();
        let backup = profile.join(SERVER_CONF_BACKUP_FILE);
        fs::write(&active, "active config").await.unwrap();

        assert_eq!(
            fixture.config().disable().await.unwrap(),
            ConfigChange::Changed
        );
        assert!(!active.exists());
        assert_eq!(fs::read_to_string(&backup).await.unwrap(), "active config");
        assert_eq!(
            fixture.config().disable().await.unwrap(),
            ConfigChange::Unchanged
        );
    }

    #[tokio::test]
    async fn disable_preserves_both_files_when_backup_already_exists() {
        let fixture = Fixture::new("active-with-backup").await;
        let profile = fixture.profile();
        let active = profile.server_conf_path();
        let backup = profile.join(SERVER_CONF_BACKUP_FILE);
        fs::write(&active, "active config").await.unwrap();
        fs::write(&backup, "backup config").await.unwrap();

        assert_eq!(
            fixture.config().state().await.unwrap(),
            ServerConfigState::Enabled
        );
        assert_eq!(
            fixture.config().enable().await.unwrap(),
            ConfigChange::Unchanged
        );
        assert_eq!(fs::read_to_string(&active).await.unwrap(), "active config");
        assert_eq!(fs::read_to_string(&backup).await.unwrap(), "backup config");

        let error = fixture.config().disable().await.unwrap_err();
        let rendered = error.to_string();
        assert!(matches!(error, Error::BackupExists { path } if path == backup));
        assert!(rendered.contains("back it up or move it"), "{rendered}");
        assert_eq!(fs::read_to_string(&active).await.unwrap(), "active config");
        assert_eq!(fs::read_to_string(&backup).await.unwrap(), "backup config");
    }

    #[tokio::test]
    async fn missing_configuration_is_an_error_for_both_changes() {
        let fixture = Fixture::new("missing").await;

        assert!(matches!(
            fixture.config().enable().await,
            Err(Error::MissingConfiguration { .. })
        ));
        assert!(matches!(
            fixture.config().disable().await,
            Err(Error::MissingConfiguration { .. })
        ));
    }

    #[tokio::test]
    async fn non_regular_configuration_paths_are_rejected() {
        let fixture = Fixture::new("non-regular").await;
        let profile = fixture.profile();
        let active = profile.server_conf_path();
        let backup = profile.join(SERVER_CONF_BACKUP_FILE);

        fs::create_dir(&active).await.unwrap();
        assert!(matches!(
            fixture.config().state().await,
            Err(Error::NotRegularFile { path }) if path == active
        ));
        fs::remove_dir(&active).await.unwrap();

        fs::create_dir(&backup).await.unwrap();
        assert!(matches!(
            fixture.config().state().await,
            Err(Error::NotRegularFile { path }) if path == backup
        ));

        fs::write(&active, "active config").await.unwrap();
        assert_eq!(
            fixture.config().state().await.unwrap(),
            ServerConfigState::Enabled
        );
        assert!(matches!(
            fixture.config().disable().await,
            Err(Error::NotRegularFile { path }) if path == backup
        ));
    }

    #[test]
    fn reload_hint_only_describes_reloading_pishoo() {
        assert!(RELOAD_HINT.contains("reload pishoo"));
        assert!(!RELOAD_HINT.contains("group"));
        assert!(!RELOAD_HINT.contains("usermod"));
        assert!(!RELOAD_HINT.contains("dseditgroup"));
    }
}
