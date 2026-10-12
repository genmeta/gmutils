use std::path::{Path, PathBuf};

use dhttp_home::{
    DhttpHome,
    identity::{IdentityProfile, ssl::ResolveIdentityProfileError},
};
use sea_orm::{
    ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement, TransactionTrait,
};
use snafu::{ResultExt, Snafu};
use tokio::fs;

use crate::cli::SiteCommand;

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
    path: PathBuf,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(transparent)]
    ResolveIdentityProfile { source: ResolveIdentityProfileError },
    #[snafu(display("failed to inspect Pishoo configuration {}", path.display()))]
    Inspect {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Pishoo configuration is not a regular file: {}", path.display()))]
    NotRegularFile { path: PathBuf },
    #[snafu(display("Pishoo configuration is missing at {}; start Pishoo to initialize it", path.display()))]
    MissingConfiguration { path: PathBuf },
    #[snafu(display("failed to access Pishoo configuration database {}", path.display()))]
    Database {
        path: PathBuf,
        source: sea_orm::DbErr,
    },
    #[snafu(display("invalid Pishoo configuration at {}: {message}", path.display()))]
    InvalidConfiguration { path: PathBuf, message: String },
}

impl ServerConfig {
    pub(crate) fn for_profile(profile: &IdentityProfile) -> Self {
        Self {
            path: profile.config_db_path(),
        }
    }

    async fn open(&self) -> Result<DatabaseConnection, Error> {
        if !regular_file_exists(&self.path).await? {
            return Err(Error::MissingConfiguration {
                path: self.path.clone(),
            });
        }
        // rw prevents a typo or missing profile from silently creating a database.
        let uri = format!(
            "sqlite://{}?mode=rw",
            urlencoding::encode(&self.path.to_string_lossy())
        );
        Database::connect(uri)
            .await
            .context(error::DatabaseSnafu { path: &self.path })
    }

    async fn listen(&self, db: &impl ConnectionTrait) -> Result<i64, Error> {
        let invalid = |message: &str| Error::InvalidConfiguration {
            path: self.path.clone(),
            message: message.into(),
        };
        let version = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA user_version",
            ))
            .await
            .context(error::DatabaseSnafu { path: &self.path })?
            .ok_or_else(|| invalid("schema version is missing"))?;
        let version: i64 = version
            .try_get_by_index(0)
            .map_err(|_| invalid("invalid schema version"))?;
        if version != 1 {
            return Err(invalid("supported schema version is 1"));
        }
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT listen, typeof(listen) AS kind FROM settings",
            ))
            .await
            .context(error::DatabaseSnafu { path: &self.path })?;
        if rows.len() != 1 {
            return Err(invalid("settings must contain exactly one row"));
        }
        let kind: String = rows[0]
            .try_get("", "kind")
            .map_err(|_| invalid("invalid listen type"))?;
        let listen: i64 = rows[0]
            .try_get("", "listen")
            .map_err(|_| invalid("listen must be an integer in 0..=3"))?;
        if kind != "integer" || !(0..=3).contains(&listen) {
            return Err(invalid("listen must be an integer in 0..=3"));
        }
        Ok(listen)
    }

    pub(crate) async fn state(&self) -> Result<ServerConfigState, Error> {
        if !regular_file_exists(&self.path).await? {
            return Ok(ServerConfigState::Missing);
        }
        let db = self.open().await?;
        let tx = db
            .begin()
            .await
            .context(error::DatabaseSnafu { path: &self.path })?;
        let listen = self.listen(&tx).await?;
        tx.commit()
            .await
            .context(error::DatabaseSnafu { path: &self.path })?;
        Ok(if listen == 0 {
            ServerConfigState::Disabled
        } else {
            ServerConfigState::Enabled
        })
    }

    async fn set_enabled(&self, enabled: bool) -> Result<ConfigChange, Error> {
        let db = self.open().await?;
        let tx = db
            .begin()
            .await
            .context(error::DatabaseSnafu { path: &self.path })?;
        let listen = self.listen(&tx).await?;
        // Preserve an enabled identity's chosen internal/external/both scope.
        let target = if enabled {
            if listen == 0 { 3 } else { listen }
        } else {
            0
        };
        if listen != target {
            tx.execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE settings SET listen = ?",
                [target.into()],
            ))
            .await
            .context(error::DatabaseSnafu { path: &self.path })?;
        }
        tx.commit()
            .await
            .context(error::DatabaseSnafu { path: &self.path })?;
        Ok(if listen == target {
            ConfigChange::Unchanged
        } else {
            ConfigChange::Changed
        })
    }

    pub(crate) async fn enable(&self) -> Result<ConfigChange, Error> {
        self.set_enabled(true).await
    }
    pub(crate) async fn disable(&self) -> Result<ConfigChange, Error> {
        self.set_enabled(false).await
    }

    /// Initialize only a newly created database, with listening disabled until opted in.
    pub(crate) async fn create_disabled(&self) -> Result<(), Error> {
        let parent = self.path.parent().expect("config database has a parent");
        fs::create_dir_all(parent)
            .await
            .context(error::InspectSnafu { path: parent })?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        drop(
            options
                .open(&self.path)
                .await
                .context(error::InspectSnafu { path: &self.path })?,
        );
        let result = async {
            let db = self.open().await?;
            let result = async {
                let tx = db.begin().await.context(error::DatabaseSnafu { path: &self.path })?;
                for sql in [
                    "CREATE TABLE settings (listen INTEGER NOT NULL CHECK(typeof(listen) = 'integer' AND listen BETWEEN 0 AND 3))",
                    "INSERT INTO settings(listen) VALUES(0)",
                    "CREATE TABLE proxy_locations(location TEXT NOT NULL PRIMARY KEY, proxy_pass TEXT NOT NULL)",
                    "PRAGMA user_version = 1",
                ] {
                    tx.execute_unprepared(sql).await.context(error::DatabaseSnafu { path: &self.path })?;
                }
                tx.commit().await.context(error::DatabaseSnafu { path: &self.path })?;
                Ok(())
            }.await;
            db.close().await.context(error::DatabaseSnafu { path: &self.path })?;
            result
        }.await;
        if result.is_err() {
            fs::remove_file(&self.path)
                .await
                .context(error::InspectSnafu { path: &self.path })?;
        }
        result
    }
}

async fn regular_file_exists(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(Error::NotRegularFile {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(Error::Inspect {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(crate) const RESTART_HINT: &str = "Restart the Pishoo process serving this DHTTP home to apply the change; for an installed service, use `pishoo restart`.";

pub(crate) fn print_enable_result(identity: &str, change: ConfigChange) {
    let message = match change {
        ConfigChange::Changed => format!("Server enabled for {identity} (listen: both)."),
        ConfigChange::Unchanged => format!("Server is already enabled for {identity}."),
    };
    super::transcript::print_line(message);
    super::transcript::print_line(RESTART_HINT);
}

fn print_disable_result(identity: &str, change: ConfigChange) {
    let message = match change {
        ConfigChange::Changed => format!("Server disabled for {identity} (listen: off)."),
        ConfigChange::Unchanged => format!("Server is already disabled for {identity}."),
    };
    super::transcript::print_line(message);
    super::transcript::print_line(RESTART_HINT);
}

pub(crate) async fn run_ensite(
    command: &SiteCommand,
    home: &DhttpHome,
) -> Result<(), crate::cli::Error> {
    let identity = super::target::IdentityTarget::parse(&command.id)?.into_dhttp_name();
    let profile = home
        .resolve_identity_profile_exactly((identity.borrow()).as_full())
        .await?;
    let change = ServerConfig::for_profile(&profile).enable().await?;
    print_enable_result(identity.as_partial(), change);
    Ok(())
}

pub(crate) async fn run_dissite(
    command: &SiteCommand,
    home: &DhttpHome,
) -> Result<(), crate::cli::Error> {
    let identity = super::target::IdentityTarget::parse(&command.id)?.into_dhttp_name();
    let profile = home
        .resolve_identity_profile_exactly((identity.borrow()).as_full())
        .await?;
    let change = ServerConfig::for_profile(&profile).disable().await?;
    print_disable_result(identity.as_partial(), change);
    Ok(())
}

#[cfg(test)]
mod tests {
    use dhttp_identity::name::DhttpName;

    use super::*;

    async fn fixture() -> (tempfile::TempDir, IdentityProfile, ServerConfig) {
        let root = tempfile::Builder::new()
            .prefix(if cfg!(windows) {
                "site # 测试"
            } else {
                "site #? 测试"
            })
            .tempdir()
            .unwrap();
        let home = DhttpHome::new(root.path().to_path_buf());
        let profile = home
            .identity_profile((DhttpName::try_from("alice.smith".to_owned()).unwrap()).as_full())
            .expect("validated identity name");
        let config = ServerConfig::for_profile(&profile);
        config.create_disabled().await.unwrap();
        (root, profile, config)
    }

    #[tokio::test]
    async fn changes_listen_without_losing_proxies_and_preserves_enabled_scope() {
        let (_root, _profile, config) = fixture().await;
        let db = config.open().await.unwrap();
        db.execute_unprepared(
            "INSERT INTO proxy_locations VALUES('/app', 'http://127.0.0.1:8080')",
        )
        .await
        .unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
        assert_eq!(config.enable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Enabled);
        for scope in [1, 2, 3] {
            db.execute_unprepared(&format!("UPDATE settings SET listen={scope}"))
                .await
                .unwrap();
            assert_eq!(config.enable().await.unwrap(), ConfigChange::Unchanged);
            assert_eq!(config.listen(&db).await.unwrap(), scope);
        }
        assert_eq!(config.disable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.disable().await.unwrap(), ConfigChange::Unchanged);
        assert_eq!(config.listen(&db).await.unwrap(), 0);
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT proxy_pass FROM proxy_locations",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<String>("", "proxy_pass").unwrap(),
            "http://127.0.0.1:8080"
        );
    }

    #[tokio::test]
    async fn invalid_or_missing_configuration_is_not_modified() {
        let (_root, profile, config) = fixture().await;
        let db = config.open().await.unwrap();
        db.execute_unprepared("PRAGMA user_version=2")
            .await
            .unwrap();
        assert!(matches!(
            config.enable().await,
            Err(Error::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            config.disable().await,
            Err(Error::InvalidConfiguration { .. })
        ));
        db.execute_unprepared("PRAGMA user_version=1; INSERT INTO settings VALUES(0)")
            .await
            .unwrap();
        assert!(matches!(
            config.enable().await,
            Err(Error::InvalidConfiguration { .. })
        ));
        db.close().await.unwrap();
        fs::remove_file(profile.config_db_path()).await.unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Missing);
        assert!(matches!(
            config.enable().await,
            Err(Error::MissingConfiguration { .. })
        ));
        assert!(!profile.config_db_path().exists());
    }

    #[tokio::test]
    async fn non_regular_database_is_rejected_and_existing_database_is_preserved() {
        let (_root, profile, config) = fixture().await;
        assert!(config.create_disabled().await.is_err());
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
        fs::remove_file(profile.config_db_path()).await.unwrap();
        fs::create_dir(profile.config_db_path()).await.unwrap();
        assert!(matches!(
            config.enable().await,
            Err(Error::NotRegularFile { .. })
        ));
    }
}
