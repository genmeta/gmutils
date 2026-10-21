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
    #[snafu(display("Pishoo configuration is missing at {}; use `genmeta listen --id NAME internal` to create it", path.display()))]
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
            path: if profile.join(".volume/sys/setting/.db").exists()
                || !profile.config_db_path().exists()
            {
                profile.join(".volume/sys/setting/.db")
            } else {
                profile.config_db_path()
            },
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

    async fn listen(&self, db: &impl ConnectionTrait) -> Result<String, Error> {
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
        if !matches!(version, 1 | 2 | 3) {
            return Err(invalid("supported schema versions are 1, 2 and 3"));
        }
        let kv = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA table_info(setting)",
            ))
            .await
            .context(error::DatabaseSnafu { path: &self.path })?;
        if !kv.is_empty() {
            let row = db
                .query_one_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    "SELECT value FROM setting WHERE key='listen'",
                ))
                .await
                .context(error::DatabaseSnafu { path: &self.path })?;
            let listen = match row {
                None => "off".to_owned(),
                Some(row) => row
                    .try_get::<String>("", "value")
                    .map_err(|_| invalid("invalid listen KV"))?,
            };
            if !matches!(
                listen.as_str(),
                "loopback" | "internal" | "external" | "all" | "off"
            ) {
                return Err(invalid("invalid listen mode"));
            }
            return Ok(listen);
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
        let listen = match kind.as_str() {
            "text" => rows[0]
                .try_get::<String>("", "listen")
                .map_err(|_| invalid("invalid listen mode"))?,
            "integer" => {
                let value: i64 = rows[0]
                    .try_get("", "listen")
                    .map_err(|_| invalid("invalid legacy listen"))?;
                match value {
                    0 => "off",
                    1 => "internal",
                    2 => "external",
                    3 => "all",
                    _ => return Err(invalid("invalid legacy listen")),
                }
                .to_owned()
            }
            _ => return Err(invalid("invalid listen mode")),
        };
        if !matches!(
            listen.as_str(),
            "loopback" | "internal" | "external" | "all" | "off"
        ) {
            return Err(invalid("invalid listen mode"));
        }
        Ok(
            if configured_enabled(db, &self.path).await? == Some(false) {
                "off".into()
            } else {
                listen
            },
        )
    }

    pub(crate) async fn state(&self) -> Result<ServerConfigState, Error> {
        if !regular_file_exists(&self.path).await? {
            return Ok(ServerConfigState::Missing);
        }
        let db = self.open().await?;
        let result = async {
            let tx = db
                .begin()
                .await
                .context(error::DatabaseSnafu { path: &self.path })?;
            let listen = self.listen(&tx).await?;
            tx.commit()
                .await
                .context(error::DatabaseSnafu { path: &self.path })?;
            Ok(if listen == "off" {
                ServerConfigState::Disabled
            } else {
                ServerConfigState::Enabled
            })
        }
        .await;
        db.close()
            .await
            .context(error::DatabaseSnafu { path: &self.path })?;
        result
    }

    async fn set_enabled(&self, enabled: bool) -> Result<ConfigChange, Error> {
        let db = self.open().await?;
        let result = async {
            let tx = db
                .begin()
                .await
                .context(error::DatabaseSnafu { path: &self.path })?;
            let listen = self.listen(&tx).await?;
            let target = if !enabled {
                "off"
            } else if listen == "off" {
                "all"
            } else {
                &listen
            };
            let changed = listen != target;
            write_listen(&tx, &self.path, target).await?;
            tx.commit()
                .await
                .context(error::DatabaseSnafu { path: &self.path })?;
            Ok(if changed {
                ConfigChange::Changed
            } else {
                ConfigChange::Unchanged
            })
        }
        .await;
        db.close()
            .await
            .context(error::DatabaseSnafu { path: &self.path })?;
        result
    }

    pub(crate) async fn enable(&self) -> Result<ConfigChange, Error> {
        if !regular_file_exists(&self.path).await? {
            self.create_disabled().await?;
        }
        self.set_enabled(true).await
    }
    #[cfg(test)]
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
                    "CREATE TABLE setting(key TEXT PRIMARY KEY NOT NULL,value TEXT NOT NULL)",
                    "CREATE TABLE proxy_location(location TEXT NOT NULL PRIMARY KEY,proxy_pass TEXT NOT NULL)",
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

// Caller holds a transaction and has validated the legacy configuration.
async fn write_listen(db: &impl ConnectionTrait, path: &Path, target: &str) -> Result<(), Error> {
    let columns = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA table_info(setting)",
        ))
        .await
        .context(error::DatabaseSnafu { path })?;
    if columns.is_empty() {
        db.execute_unprepared("CREATE TABLE setting(key TEXT PRIMARY KEY NOT NULL,value TEXT NOT NULL); DROP TABLE settings; ALTER TABLE proxy_locations RENAME TO proxy_location;").await.context(error::DatabaseSnafu{path})?;
    }
    if target == "off" {
        db.execute_unprepared("DELETE FROM setting WHERE key='listen'")
            .await
            .context(error::DatabaseSnafu { path })?;
    } else {
        db.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"INSERT INTO setting VALUES('listen',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[target.into()])).await.context(error::DatabaseSnafu{path})?;
    }
    Ok(())
}

// A missing column denotes legacy v1; invalid current values must never enable a server.
async fn configured_enabled(db: &impl ConnectionTrait, path: &Path) -> Result<Option<bool>, Error> {
    let columns = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA table_info(settings)",
        ))
        .await
        .context(error::DatabaseSnafu { path })?;
    if !columns
        .iter()
        .any(|column| column.try_get::<String>("", "name").ok().as_deref() == Some("enabled"))
    {
        return Ok(None);
    }
    let rows = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT enabled, typeof(enabled) AS kind FROM settings",
        ))
        .await
        .context(error::DatabaseSnafu { path })?;
    if rows.len() == 1
        && rows[0].try_get::<String>("", "kind").ok().as_deref() == Some("integer")
        && let Ok(value @ (0 | 1)) = rows[0].try_get::<i64>("", "enabled")
    {
        return Ok(Some(value == 1));
    }
    Err(Error::InvalidConfiguration {
        path: path.to_owned(),
        message: "enabled must be one integer in 0..=1".into(),
    })
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

pub(crate) const SERVICE_HINT: &str = "Configuration saved. Run `pishoo reload` to re-read configured identities, or `pishoo reload --pid PID` for a foreground process. Manage the installed service with systemctl or brew services.";

pub(crate) fn print_enable_result(identity: &str, change: ConfigChange) {
    let message = match change {
        ConfigChange::Changed => format!("Server enabled for {identity}."),
        ConfigChange::Unchanged => format!("Server is already enabled for {identity}."),
    };
    super::transcript::print_line(message);
    super::transcript::print_line(SERVICE_HINT);
}

/// Local configuration remains usable when HTTP listening is off.
pub async fn run_listen(
    id: &str,
    scope: Option<&str>,
    home: &DhttpHome,
) -> Result<(), crate::cli::Error> {
    let identity = super::target::IdentityTarget::parse(id)?.into_dhttp_name();
    let profile = home
        .resolve_identity_profile_exactly(identity.as_full())
        .await?;
    let config = ServerConfig::for_profile(&profile);
    if let Some(mode) = scope {
        if !matches!(mode, "internal" | "external" | "all" | "off") {
            return Err(Error::InvalidConfiguration {
                path: config.path.clone(),
                message: "invalid listening scope".into(),
            }
            .into());
        }
        if !regular_file_exists(&config.path).await? {
            config.create_disabled().await?;
        }
    }
    let db = config.open().await?;
    let result = async {
        let tx = db
            .begin()
            .await
            .context(error::DatabaseSnafu { path: &config.path })?;
        let listen = config.listen(&tx).await?;
        let target = scope.unwrap_or(&listen);
        if scope.is_some() {
            write_listen(&tx, &config.path, target).await?;
        }
        tx.commit()
            .await
            .context(error::DatabaseSnafu { path: &config.path })?;
        println!("{}", serde_json::json!({"listen":target}));
        Ok::<_, Error>(())
    }
    .await;
    db.close()
        .await
        .context(error::DatabaseSnafu { path: &config.path })?;
    result?;
    if scope.is_some() {
        super::transcript::print_line(SERVICE_HINT);
    }
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
    async fn changes_listen_without_losing_proxies_and_off_discards_scope() {
        let (_root, _profile, config) = fixture().await;
        let db = config.open().await.unwrap();
        db.execute_unprepared("INSERT INTO proxy_location VALUES('/app', 'http://127.0.0.1:8080')")
            .await
            .unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
        assert_eq!(config.enable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Enabled);
        for scope in ["loopback", "internal", "external", "all"] {
            db.execute_unprepared(&format!("INSERT INTO setting VALUES('listen','{scope}') ON CONFLICT(key) DO UPDATE SET value=excluded.value"))
                .await
                .unwrap();
            assert_eq!(config.enable().await.unwrap(), ConfigChange::Unchanged);
            assert_eq!(config.listen(&db).await.unwrap(), scope);
        }
        assert_eq!(config.disable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.disable().await.unwrap(), ConfigChange::Unchanged);
        assert_eq!(config.listen(&db).await.unwrap(), "off");
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT proxy_pass FROM proxy_location",
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
        db.execute_unprepared("PRAGMA user_version=99")
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
        db.execute_unprepared(
            "PRAGMA user_version=1; INSERT INTO setting VALUES('listen','invalid')",
        )
        .await
        .unwrap();
        assert!(matches!(
            config.enable().await,
            Err(Error::InvalidConfiguration { .. })
        ));
        db.close().await.unwrap();
        fs::remove_file(profile.join(".volume/sys/setting/.db"))
            .await
            .unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Missing);
        assert!(matches!(
            config.disable().await,
            Err(Error::MissingConfiguration { .. })
        ));
        assert!(!profile.join(".volume/sys/setting/.db").exists());
        assert_eq!(config.enable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Enabled);
    }

    #[tokio::test]
    async fn legacy_enabled_migrates_to_a_single_named_mode() {
        let (_root, _profile, config) = fixture().await;
        let db = config.open().await.unwrap();
        db.execute_unprepared("DROP TABLE setting; ALTER TABLE proxy_location RENAME TO proxy_locations; CREATE TABLE settings(listen INTEGER, enabled INTEGER); INSERT INTO settings VALUES(1,0)").await.unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
        assert_eq!(config.enable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.listen(&db).await.unwrap(), "all");
        assert_eq!(configured_enabled(&db, &config.path).await.unwrap(), None);
        assert_eq!(config.disable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.listen(&db).await.unwrap(), "off");
        db.close().await.unwrap();
    }

    #[tokio::test]
    async fn local_listen_enables_named_modes_without_needing_http() {
        let (root, profile, config) = fixture().await;
        let home = DhttpHome::new(root.path().to_path_buf());
        for mode in ["internal", "external", "all", "off"] {
            run_listen("alice.smith", Some(mode), &home).await.unwrap();
            let db = config.open().await.unwrap();
            assert_eq!(config.listen(&db).await.unwrap(), mode);
            assert_eq!(
                config.state().await.unwrap(),
                if mode == "off" {
                    ServerConfigState::Disabled
                } else {
                    ServerConfigState::Enabled
                }
            );
            db.close().await.unwrap();
        }
        for mode in ["0", "1", "both", "ALL", "loopback", "auto", "list"] {
            assert!(run_listen("alice.smith", Some(mode), &home).await.is_err());
        }
        assert!(!profile.ssl_dir().exists());
    }

    #[tokio::test]
    async fn listen_off_preserves_v3_mounts_and_other_settings() {
        let (root, _profile, config) = fixture().await;
        let home = DhttpHome::new(root.path().to_path_buf());
        let db = config.open().await.unwrap();
        db.execute_unprepared("PRAGMA user_version=3; INSERT INTO setting VALUES('theme','dark'); INSERT INTO proxy_location VALUES('/api','http://127.0.0.1:8080')").await.unwrap();
        run_listen("alice.smith", Some("all"), &home).await.unwrap();
        run_listen("alice.smith", Some("off"), &home).await.unwrap();
        assert_eq!(config.listen(&db).await.unwrap(), "off");
        for sql in ["SELECT value FROM setting WHERE key='theme'", "SELECT proxy_pass FROM proxy_location WHERE location='/api'"] {
            assert!(db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, sql)).await.unwrap().is_some());
        }
        let version = db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA user_version")).await.unwrap().unwrap();
        assert_eq!(version.try_get_by_index::<i64>(0).unwrap(), 3);
        db.close().await.unwrap();
    }

    #[tokio::test]
    async fn legacy_v1_migrates_when_listen_changes() {
        let (_root, _profile, config) = fixture().await;
        let db = config.open().await.unwrap();
        db.execute_unprepared(
            "DROP TABLE setting; ALTER TABLE proxy_location RENAME TO proxy_locations; CREATE TABLE settings(listen INTEGER); INSERT INTO settings VALUES(0)",
        )
        .await
        .unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
        assert_eq!(config.enable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.listen(&db).await.unwrap(), "all");
        assert_eq!(config.disable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.listen(&db).await.unwrap(), "off");
        assert_eq!(configured_enabled(&db, &config.path).await.unwrap(), None);
        db.close().await.unwrap();
    }

    #[tokio::test]
    async fn listen_creates_configuration_only_for_an_explicit_valid_mode() {
        let (root, profile, config) = fixture().await;
        let home = DhttpHome::new(root.path().to_path_buf());
        fs::remove_file(profile.join(".volume/sys/setting/.db"))
            .await
            .unwrap();
        assert!(run_listen("alice.smith", None, &home).await.is_err());
        assert!(!profile.join(".volume/sys/setting/.db").exists());
        assert!(
            run_listen("alice.smith", Some("both"), &home)
                .await
                .is_err()
        );
        assert!(!profile.join(".volume/sys/setting/.db").exists());
        run_listen("alice.smith", Some("internal"), &home)
            .await
            .unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Enabled);
        let db = config.open().await.unwrap();
        assert_eq!(config.listen(&db).await.unwrap(), "internal");
        run_listen("alice.smith", Some("off"), &home).await.unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
        db.close().await.unwrap();
        assert!(!profile.ssl_dir().exists());
    }

    #[tokio::test]
    async fn non_regular_database_is_rejected_and_existing_database_is_preserved() {
        let (_root, profile, config) = fixture().await;
        assert!(config.create_disabled().await.is_err());
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
        fs::remove_file(profile.join(".volume/sys/setting/.db"))
            .await
            .unwrap();
        fs::create_dir(profile.join(".volume/sys/setting/.db"))
            .await
            .unwrap();
        assert!(matches!(
            config.enable().await,
            Err(Error::NotRegularFile { .. })
        ));
    }
}
