use std::path::{Path, PathBuf};

use dhttp_home::{
    DhttpHome,
    identity::{IdentityProfile, ssl::ResolveIdentityProfileError},
};
#[cfg(test)]
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};
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
    #[snafu(display("invalid Pishoo configuration at {}: {message}", path.display()))]
    InvalidConfiguration { path: PathBuf, message: String },
    #[snafu(display(
        "cannot run Pishoo; install the matching Pishoo release or set PISHOO_BIN: {source}"
    ))]
    PishooUnavailable { source: std::io::Error },
}

impl ServerConfig {
    pub(crate) fn for_profile(profile: &IdentityProfile) -> Self {
        Self {
            path: profile.join(".volume/sys/setting/database"),
        }
    }

    // The host executable owns all schema creation, validation and configuration writes.
    async fn configure(&self, arguments: &[&str]) -> Result<String, Error> {
        let profile = self
            .path
            .ancestors()
            .nth(4)
            .expect("identity configuration path");
        let executable = std::env::var_os("PISHOO_BIN").unwrap_or_else(|| "pishoo".into());
        let output = tokio::process::Command::new(executable)
            .arg("configure")
            .arg("--profile")
            .arg(profile)
            .args(arguments)
            .kill_on_drop(true)
            .output()
            .await
            .context(error::PishooUnavailableSnafu)?;
        let invalid = |message| Error::InvalidConfiguration {
            path: self.path.clone(),
            message,
        };
        if !output.status.success() {
            return Err(invalid(format!(
                "Pishoo configuration command failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| invalid(format!("invalid Pishoo response: {e}")))?;
        let listen = response["listen"]
            .as_str()
            .filter(|value| matches!(*value, "internal" | "external" | "all" | "off"))
            .ok_or_else(|| invalid("invalid Pishoo listen response".into()))?;
        Ok(listen.into())
    }

    pub(crate) async fn state(&self) -> Result<ServerConfigState, Error> {
        if !regular_file_exists(&self.path).await? {
            // Legacy paths are not current host configuration; Pishoo owns fresh initialization.
            return Ok(ServerConfigState::Missing);
        }
        Ok(if self.configure(&["--init"]).await? == "off" {
            ServerConfigState::Disabled
        } else {
            ServerConfigState::Enabled
        })
    }

    pub(crate) async fn enable(&self) -> Result<ConfigChange, Error> {
        match self.state().await? {
            ServerConfigState::Enabled => Ok(ConfigChange::Unchanged),
            _ => {
                self.configure(&["--listen", "all"]).await?;
                Ok(ConfigChange::Changed)
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn disable(&self) -> Result<ConfigChange, Error> {
        match self.state().await? {
            ServerConfigState::Missing => Err(Error::MissingConfiguration {
                path: self.path.clone(),
            }),
            state => {
                self.configure(&["--listen", "off"]).await?;
                Ok(if state == ServerConfigState::Disabled {
                    ConfigChange::Unchanged
                } else {
                    ConfigChange::Changed
                })
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn create_disabled(&self) -> Result<(), Error> {
        if regular_file_exists(&self.path).await? {
            return Err(Error::InvalidConfiguration {
                path: self.path.clone(),
                message: "configuration already exists".into(),
            });
        }
        self.configure(&["--init"]).await?;
        Ok(())
    }

    #[cfg(test)]
    async fn open(&self) -> Result<DatabaseConnection, sea_orm::DbErr> {
        Database::connect(format!(
            "sqlite://{}?mode=rw",
            urlencoding::encode(&self.path.to_string_lossy())
        ))
        .await
    }

    #[cfg(test)]
    async fn listen(&self, _db: &impl ConnectionTrait) -> Result<String, Error> {
        self.configure(&[]).await
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

pub(crate) const SERVICE_HINT: &str =
    "Running Pishoo applies listening changes automatically. Start Pishoo if it is not running.";

/// Delegate local configuration to Pishoo even when its HTTP listener is off.
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
    if scope.is_some_and(|mode| !matches!(mode, "internal" | "external" | "all" | "off")) {
        return Err(Error::InvalidConfiguration {
            path: config.path,
            message: "invalid listening scope".into(),
        }
        .into());
    }
    let listen = match scope {
        Some(mode) => config.configure(&["--listen", mode]).await?,
        None => config.configure(&["--init"]).await?,
    };
    println!("{}", serde_json::json!({"listen":listen}));
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
        let mut names = std::fs::read_dir(profile.join(".volume/sys"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["access", "contact", "pkg", "setting"]);
        assert!(!profile.config_db_path().exists());
        (root, profile, config)
    }

    #[tokio::test]
    #[ignore = "requires matching PISHOO_BIN; run the cross-repository configuration tests"]
    async fn changes_listen_without_losing_proxies_and_off_discards_scope() {
        let (_root, _profile, config) = fixture().await;
        let db = config.open().await.unwrap();
        db.execute_unprepared("INSERT INTO proxy_location VALUES('/app', 'http://127.0.0.1:8080')")
            .await
            .unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
        assert_eq!(config.enable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Enabled);
        for scope in ["internal", "external", "all"] {
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
    #[ignore = "requires matching PISHOO_BIN; run the cross-repository configuration tests"]
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
            "PRAGMA user_version=3; INSERT INTO setting VALUES('listen','invalid')",
        )
        .await
        .unwrap();
        assert!(matches!(
            config.enable().await,
            Err(Error::InvalidConfiguration { .. })
        ));
        db.close().await.unwrap();
        fs::remove_file(profile.join(".volume/sys/setting/database"))
            .await
            .unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Missing);
        assert!(matches!(
            config.disable().await,
            Err(Error::MissingConfiguration { .. })
        ));
        assert!(!profile.join(".volume/sys/setting/database").exists());
        assert_eq!(config.enable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Enabled);
        assert!(!profile.join(".volume/sys/file").exists());
        assert!(!profile.join("app").exists());
    }

    #[tokio::test]
    #[ignore = "requires matching PISHOO_BIN; run the cross-repository configuration tests"]
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
    #[ignore = "requires matching PISHOO_BIN; run the cross-repository configuration tests"]
    async fn listen_off_preserves_v3_mounts_and_other_settings() {
        let (root, _profile, config) = fixture().await;
        let home = DhttpHome::new(root.path().to_path_buf());
        let db = config.open().await.unwrap();
        db.execute_unprepared("PRAGMA user_version=3; INSERT INTO setting VALUES('theme','dark'); INSERT INTO proxy_location VALUES('/api','http://127.0.0.1:8080')").await.unwrap();
        run_listen("alice.smith", Some("all"), &home).await.unwrap();
        run_listen("alice.smith", Some("off"), &home).await.unwrap();
        assert_eq!(config.listen(&db).await.unwrap(), "off");
        for sql in [
            "SELECT value FROM setting WHERE key='theme'",
            "SELECT proxy_pass FROM proxy_location WHERE location='/api'",
        ] {
            assert!(
                db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, sql))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        let version = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA user_version",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(version.try_get_by_index::<i64>(0).unwrap(), 3);
        db.close().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires matching PISHOO_BIN; run the cross-repository configuration tests"]
    async fn old_versions_are_archived_and_enabled_with_fresh_configuration() {
        for version in [1, 2] {
            let (_root, profile, config) = fixture().await;
            let db = config.open().await.unwrap();
            db.execute_unprepared(&format!("PRAGMA user_version={version}; INSERT INTO setting VALUES('listen','invalid'); INSERT INTO proxy_location VALUES('/old','http://127.0.0.1:8080')"))
                .await.unwrap();
            db.close().await.unwrap();
            assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
            assert_eq!(config.enable().await.unwrap(), ConfigChange::Changed);
            assert_eq!(config.state().await.unwrap(), ServerConfigState::Enabled);
            let archives = std::fs::read_dir(profile.join(".volume/sys"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".setting-v")
                })
                .collect::<Vec<_>>();
            assert_eq!(archives.len(), 1);
            assert!(archives[0].path().join("setting/database").is_file());
            let db = config.open().await.unwrap();
            let row = db
                .query_one_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    "SELECT count(*) FROM proxy_location",
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.try_get_by_index::<i64>(0).unwrap(), 0);
            db.close().await.unwrap();
            assert!(!profile.join(".volume/sys/app").exists());
            assert!(!profile.join(".volume/sys/lib").exists());
        }
    }

    #[tokio::test]
    #[ignore = "requires matching PISHOO_BIN; run the cross-repository configuration tests"]
    async fn listen_query_initializes_missing_configuration_and_modes_remain_validated() {
        let (root, profile, config) = fixture().await;
        let home = DhttpHome::new(root.path().to_path_buf());
        fs::remove_file(profile.join(".volume/sys/setting/database"))
            .await
            .unwrap();
        run_listen("alice.smith", None, &home).await.unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
        assert!(
            run_listen("alice.smith", Some("both"), &home)
                .await
                .is_err()
        );
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
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
    #[ignore = "requires matching PISHOO_BIN; run the cross-repository configuration tests"]
    async fn non_regular_database_is_rejected_and_existing_database_is_preserved() {
        let (_root, profile, config) = fixture().await;
        assert!(config.create_disabled().await.is_err());
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Disabled);
        fs::remove_file(profile.join(".volume/sys/setting/database"))
            .await
            .unwrap();
        fs::create_dir(profile.join(".volume/sys/setting/database"))
            .await
            .unwrap();
        assert!(matches!(
            config.enable().await,
            Err(Error::NotRegularFile { .. })
        ));
    }
    #[tokio::test]
    #[ignore = "requires matching PISHOO_BIN; run the cross-repository configuration tests"]
    async fn legacy_path_does_not_block_fresh_service_activation() {
        let (root, profile, config) = fixture().await;
        fs::remove_file(&config.path).await.unwrap();
        fs::create_dir_all(profile.db_dir()).await.unwrap();
        fs::write(profile.config_db_path(), b"old configuration kept")
            .await
            .unwrap();
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Missing);
        assert_eq!(config.enable().await.unwrap(), ConfigChange::Changed);
        assert_eq!(config.state().await.unwrap(), ServerConfigState::Enabled);
        run_listen(
            "alice.smith",
            Some("internal"),
            &DhttpHome::new(root.path().to_path_buf()),
        )
        .await
        .unwrap();
        assert_eq!(
            fs::read(profile.config_db_path()).await.unwrap(),
            b"old configuration kept"
        );
    }
}
