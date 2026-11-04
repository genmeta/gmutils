use dhttp_identity::name::DhttpName;
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};

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
    db.execute_unprepared("PRAGMA user_version=3; INSERT INTO setting VALUES('listen','invalid')")
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

impl ServerConfig {
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

    async fn open(&self) -> Result<DatabaseConnection, sea_orm::DbErr> {
        Database::connect(format!(
            "sqlite://{}?mode=rw",
            urlencoding::encode(&self.path.to_string_lossy())
        ))
        .await
    }

    async fn listen(&self, _db: &impl ConnectionTrait) -> Result<String, Error> {
        self.configure(&[]).await
    }
}
