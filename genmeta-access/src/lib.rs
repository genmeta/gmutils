mod cli;

use std::io::IsTerminal;

pub use cli::{Options, ParseCommandError, ReportFromStr};
use dhttp_home::{DhttpHome, LocateDhttpHomeError, identity::default::LoadDefaultConfigError};
use firewall_base::{
    action::RequestAction,
    error::location::{LocateLocationFailed, MatchLocationFailed},
};
use firewall_db::{
    identity::Name,
    identity_access_db_path, init_access_database_for, open_access_database,
    service::{
        error::Error as ServiceError,
        location_service::{LocationService, RemoveRuleFailed},
    },
};
use snafu::{IntoError, OptionExt, ResultExt, Snafu};
use tracing_subscriber::prelude::*;

use crate::cli::{Command, PathOperation};

// --- Error ---

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(transparent)]
    ParseCommand { source: ParseCommandError },

    #[snafu(display("failed to locate DHTTP_HOME"))]
    LocateHome { source: LocateDhttpHomeError },

    #[snafu(display("failed to load default identity config"))]
    LoadDefaultIdentityConfig { source: LoadDefaultConfigError },

    #[snafu(display(
        "no default identity configured, use `genmeta identity default <name>` to set one"
    ))]
    MissingDefaultIdentity,

    #[snafu(display("failed to initialize identity access database"))]
    InitDatabase { source: firewall_db::AccessDbError },

    #[snafu(display("failed to open identity access database"))]
    OpenDatabase { source: firewall_db::AccessDbError },

    #[snafu(display("failed to list access path rules"))]
    ListRules {
        source: ServiceError<MatchLocationFailed>,
    },

    #[snafu(display("failed to remove access path"))]
    RemovePath {
        source: ServiceError<LocateLocationFailed>,
    },

    #[snafu(display("failed to remove rules"))]
    RemoveRules {
        source: ServiceError<RemoveRuleFailed>,
    },

    #[snafu(display("failed to add rule"))]
    AddRule { source: sea_orm::DbErr },

    #[snafu(display("failed to list access paths"))]
    ListPaths { source: sea_orm::DbErr },
}

// --- Logic ---

fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (stderr, guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    guard
}

pub async fn run(options: Options) -> Result<(), Error> {
    let _guard = init_tracing();

    let home = DhttpHome::load_from_environment().context(error::LocateHomeSnafu)?;
    let output = run_for_home(&home, options).await?;

    if !output.is_empty() {
        println!("{}", output.trim_end());
    }
    Ok(())
}

pub async fn run_for_home(home: &DhttpHome, options: Options) -> Result<String, Error> {
    let (identity, command) = options.into_parts()?;
    if let Command::Print { output } = command {
        return Ok(output);
    }

    let identity = resolve_identity(home, identity).await?;
    let identity_home = home.identity_home(identity.borrow());
    let db_path = identity_access_db_path(&identity_home);
    let db = if db_path.is_file() {
        open_access_database(&identity_home)
            .await
            .context(error::OpenDatabaseSnafu)?
    } else {
        tracing::warn!(
            "access store not found, initializing at `{}`",
            db_path.display()
        );
        init_access_database_for(&identity_home)
            .await
            .context(error::InitDatabaseSnafu)?
    };
    run_with(command, &db).await
}

async fn resolve_identity(
    home: &DhttpHome,
    identity: Option<Name<'static>>,
) -> Result<Name<'static>, Error> {
    if let Some(identity) = identity {
        return Ok(identity);
    }

    let config = match home.load_identity_default_config().await {
        Ok(config) => config,
        Err(LoadDefaultConfigError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return error::MissingDefaultIdentitySnafu.fail();
        }
        Err(source) => return Err(error::LoadDefaultIdentityConfigSnafu.into_error(source)),
    };

    config
        .config()
        .name()
        .cloned()
        .context(error::MissingDefaultIdentitySnafu)
}

async fn run_with(command: Command, db: &sea_orm::DatabaseConnection) -> Result<String, Error> {
    let location_service = LocationService::new(db);

    match command {
        Command::Print { output } => return Ok(output),
        Command::Path { pattern, operation } => match operation {
            PathOperation::List => match location_service.list_rules(&pattern).await {
                Ok(rules) => return Ok(rules.to_string()),
                Err(ServiceError::Custom { source }) => return Ok(source.to_string()),
                result => _ = result.context(error::ListRulesSnafu)?,
            },
            PathOperation::Remove { all, sequence } => match all {
                true => location_service
                    .remove_rule_set(&pattern)
                    .await
                    .context(error::RemovePathSnafu)?,
                false => location_service
                    .remove_rules(&pattern, sequence)
                    .await
                    .context(error::RemoveRulesSnafu)?,
            },
            PathOperation::Clear => location_service
                .remove_rule_set(&pattern)
                .await
                .context(error::RemovePathSnafu)?,
            PathOperation::Allow { expr } => location_service
                .append_rule(&pattern, RequestAction::Allow, expr)
                .await
                .context(error::AddRuleSnafu)?,
            PathOperation::Deny { expr } => location_service
                .append_rule(&pattern, RequestAction::Deny, expr)
                .await
                .context(error::AddRuleSnafu)?,
        },
        Command::List { wide } => match wide {
            true => {
                return Ok(location_service
                    .list_all_rules()
                    .await
                    .context(error::ListPathsSnafu)?
                    .to_string());
            }
            false => {
                return Ok(location_service
                    .list_rule_sets()
                    .await
                    .context(error::ListPathsSnafu)?
                    .to_string());
            }
        },
        Command::RemovePaths { patterns } => {
            for pattern in patterns {
                location_service
                    .remove_rule_set(&pattern)
                    .await
                    .context(error::RemovePathSnafu)?;
            }
        }
    }

    Ok(String::new())
}
