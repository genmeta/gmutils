use std::io::IsTerminal;

use clap::Parser;
use dhttp_home::{DhttpHome, LocateDhttpHomeError};
use firewall_base::{
    action::RequestAction,
    error::location::{LocateLocationFailed, MatchLocationFailed},
    expr::exprs::LocationRuleExprs,
    pattern::LocationPattern,
};
use firewall_db::{
    identity::Name,
    identity_access_db_path, init_access_database_for, open_access_database,
    service::{
        error::Error as ServiceError,
        location_service::{LocationService, RemoveRuleFailed},
    },
};
use snafu::{ResultExt, Snafu};
use tracing_subscriber::prelude::*;

/// Wrapper for clap that uses [`snafu::Report`] for richer error display.
///
/// Use as a clap argument type to get multi-line error chain output when
/// parsing complex types like [`LocationPattern`] or [`Name`]:
///
/// ```ignore
/// #[derive(clap::Parser)]
/// struct Cli {
///     pattern: ReportFromStr<LocationPattern>,
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ReportFromStr<T>(pub T);

#[derive(Debug, Snafu)]
#[snafu(display("{}", snafu::Report::from_error(source)))]
pub struct ReportError<E: std::error::Error + 'static> {
    #[snafu(source(false))]
    source: E,
}

impl<T> std::str::FromStr for ReportFromStr<T>
where
    T: std::str::FromStr<Err: std::error::Error + 'static>,
{
    type Err = ReportError<T::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match T::from_str(s) {
            Ok(value) => Ok(Self(value)),
            Err(source) => Err(ReportError { source }),
        }
    }
}

// --- CLI types ---

#[derive(Parser, Debug, Clone)]
enum RulesOptions {
    #[command(visible_alias = "ls")]
    List {},
    #[command(visible_alias = "rm")]
    Remove {
        #[arg(long, conflicts_with = "sequence")]
        all: bool,
        #[arg(num_args = 1.., required_unless_present = "all")]
        sequence: Vec<usize>,
    },
    Clear {},
}

#[derive(Parser, Debug, Clone)]
enum RuleSetOptions {
    Rules {
        #[command(subcommand)]
        options: RulesOptions,
    },
    Allow {
        #[command(flatten)]
        expr: LocationRuleExprs,
    },
    Deny {
        #[command(flatten)]
        expr: LocationRuleExprs,
    },
}

#[derive(Parser, Debug, Clone)]
enum RuleSetsOptions {
    #[command(visible_alias = "ls")]
    List {
        #[arg(short, long)]
        wide: bool,
    },
    #[command(visible_alias = "rm")]
    Remove {
        patterns: Vec<ReportFromStr<LocationPattern>>,
    },
}

#[derive(Parser, Debug, Clone)]
enum Command {
    Rulesets {
        #[command(subcommand)]
        options: RuleSetsOptions,
    },
    Ruleset {
        pattern: ReportFromStr<LocationPattern>,
        #[command(subcommand)]
        options: RuleSetOptions,
    },
}

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Options {
    identity: ReportFromStr<Name<'static>>,

    #[command(subcommand)]
    command: Command,
}

// --- Error ---

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(display("failed to locate DHTTP_HOME"))]
    LocateHome { source: LocateDhttpHomeError },

    #[snafu(display("failed to initialize identity access database"))]
    InitDatabase { source: firewall_db::AccessDbError },

    #[snafu(display("failed to open identity access database"))]
    OpenDatabase { source: firewall_db::AccessDbError },

    #[snafu(display("failed to list ruleset rules"))]
    ListRules {
        source: ServiceError<MatchLocationFailed>,
    },

    #[snafu(display("failed to remove ruleset"))]
    RemoveRuleSet {
        source: ServiceError<LocateLocationFailed>,
    },

    #[snafu(display("failed to remove rules"))]
    RemoveRules {
        source: ServiceError<RemoveRuleFailed>,
    },

    #[snafu(display("failed to add rule"))]
    AddRule { source: sea_orm::DbErr },

    #[snafu(display("failed to list rulesets"))]
    ListRuleSets { source: sea_orm::DbErr },
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
    let ReportFromStr(identity) = options.identity;
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
    run_with(options.command, &db).await
}

async fn run_with(command: Command, db: &sea_orm::DatabaseConnection) -> Result<String, Error> {
    let location_service = LocationService::new(db);

    match command {
        Command::Ruleset {
            pattern: ReportFromStr(pattern),
            options,
        } => match options {
            RuleSetOptions::Rules { options } => match options {
                RulesOptions::List {} => match location_service.list_rules(&pattern).await {
                    Ok(rules) => return Ok(rules.to_string()),
                    Err(ServiceError::Custom { source }) => return Ok(source.to_string()),
                    result => _ = result.context(error::ListRulesSnafu)?,
                },
                RulesOptions::Remove { all, sequence } => match all {
                    true => location_service
                        .remove_rule_set(&pattern)
                        .await
                        .context(error::RemoveRuleSetSnafu)?,
                    false => location_service
                        .remove_rules(&pattern, sequence)
                        .await
                        .context(error::RemoveRulesSnafu)?,
                },
                RulesOptions::Clear {} => location_service
                    .remove_rule_set(&pattern)
                    .await
                    .context(error::RemoveRuleSetSnafu)?,
            },
            RuleSetOptions::Allow { expr } => location_service
                .append_rule(&pattern, RequestAction::Allow, expr)
                .await
                .context(error::AddRuleSnafu)?,
            RuleSetOptions::Deny { expr } => location_service
                .append_rule(&pattern, RequestAction::Deny, expr)
                .await
                .context(error::AddRuleSnafu)?,
        },
        Command::Rulesets { options } => match options {
            RuleSetsOptions::List { wide } => match wide {
                true => {
                    return Ok(location_service
                        .list_all_rules()
                        .await
                        .context(error::ListRuleSetsSnafu)?
                        .to_string());
                }
                false => {
                    return Ok(location_service
                        .list_rule_sets()
                        .await
                        .context(error::ListRuleSetsSnafu)?
                        .to_string());
                }
            },
            RuleSetsOptions::Remove { patterns } => {
                for ReportFromStr(pattern) in patterns {
                    location_service
                        .remove_rule_set(&pattern)
                        .await
                        .context(error::RemoveRuleSetSnafu)?;
                }
            }
        },
    }

    Ok(String::new())
}
