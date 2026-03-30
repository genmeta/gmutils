use std::str::FromStr;

use clap::Parser;
use firewall_base::{
    action::RequestAction, expr::exprs::LocationRuleExprs, pattern::LocationPattern,
};
use firewall_db::{
    access_db_path,
    identity::Name,
    init_identity_access_database, load_genmeta_home, open_identity_access_database,
    service::{error::Error as ServiceError, location_service::LocationService},
};
use snafu::{OptionExt, ResultExt, Snafu};

// --- CLI types ---

#[derive(Debug, Clone, Copy)]
struct ReportFromStr<T>(T);

#[derive(Debug, snafu::Snafu)]
#[snafu(display("{}", snafu::Report::from_error(source)))]
struct ReportError<E: std::error::Error + 'static> {
    #[snafu(source(false))]
    source: E,
}

impl<T> FromStr for ReportFromStr<T>
where
    T: FromStr<Err: std::error::Error + 'static>,
{
    type Err = ReportError<T::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        T::from_str(s)
            .map(Self)
            .map_err(|source| ReportError { source })
    }
}

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
    Init {
        identity: ReportFromStr<Name<'static>>,
    },
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
pub struct Options {
    identity: Option<ReportFromStr<Name<'static>>>,

    #[command(subcommand)]
    command: Command,
}

// --- Error ---

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(display("failed to locate GENMETA_HOME"))]
    LocateHome { source: firewall_db::AccessDbError },

    #[snafu(display("identity is required for this command"))]
    MissingIdentity,

    #[snafu(display("failed to initialize identity access database"))]
    InitDatabase { source: firewall_db::AccessDbError },

    #[snafu(display("failed to open identity access database"))]
    OpenDatabase { source: firewall_db::AccessDbError },

    #[snafu(display("failed to list ruleset rules"))]
    ListRules {
        source: ServiceError<firewall_base::error::location::MatchLocationFailed>,
    },

    #[snafu(display("failed to remove ruleset"))]
    RemoveRuleSet {
        source: ServiceError<firewall_base::error::location::LocateLocationFailed>,
    },

    #[snafu(display("failed to remove rules"))]
    RemoveRules {
        source: ServiceError<firewall_db::service::location_service::RemoveRuleFailed>,
    },

    #[snafu(display("failed to add rule"))]
    AddRule { source: sea_orm::DbErr },

    #[snafu(display("failed to list rulesets"))]
    ListRuleSets { source: sea_orm::DbErr },
}

// --- Logic ---

fn tracing_init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

async fn run_with(command: Command, db: &sea_orm::DatabaseConnection) -> Result<String, Error> {
    let location_service = LocationService::new(db);

    match command {
        Command::Init { .. } => return Ok(String::new()),
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

pub async fn run(options: Options) -> Result<(), Error> {
    tracing_init();

    let home = load_genmeta_home().context(error::LocateHomeSnafu)?;
    let output = match options.command {
        Command::Init {
            identity: ReportFromStr(identity),
        } => {
            init_identity_access_database(&home, identity.borrow())
                .await
                .context(error::InitDatabaseSnafu)?;
            access_db_path(&home, identity.borrow())
                .display()
                .to_string()
        }
        command => {
            let identity = options
                .identity
                .map(|ReportFromStr(id)| id)
                .context(error::MissingIdentitySnafu)?;
            let db = open_identity_access_database(&home, identity.borrow())
                .await
                .context(error::OpenDatabaseSnafu)?;
            run_with(command, &db).await?
        }
    };

    if !output.is_empty() {
        println!("{}", output.trim_end());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;
    use firewall_db::{GenmetaHome, access_db_path, init_identity_access_database};

    use super::*;

    struct TestHome {
        path: PathBuf,
    }

    impl TestHome {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "genmeta-access-tests-{name}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn home(&self) -> GenmetaHome {
            GenmetaHome::new(self.path.clone())
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    async fn run_cli(home: &GenmetaHome, command: &str) -> String {
        let mut args = vec!["access"];
        args.extend(command.split_whitespace());
        let options = Options::parse_from(&args);
        run_for_home(home, options)
            .await
            .unwrap_or_else(|error| panic!("{}", snafu::Report::from_error(error)))
    }

    async fn run_for_home(home: &GenmetaHome, options: Options) -> Result<String, Error> {
        match options.command {
            Command::Init {
                identity: ReportFromStr(identity),
            } => {
                init_identity_access_database(home, identity.borrow())
                    .await
                    .context(error::InitDatabaseSnafu)?;
                Ok(access_db_path(home, identity.borrow())
                    .display()
                    .to_string())
            }
            command => {
                let identity = options
                    .identity
                    .map(|ReportFromStr(id)| id)
                    .context(error::MissingIdentitySnafu)?;
                let db = open_identity_access_database(home, identity.borrow())
                    .await
                    .context(error::OpenDatabaseSnafu)?;
                run_with(command, &db).await
            }
        }
    }

    #[tokio::test]
    async fn cli_identity_init_creates_store() {
        let test_home = TestHome::new("cli-init");
        let home = test_home.home();
        let identity: Name<'static> = "alice.pilot".parse().unwrap();

        run_cli(&home, "init alice.pilot").await;

        assert!(access_db_path(&home, identity.borrow()).is_file());
    }

    #[tokio::test]
    async fn cli_identity_command_fails_without_store() {
        let test_home = TestHome::new("cli-missing-store");
        let home = test_home.home();

        let error = run_for_home(
            &home,
            Options::parse_from(["access", "alice.pilot", "rulesets", "list"]),
        )
        .await
        .unwrap_err();

        let rendered = format!("{}", snafu::Report::from_error(error));
        assert!(rendered.contains("access store does not exist"));
    }

    #[tokio::test]
    async fn invalid_identity_input_error() {
        let error = Options::try_parse_from(["access", "invalid identity", "rulesets", "list"])
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("name contains invalid characters")
        );
    }

    #[tokio::test]
    async fn cli_ruleset_crud_flow() {
        let test_home = TestHome::new("cli-ruleset-crud");
        let home = test_home.home();
        let identity: Name<'static> = "alice.pilot".parse().unwrap();
        init_identity_access_database(&home, identity.borrow())
            .await
            .unwrap();

        run_cli(&home, "alice.pilot ruleset /api deny *?").await;
        let listed = run_cli(&home, "alice.pilot ruleset /api rules list").await;
        assert!(listed.contains("/api"));
        assert!(listed.contains("deny *?"));

        let all = run_cli(&home, "alice.pilot rulesets list --wide").await;
        assert!(all.contains("/api"));

        run_cli(&home, "alice.pilot ruleset /api rules remove 0").await;
        let after_remove = run_cli(&home, "alice.pilot ruleset /api rules list").await;
        assert!(after_remove.contains("- /api"));
        assert!(!after_remove.contains("deny *?"));
    }

    #[tokio::test]
    async fn end_to_end_identity_store_isolation() {
        let test_home = TestHome::new("cli-isolation");
        let home = test_home.home();

        run_cli(&home, "init alice.pilot").await;
        run_cli(&home, "init bob.pilot").await;
        run_cli(&home, "alice.pilot ruleset /api allow *?").await;

        let alice_rules = run_cli(&home, "alice.pilot rulesets list --wide").await;
        let bob_rules = run_cli(&home, "bob.pilot rulesets list --wide").await;

        assert!(alice_rules.contains("/api"));
        assert!(!bob_rules.contains("/api"));
    }
}
