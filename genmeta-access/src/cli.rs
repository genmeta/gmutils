use std::str::FromStr;

use clap::{Args, Parser, Subcommand, error::ErrorKind};
use dhttp_access::{db::identity::Name, expr::exprs::LocationRuleExprs, pattern::LocationPattern};
use snafu::{IntoError, ResultExt, Snafu};

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

impl<T> FromStr for ReportFromStr<T>
where
    T: FromStr<Err: std::error::Error + 'static>,
{
    type Err = ReportError<T::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match T::from_str(s) {
            Ok(value) => Ok(Self(value)),
            Err(source) => Err(ReportError { source }),
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about,
    override_usage = "genmeta access [OPTIONS] <path> <operation> ...\n       genmeta access [OPTIONS] list [--wide]\n       genmeta access [OPTIONS] remove <path>...",
    after_help = "Examples:\n  genmeta access \"/\" allow luffy.pilot\n  genmeta access \"/\" list\n  genmeta access list --wide\n  genmeta access --identity reimu.pilot \"/\" deny \"*?\""
)]
pub struct Options {
    #[arg(
        long,
        value_name = "NAME",
        help = "identity to manage; defaults to `genmeta identity default`"
    )]
    identity: Option<ReportFromStr<Name<'static>>>,

    #[command(subcommand)]
    command: CliCommand,
}

impl Options {
    pub(crate) fn into_parts(self) -> Result<(Option<Name<'static>>, Command), ParseCommandError> {
        let identity = self.identity.map(|ReportFromStr(identity)| identity);
        let command = self.command.try_into()?;
        Ok((identity, command))
    }
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    #[command(visible_alias = "ls")]
    List(GlobalList),
    #[command(visible_alias = "rm")]
    Remove(GlobalRemove),
    #[command(external_subcommand)]
    Path(Vec<String>),
}

#[derive(Args, Debug, Clone)]
struct GlobalList {
    #[arg(short, long)]
    wide: bool,
}

#[derive(Args, Debug, Clone)]
struct GlobalRemove {
    #[arg(required = true)]
    patterns: Vec<ReportFromStr<LocationPattern>>,
}

impl TryFrom<CliCommand> for Command {
    type Error = ParseCommandError;

    fn try_from(value: CliCommand) -> Result<Self, Self::Error> {
        match value {
            CliCommand::List(GlobalList { wide }) => Ok(Self::List { wide }),
            CliCommand::Remove(GlobalRemove { patterns }) => Ok(Self::RemovePaths {
                patterns: patterns
                    .into_iter()
                    .map(|ReportFromStr(pattern)| pattern)
                    .collect(),
            }),
            CliCommand::Path(arguments) => parse_path_command(arguments),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Command {
    Print {
        output: String,
    },
    List {
        wide: bool,
    },
    RemovePaths {
        patterns: Vec<LocationPattern>,
    },
    Path {
        pattern: LocationPattern,
        operation: PathOperation,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum PathOperation {
    List,
    Remove { all: bool, sequence: Vec<usize> },
    Clear,
    Allow { expr: LocationRuleExprs },
    Deny { expr: LocationRuleExprs },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ParseCommandError {
    #[snafu(display("failed to parse access path command"))]
    ParsePathCommand { source: clap::Error },

    #[snafu(display("failed to parse rule expression `{input}`"))]
    InvalidRuleExpr {
        input: String,
        source: <LocationRuleExprs as FromStr>::Err,
    },
}

#[derive(Parser, Debug, Clone)]
#[command(name = "genmeta access")]
struct PathCommand {
    pattern: ReportFromStr<LocationPattern>,

    #[command(subcommand)]
    operation: PathOperationCommand,
}

#[derive(Subcommand, Debug, Clone)]
enum PathOperationCommand {
    #[command(visible_alias = "ls")]
    List,
    #[command(visible_alias = "rm")]
    Remove(PathRemove),
    Clear,
    Allow(RuleExprArgs),
    Deny(RuleExprArgs),
}

#[derive(Args, Debug, Clone)]
struct PathRemove {
    #[arg(long, conflicts_with = "sequence")]
    all: bool,

    #[arg(value_name = "SEQUENCE", required_unless_present = "all")]
    sequence: Vec<usize>,
}

#[derive(Args, Debug, Clone)]
struct RuleExprArgs {
    #[arg(
        value_name = "EXPR",
        required = true,
        num_args = 1..,
        allow_hyphen_values = true,
        trailing_var_arg = true
    )]
    expr: Vec<String>,
}

impl TryFrom<PathCommand> for Command {
    type Error = ParseCommandError;

    fn try_from(value: PathCommand) -> Result<Self, Self::Error> {
        let ReportFromStr(pattern) = value.pattern;
        let operation = value.operation.try_into()?;
        Ok(Command::Path { pattern, operation })
    }
}

impl TryFrom<PathOperationCommand> for PathOperation {
    type Error = ParseCommandError;

    fn try_from(value: PathOperationCommand) -> Result<Self, Self::Error> {
        match value {
            PathOperationCommand::List => Ok(Self::List),
            PathOperationCommand::Remove(PathRemove { all, sequence }) => {
                Ok(Self::Remove { all, sequence })
            }
            PathOperationCommand::Clear => Ok(Self::Clear),
            PathOperationCommand::Allow(args) => args.into_expr().map(|expr| Self::Allow { expr }),
            PathOperationCommand::Deny(args) => args.into_expr().map(|expr| Self::Deny { expr }),
        }
    }
}

impl RuleExprArgs {
    fn into_expr(self) -> Result<LocationRuleExprs, ParseCommandError> {
        let input = self.expr.join(" ");
        input
            .parse()
            .context(parse_command_error::InvalidRuleExprSnafu { input })
    }
}

fn parse_path_command(arguments: Vec<String>) -> Result<Command, ParseCommandError> {
    let command = match PathCommand::try_parse_from(
        std::iter::once("genmeta access").chain(arguments.iter().map(String::as_str)),
    ) {
        Ok(command) => command,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            return Ok(Command::Print {
                output: error.to_string(),
            });
        }
        Err(source) => return Err(parse_command_error::ParsePathCommandSnafu.into_error(source)),
    };
    command.try_into()
}
