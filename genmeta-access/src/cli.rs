use std::str::FromStr;

use clap::{Args, Parser, Subcommand, error::ErrorKind};
use genmeta_network::name::DhttpName as Name;
use snafu::{IntoError, Snafu};

use crate::api::{Effect, Method};

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
        T::from_str(s)
            .map(Self)
            .map_err(|source| ReportError { source })
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about = "Manage daccess policies through authenticated DHTTP APIs",
    override_usage = "genmeta access [OPTIONS] <path> <operation> ...\n       genmeta access [OPTIONS] list [--wide]\n       genmeta access [OPTIONS] remove <path>...",
    after_help = "Examples:\n  genmeta access /api allow '*?' --method GET\n  genmeta access /api review '**'\n  genmeta access /api list\n  genmeta access /api remove '*?' --method GET\n  genmeta access list --wide\n\nGrantees: a registered contact name, group@issuer, ** (named), ? (anonymous), *? (all).\nPaths are literal API prefixes; old regex and rule-expression syntax is unsupported."
)]
pub struct Options {
    #[arg(
        long,
        global = true,
        help = "use the global dhttp home instead of the default user home"
    )]
    global: bool,
    #[arg(
        long,
        visible_alias = "id",
        value_name = "NAME",
        help = "identity to manage and authenticate with; defaults to `genmeta identity default`"
    )]
    identity: Option<ReportFromStr<Name<'static>>>,
    #[arg(
        long,
        value_name = "METHOD",
        help = "HTTP method (uppercase or *); defaults to * for writes/grantee removal, all methods for lists/clear"
    )]
    method: Option<ReportFromStr<Method>>,
    /// Timeout in seconds for each management request
    #[arg(long, default_value = "30", value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) timeout: u64,
    #[command(subcommand)]
    command: CliCommand,
}

impl Options {
    pub(crate) fn home_scope(&self) -> genmeta_network::home::HomeScope {
        if self.global {
            genmeta_network::home::HomeScope::Global
        } else {
            genmeta_network::home::HomeScope::User
        }
    }
    pub(crate) fn into_parts(self) -> Result<(Option<Name<'static>>, Command), ParseCommandError> {
        let method = self.method.map(|ReportFromStr(value)| value);
        let command = match self.command {
            CliCommand::List(args) => Command::List {
                wide: args.wide,
                method,
            },
            CliCommand::Remove(args) => Command::RemovePaths {
                paths: args.paths,
                method,
            },
            CliCommand::Path(arguments) => parse_path_command(arguments, method)?,
        };
        Ok((self.identity.map(|ReportFromStr(value)| value), command))
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
    #[arg(required = true, value_parser = parse_api)]
    paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum Command {
    Print {
        output: String,
    },
    List {
        wide: bool,
        method: Option<Method>,
    },
    RemovePaths {
        paths: Vec<String>,
        method: Option<Method>,
    },
    Path {
        path: String,
        method: Option<Method>,
        operation: PathOperation,
    },
}
#[derive(Debug, Clone)]
pub(crate) enum PathOperation {
    List,
    Remove { all: bool, grantees: Vec<String> },
    Clear,
    Set { effect: Effect, grantee: String },
}
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ParseCommandError {
    #[snafu(display("failed to parse access path command"))]
    ParsePathCommand { source: clap::Error },
}

#[derive(Parser, Debug, Clone)]
#[command(name = "genmeta access")]
struct PathCommand {
    #[arg(value_parser = parse_api)]
    path: String,
    #[arg(long, global = true, value_name = "METHOD")]
    method: Option<ReportFromStr<Method>>,
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
    Allow(GranteeArgs),
    Deny(GranteeArgs),
    Review(GranteeArgs),
}
#[derive(Args, Debug, Clone)]
struct PathRemove {
    #[arg(long, conflicts_with = "grantees")]
    all: bool,
    /// Grantees identifying policies to delete (defaults to method *)
    #[arg(value_name = "GRANTEE", required_unless_present = "all", value_parser = parse_grantee)]
    grantees: Vec<String>,
}
#[derive(Args, Debug, Clone)]
struct GranteeArgs {
    #[arg(value_name = "GRANTEE", value_parser = parse_grantee)]
    grantee: String,
}

fn parse_api(input: &str) -> Result<String, String> {
    let uri: http::uri::PathAndQuery = input
        .parse()
        .map_err(|_| "expected a literal API path beginning with /".to_owned())?;
    if !input.starts_with('/') || uri.query().is_some() || input.contains(['#', '*', ' ']) {
        return Err(
            "expected a literal API path beginning with /, without query, wildcard or regex".into(),
        );
    }
    let path = input.trim_end_matches('/');
    Ok(if path.is_empty() { "/" } else { path }.to_owned())
}

fn parse_grantee(input: &str) -> Result<String, String> {
    if matches!(input, "**" | "?" | "*?") {
        return Ok(input.to_owned());
    }
    if let Some((title, issuer)) = input.split_once('@') {
        if title.is_empty() || title.contains([' ', '*', '?', '~', '@']) {
            return Err("invalid group title".into());
        }
        let issuer = genmeta_network::runtime_home::normalize_dns_name(issuer)
            .ok_or("invalid group issuer name")?;
        return Ok(format!("{title}@{issuer}"));
    }
    genmeta_network::runtime_home::normalize_dns_name(input)
        .ok_or_else(|| "invalid contact name; use **, ?, *? or an exact DNS name".into())
}

fn parse_path_command(
    arguments: Vec<String>,
    method: Option<Method>,
) -> Result<Command, ParseCommandError> {
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
    let operation = match command.operation {
        PathOperationCommand::List => PathOperation::List,
        PathOperationCommand::Remove(args) => PathOperation::Remove {
            all: args.all,
            grantees: args.grantees,
        },
        PathOperationCommand::Clear => PathOperation::Clear,
        PathOperationCommand::Allow(args) => PathOperation::Set {
            effect: Effect::Allow,
            grantee: args.grantee,
        },
        PathOperationCommand::Deny(args) => PathOperation::Set {
            effect: Effect::Deny,
            grantee: args.grantee,
        },
        PathOperationCommand::Review(args) => PathOperation::Set {
            effect: Effect::Review,
            grantee: args.grantee,
        },
    };
    Ok(Command::Path {
        path: command.path,
        method: command.method.map(|ReportFromStr(value)| value).or(method),
        operation,
    })
}
