#![recursion_limit = "256"]

use clap::{Arg, ArgAction, Command as ClapCommand, CommandFactory, FromArgMatches};
use genmeta_identity::{Cli, Error, run};

fn enable_help(mut cmd: ClapCommand) -> ClapCommand {
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|sc| sc.get_name().to_string())
        .collect();
    for name in names {
        cmd = cmd.mut_subcommand(&name, enable_help);
    }
    cmd = cmd.arg(
        Arg::new("help_flag")
            .short('h')
            .long("help")
            .action(ArgAction::HelpLong)
            .help("Print help"),
    );
    if cmd.get_version().is_some() {
        cmd = cmd.arg(
            Arg::new("version_flag")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .help("Print version"),
        );
    }
    cmd
}

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), Error> {
    let mut cmd = Cli::command();

    let names: Vec<String> = cmd
        .get_subcommands()
        .filter(|sc| !matches!(sc.get_name(), "version"))
        .map(|sc| sc.get_name().to_string())
        .collect();
    for name in names {
        cmd = cmd.mut_subcommand(&name, enable_help);
    }

    let matches = cmd.get_matches();
    let options = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    run(options).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
