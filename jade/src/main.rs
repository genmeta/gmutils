use std::{io::IsTerminal, process::ExitCode};

use clap::Parser;

mod archive;
mod cli;
mod display;
mod error;
mod identity;
mod pack;
mod package;
mod project;
mod upload;

#[cfg(test)]
#[path = "../tests/support/upload_credentials.rs"]
mod test_credentials;

#[derive(Parser, Debug)]
#[command(name = "jade", version, about)]
struct Cli {
    /// Enable debug logs on stderr
    #[arg(long, global = true)]
    verb: bool,
    /// Write one JSON result to stdout; disable interactive prompts
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    options: cli::Command,
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = std::env::args_os().collect::<Vec<_>>();
    let json = args
        .iter()
        .skip(1)
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--json");
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            return if error.print().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Err(error) => {
            let command = args
                .iter()
                .skip(1)
                .take_while(|arg| *arg != "--")
                .filter_map(|arg| arg.to_str())
                .find(|arg| !arg.starts_with('-'))
                .filter(|arg| matches!(*arg, "create" | "build" | "publish"));
            return display::failure(command, json, &error::Error::new("E_USAGE", error));
        }
    };
    tracing_subscriber::fmt()
        .with_max_level(if cli.verb {
            tracing::level_filters::LevelFilter::DEBUG
        } else {
            tracing::level_filters::LevelFilter::OFF
        })
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();
    let command = cli.options.name();
    let result = tokio::select! {
        result = cli::run(cli.options, cli.json) => result,
        _ = tokio::signal::ctrl_c() => Err(error::Error::new("E_CANCELLED", "Command cancelled")),
    };
    match result {
        Ok(value) => match display::success(command, cli.json, value) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => display::failure(Some(command), cli.json, &error),
        },
        Err(error) => {
            tracing::debug!(?error, "Command failed");
            display::failure(Some(command), cli.json, &error)
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/cli_main.rs"]
mod tests;
