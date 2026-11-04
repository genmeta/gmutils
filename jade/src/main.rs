use std::{io::IsTerminal, process::ExitCode};

use clap::Parser;
use indicatif::ProgressStyle;
use tracing_indicatif::{
    IndicatifLayer,
    filter::{IndicatifFilter, hide_indicatif_span_fields},
};
use tracing_subscriber::{
    Layer, fmt::format::DefaultFields, layer::SubscriberExt, util::SubscriberInitExt,
};

mod archive;
mod cli;
mod display;
mod error;
mod identity;
mod pack;
mod package;
mod project;
mod run;
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
                .filter(|arg| matches!(*arg, "create" | "build" | "publish" | "run"));
            return display::failure(command, json, &error::Error::new("E_USAGE", error));
        }
    };
    let indicatif_layer = IndicatifLayer::new()
        .with_span_field_formatter(hide_indicatif_span_fields(DefaultFields::new()))
        .with_progress_style(
            ProgressStyle::with_template("{span_child_prefix}{spinner} {msg}")
                .expect("BUG: static progress bar template is valid"),
        );
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_writer(indicatif_layer.get_stderr_writer())
                .with_filter(if cli.verb {
                    tracing::level_filters::LevelFilter::DEBUG
                } else {
                    tracing::level_filters::LevelFilter::OFF
                }),
        )
        .with(
            (!cli.json && std::io::stderr().is_terminal())
                .then(|| indicatif_layer.with_filter(IndicatifFilter::new(false))),
        )
        .init();
    let command = cli.options.name();
    let result = if command == "run" {
        cli::run(cli.options, cli.json).await
    } else {
        tokio::select! {
            result = cli::run(cli.options, cli.json) => result,
            _ = tokio::signal::ctrl_c() => Err(error::Error::new("E_CANCELLED", "Command cancelled")),
        }
    };
    match result {
        Ok(value) => match display::success(command, cli.json, cli.verb, value) {
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
