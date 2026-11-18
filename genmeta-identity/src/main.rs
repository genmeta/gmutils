#![recursion_limit = "256"]

use clap::Parser;
use genmeta_identity::{Cli, run};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let options = Cli::parse();

    match run(options).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::debug!(?error, "Exit with error");
            eprintln!(
                "{}",
                genmeta_identity::display_identity(&snafu::Report::from_error(error).to_string())
            );
            std::process::ExitCode::FAILURE
        }
    }
}
