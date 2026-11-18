use clap::Parser;
use genmeta_curl::{Options, run};

#[tokio::main]
#[allow(clippy::result_large_err)]
async fn main() -> std::process::ExitCode {
    match run(Options::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::debug!(?error, "Exit with error");
            eprintln!(
                "{}",
                genmeta_curl::display_identity(&snafu::Report::from_error(error).to_string())
            );
            std::process::ExitCode::FAILURE
        }
    }
}
