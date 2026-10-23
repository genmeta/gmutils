use clap::Parser;
use genmeta_doctor::{Error, Options, run};

#[derive(Parser)]
#[command(name = "doctor", version, about)]
struct Cli {
    /// Enable debug logs
    #[arg(long, global = true)]
    verb: bool,
    #[command(subcommand)]
    options: Options,
}

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), Error> {
    let options = Cli::parse().options;

    run(options).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
