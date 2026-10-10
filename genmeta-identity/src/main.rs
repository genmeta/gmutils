#![recursion_limit = "256"]

use clap::Parser;
use genmeta_identity::{Cli, Error, run};

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), Error> {
    let options = Cli::parse();

    run(options).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
