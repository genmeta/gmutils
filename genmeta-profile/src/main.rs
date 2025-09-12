use clap::Parser;
use genmeta_profile::{Options, run};
use snafu::Whatever;

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), Whatever> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
