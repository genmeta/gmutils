use clap::Parser;
use genmeta_common::error::Whatever;
use genmeta_discover::{Options, run};

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), Whatever> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
