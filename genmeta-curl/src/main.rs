use clap::Parser;
use genmeta_curl::{Options, run};

#[tokio::main]
#[allow(clippy::result_large_err)]
#[snafu::report]
async fn main() -> Result<(), genmeta_curl::Error> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
