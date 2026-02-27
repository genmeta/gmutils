use clap::Parser;
use genmeta_curl::{Options, run};

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), genmeta_curl::Error> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
