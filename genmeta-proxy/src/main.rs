use clap::Parser;
use genmeta_proxy::{Options, run};

#[tokio::main]
#[allow(clippy::result_large_err)]
#[snafu::report]
async fn main() -> Result<(), genmeta_proxy::Error> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
