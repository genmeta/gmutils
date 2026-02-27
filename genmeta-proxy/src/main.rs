use clap::Parser;
use genmeta_proxy::{Options, run};

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), genmeta_proxy::Error> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
