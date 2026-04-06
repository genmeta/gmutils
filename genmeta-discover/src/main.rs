use clap::Parser;
use genmeta_discover::{Options, run};

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), genmeta_discover::Error> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "exit with error");
    })
}
