use clap::Parser;
use genmeta_nat::{Options, run};

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), genmeta_nat::Error> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
