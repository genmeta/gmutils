use clap::Parser;
use genmeta_doctor::{Error, Options, run};

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), Error> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}
