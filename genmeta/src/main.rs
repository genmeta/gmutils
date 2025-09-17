use clap::Parser;
use genmeta_common::error::Whatever;

#[derive(Parser, Debug, Clone)]
#[command(version)]
enum Options {
    Ssh3(genmeta_ssh3::Options),
    Curl(genmeta_curl::Options),
    Nslookup(genmeta_nslookup::Options),
    Discover(genmeta_discover::Options),
    Doctor {
        #[command(subcommand)]
        options: genmeta_doctor::Options,
    },
}

#[derive(snafu::Snafu, Debug)]
enum Error {
    #[snafu(transparent)]
    Whatever { source: Whatever },
    #[snafu(transparent)]
    Ssh3 { source: genmeta_ssh3::Error },
    #[snafu(transparent)]
    Nslookup { source: genmeta_nslookup::Error },
    #[snafu(transparent)]
    Doctor { source: genmeta_doctor::Error },
}

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), Error> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}

async fn run(options: Options) -> Result<(), Error> {
    match options {
        Options::Ssh3(options) => genmeta_ssh3::run(options).await?,
        Options::Curl(options) => genmeta_curl::run(options).await?,
        Options::Nslookup(options) => genmeta_nslookup::run(options).await?,
        Options::Discover(options) => genmeta_discover::run(options).await?,
        Options::Doctor { options } => genmeta_doctor::run(options).await?,
    };
    Ok(())
}
