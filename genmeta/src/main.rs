use clap::Parser;
use genmeta_common::error::Whatever;

#[derive(Parser, Debug, Clone)]
#[command(version)]
enum Options {
    Ssh3(genmeta_ssh3::Options),
    Curl(genmeta_curl::Options),
    Discover(genmeta_discover::Options),
    Doctor {
        #[command(subcommand)]
        options: genmeta_doctor::Options,
    },
    Identity {
        #[command(subcommand)]
        options: genmeta_identity::Options,
    },
    Nslookup(genmeta_nslookup::Options),
}

#[derive(snafu::Snafu, Debug)]
enum Error {
    #[snafu(transparent)]
    Doctor { source: genmeta_doctor::Error },
    #[snafu(transparent)]
    Identity { source: genmeta_identity::Error },
    #[snafu(transparent)]
    Nslookup { source: genmeta_nslookup::Error },
    #[snafu(transparent)]
    Ssh3 { source: genmeta_ssh3::Error },
    #[snafu(transparent)]
    Curl { source: genmeta_curl::Error },
    #[snafu(transparent)]
    Discover { source: genmeta_discover::Error },
    #[snafu(transparent)]
    Whatever { source: Whatever },
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
        Options::Curl(options) => genmeta_curl::run(options).await?,
        Options::Discover(options) => genmeta_discover::run(options).await?,
        Options::Doctor { options } => genmeta_doctor::run(options).await?,
        Options::Identity { options } => genmeta_identity::run(options).await?,
        Options::Nslookup(options) => genmeta_nslookup::run(options).await?,
        Options::Ssh3(options) => genmeta_ssh3::run(options).await?,
    };
    Ok(())
}
