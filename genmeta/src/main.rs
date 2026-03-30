use clap::Parser;
use snafu::Whatever;

#[derive(Parser, Debug, Clone)]
enum Options {
    Access(genmeta_access::Options),
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
    Proxy(genmeta_proxy::Options),
    Ssh(genmeta_ssh::Options),
    Version {},
}

#[derive(snafu::Snafu, Debug)]
enum Error {
    #[snafu(transparent)]
    Access { source: genmeta_access::Error },
    #[snafu(transparent)]
    Curl { source: genmeta_curl::Error },
    #[snafu(transparent)]
    Discover { source: genmeta_discover::Error },
    #[snafu(transparent)]
    Doctor { source: genmeta_doctor::Error },
    #[snafu(transparent)]
    Identity { source: genmeta_identity::Error },
    #[snafu(transparent)]
    Nslookup { source: genmeta_nslookup::Error },
    #[snafu(transparent)]
    Proxy { source: genmeta_proxy::Error },
    #[snafu(transparent)]
    Ssh { source: genmeta_ssh::Error },
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
        Options::Access(options) => genmeta_access::run(options).await?,
        Options::Curl(options) => genmeta_curl::run(options).await?,
        Options::Discover(options) => genmeta_discover::run(options).await?,
        Options::Doctor { options } => genmeta_doctor::run(options).await?,
        Options::Identity { options } => genmeta_identity::run(options).await?,
        Options::Nslookup(options) => genmeta_nslookup::run(options).await?,
        Options::Proxy(options) => genmeta_proxy::run(options).await?,
        Options::Ssh(options) => genmeta_ssh::run(options).await?,
        Options::Version {} => println!("{}", env!("CARGO_PKG_VERSION")),
    };
    Ok(())
}
