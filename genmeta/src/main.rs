use clap::Parser;
use snafu::{ResultExt, Whatever};

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

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), Whatever> {
    run(Options::parse()).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}

async fn run(options: Options) -> Result<(), Whatever> {
    match options {
        Options::Ssh3(options) => genmeta_ssh3::run(options).await.whatever_context(""),
        Options::Curl(options) => genmeta_curl::run(options).await,
        Options::Nslookup(options) => genmeta_nslookup::run(options).await.whatever_context(""),
        Options::Discover(options) => genmeta_discover::run(options).await.whatever_context(""),
        Options::Doctor { options } => genmeta_doctor::run(options).await.whatever_context(""),
    }
}
