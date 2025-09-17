use genmeta_common::error::Whatever;

#[derive(Debug, Clone, clap::Parser)]
#[command(name = "doctor", version, about)]
pub enum Options {
    /// Diagnose network and environment issues
    Net(genmeta_nat::Options),
    Profile(genmeta_profile::Options),
}

#[derive(snafu::Snafu, Debug)]
pub enum Error {
    #[snafu(transparent)]
    Whatever { source: Whatever },
    #[snafu(transparent)]
    Profile { source: genmeta_profile::Error },
}

pub async fn run(options: Options) -> Result<(), Error> {
    match options {
        Options::Net(options) => genmeta_nat::run(options).await?,
        Options::Profile(options) => genmeta_profile::run(options).await?,
    };
    Ok(())
}
