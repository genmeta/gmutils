use genmeta_common::error::Whatever;

#[derive(Debug, Clone, clap::Parser)]
#[command(name = "doctor", version, about)]
pub enum Options {
    Net(genmeta_nat::Options),
}

#[derive(snafu::Snafu, Debug)]
pub enum Error {
    #[snafu(transparent)]
    Whatever { source: Whatever },
}

pub async fn run(options: Options) -> Result<(), Error> {
    match options {
        Options::Net(options) => genmeta_nat::run(options).await?,
    };
    Ok(())
}
