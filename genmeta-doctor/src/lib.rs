pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, clap::Parser)]
#[command(name = "doctor", version, about)]
pub enum Options {
    Net(genmeta_nat::Options),
    Version {},
}

#[derive(snafu::Snafu, Debug)]
pub enum Error {
    #[snafu(transparent)]
    Nat { source: genmeta_nat::Error },
}

pub async fn run(options: Options) -> Result<(), Error> {
    match options {
        Options::Net(options) => genmeta_nat::run(options).await?,
        Options::Version {} => println!("{}", env!("CARGO_PKG_VERSION")),
    };
    Ok(())
}
