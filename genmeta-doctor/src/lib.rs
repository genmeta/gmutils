use snafu::Whatever;

#[derive(Debug, Clone, clap::Parser)]
#[command(name = "doctor", version, about)]
pub enum Options {
    /// Diagnose network and environment issues
    Net(genmeta_nat::Options),
}

type Error = Whatever;

pub async fn run(options: Options) -> Result<(), Error> {
    match options {
        Options::Net(opt) => genmeta_nat::run(opt).await,
    }
}
