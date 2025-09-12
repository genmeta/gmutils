use snafu::Whatever;

#[derive(Debug, Clone, clap::Parser)]
#[command(name = "doctor", version, about)]
pub enum Options {
    /// Diagnose network and environment issues
    Net(genmeta_nat::Options),
    Profile(genmeta_profile::Options),
}

pub async fn run(options: Options) -> Result<(), Whatever> {
    match options {
        Options::Net(options) => genmeta_nat::run(options).await,
        Options::Profile(options) => genmeta_profile::run(options).await,
    }
}
