use clap::Parser;

#[derive(Parser, Debug)]
pub struct Options {}

#[derive(Debug)]
pub enum Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

impl std::error::Error for Error {}

pub async fn run(_: Options) -> Result<(), Error> {
    Ok(())
}
