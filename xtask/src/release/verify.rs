use snafu::Whatever;

pub async fn run(_options: crate::release::VerifyOptions) -> Result<(), Whatever> {
    snafu::whatever!("release subcommand not implemented yet")
}
