use snafu::Whatever;

pub async fn publish(_options: crate::release::S3Options) -> Result<(), Whatever> {
    snafu::whatever!("release subcommand not implemented yet")
}
