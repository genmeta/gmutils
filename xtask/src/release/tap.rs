use snafu::Whatever;

pub async fn update(_repo: std::path::PathBuf, _commit: bool, _push: bool) -> Result<(), Whatever> {
    snafu::whatever!("release subcommand not implemented yet")
}
