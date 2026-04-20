use clap::Parser;
use genmeta_proxy::{Options, run};
use snafu::ResultExt;

#[allow(clippy::result_large_err)]
#[snafu::report]
fn main() -> Result<(), genmeta_proxy::Error> {
    let options = Options::parse();

    if options.daemon {
        #[cfg(unix)]
        {
            let mut d = daemonize::Daemonize::new();
            if let Some(ref log_path) = options.log {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path)
                    .context(genmeta_proxy::CreateLogFileSnafu {
                        path: log_path.clone(),
                    })?;
                d = d.stderr(file);
            }
            d.start().context(genmeta_proxy::DaemonizeSnafu)?;
        }
        #[cfg(not(unix))]
        {
            return Err(<genmeta_proxy::Error as snafu::FromString>::without_source(
                "--daemon is not supported on this platform".to_owned(),
            ));
        }
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            <genmeta_proxy::Error as snafu::FromString>::with_source(
                Box::new(e),
                "failed to build tokio runtime".to_owned(),
            )
        })?
        .block_on(run(options))
        .inspect_err(|error| {
            tracing::debug!(?error, "Exit with error");
        })
}
