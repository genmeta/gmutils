use std::io::IsTerminal;

use clap::Parser;
use snafu::Whatever;

mod display;
mod install;
mod server;

#[cfg(test)]
#[path = "../tests/support/upload_credentials.rs"]
mod test_credentials;

#[derive(Parser, Debug)]
#[command(name = "genmeta", version, about)]
struct Cli {
    /// Enable debug logs
    #[arg(long, global = true)]
    verb: bool,
    #[command(subcommand)]
    options: Options,
}

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
enum Options {
    Access(genmeta_access::Options),
    Curl(genmeta_curl::Options),
    Discover(genmeta_discover::Options),
    #[command(version = genmeta_doctor::VERSION)]
    Doctor {
        #[command(subcommand)]
        options: genmeta_doctor::Options,
    },
    #[command(visible_alias = "id")]
    Identity(genmeta_identity::Cli),
    #[command(flatten)]
    Package(PackageCommand),
    #[command(flatten)]
    Server(server::Command),
    Nslookup(genmeta_nslookup::Options),
    Proxy(genmeta_proxy::Options),
    Version {},
}

#[derive(clap::Subcommand, Debug, Clone)]
enum PackageCommand {
    /// Install a published package and its exact dependencies
    #[command(disable_version_flag = true)]
    Install {
        /// Package short name or canonical publisher/name
        #[arg(required_unless_present_any=["list","info"],conflicts_with_all=["list","info"])]
        target: Option<String>,
        /// Query installed packages without installing or downloading
        #[arg(long,conflicts_with_all=["target","info","version"])]
        list: bool,
        /// Show readable package details with --list
        #[arg(short = 'v', long, requires = "list", conflicts_with_all = ["target", "info", "version"])]
        verbose: bool,
        /// Query an installed package without installing or downloading
        #[arg(long,value_name="NAME",conflicts_with_all=["target","list","version"])]
        info: Option<String>,
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
        /// Exact release version (defaults to the latest published version)
        #[arg(long, value_name = "MAJOR.MINOR.PATCH")]
        version: Option<String>,
    },
    /// Update an installed package from its current verified maintenance publisher
    #[command(disable_version_flag = true)]
    Update {
        /// Package short name or canonical publisher/name
        target: String,
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
        /// Exact release version (defaults to the latest published version)
        #[arg(long, value_name = "MAJOR.MINOR.PATCH")]
        version: Option<String>,
    },
    /// Remove a package, retaining its data and dependencies
    Uninstall {
        /// Package short name or canonical publisher/name
        target: String,
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
    },
}

#[derive(snafu::Snafu, Debug)]
enum Error {
    #[snafu(transparent)]
    Access { source: genmeta_access::Error },
    #[snafu(transparent)]
    Curl { source: genmeta_curl::Error },
    #[snafu(transparent)]
    Doctor { source: genmeta_doctor::Error },
    #[snafu(transparent)]
    Identity { source: genmeta_identity::Error },
    #[snafu(transparent)]
    Nslookup { source: genmeta_nslookup::Error },
    #[snafu(transparent)]
    Proxy { source: genmeta_proxy::Error },
    #[snafu(transparent)]
    Whatever { source: Whatever },
}

fn install_process_crypto_provider() {
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) | Err(_) => {}
    }
}

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), Error> {
    install_process_crypto_provider();

    let Cli { verb, options } = Cli::parse();
    if matches!(
        options,
        Options::Package(_) | Options::Server(_) | Options::Version {}
    ) {
        tracing_subscriber::fmt()
            .with_max_level(if verb {
                tracing::level_filters::LevelFilter::DEBUG
            } else {
                tracing::level_filters::LevelFilter::OFF
            })
            .with_ansi(std::io::stderr().is_terminal())
            .with_writer(std::io::stderr)
            .init();
    }

    run(options).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}

async fn run(options: Options) -> Result<(), Error> {
    match options {
        Options::Access(options) => genmeta_access::run(options).await?,
        Options::Curl(options) => genmeta_curl::run(options).await?,
        Options::Discover(options) => genmeta_discover::run(options).await,
        Options::Doctor { options } => genmeta_doctor::run(options).await?,
        Options::Identity(options) => genmeta_identity::run(options).await?,
        Options::Package(command) => match command {
            PackageCommand::Install {
                target,
                list,
                verbose,
                info,
                id,
                version,
            } => {
                if list {
                    install::run("list", None, id, None, verbose).await?;
                } else if let Some(name) = info {
                    install::run("info", Some(name), id, None, false).await?;
                } else {
                    install::run("install", target, id, version, false).await?;
                }
            }
            PackageCommand::Update {
                target,
                id,
                version,
            } => install::run("update", Some(target), id, version, false).await?,
            PackageCommand::Uninstall { target, id } => {
                install::run("remove", Some(target), id, None, false).await?
            }
        },
        Options::Server(command) => server::run(command).await?,
        Options::Nslookup(options) => genmeta_nslookup::run(options).await?,
        Options::Proxy(options) => genmeta_proxy::run(options).await?,
        Options::Version {} => println!("{}", env!("CARGO_PKG_VERSION")),
    };
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/cli_main.rs"]
mod tests;
