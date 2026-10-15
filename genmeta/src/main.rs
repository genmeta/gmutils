use std::path::PathBuf;

use clap::Parser;
use snafu::Whatever;

mod install;
mod pack;
mod server;

#[cfg(test)]
#[path = "../tests/support/upload_credentials.rs"]
mod test_credentials;
mod upload;

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
    /// Build, publish and manage App and Lib packages
    #[command(version)]
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
    /// Manage Pishoo reverse proxy configuration
    Server {
        #[command(subcommand)]
        command: server::Command,
    },
    Nslookup(genmeta_nslookup::Options),
    Proxy(genmeta_proxy::Options),
    Version {},
}

#[derive(clap::Subcommand, Debug, Clone)]
enum PackageCommand {
    /// Build a local project and create a signed WEBC package
    #[command(version)]
    Build {
        /// Project directory or build manifest
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Sign already-built artifacts without running the source build
        #[arg(long)]
        no_build: bool,
        /// Signed output file (defaults to the built manifest's dist directory)
        #[arg(short, long, value_name = "FILE.webc")]
        output: Option<PathBuf>,
        /// Check the signing identity against the built manifest publisher
        #[arg(short, long, value_name = "PUBLISHER")]
        id: Option<String>,
    },
    /// Publish a signed WEBC package to the trusted store
    #[command(version)]
    Publish {
        /// Existing signed WEBC file
        file: PathBuf,
        #[arg(short, long, value_name = "PUBLISHER")]
        id: Option<String>,
    },
    /// Install a published package and its exact dependencies
    #[command(disable_version_flag = true)]
    Install {
        /// Package short name or canonical publisher/name
        target: String,
        /// Install this local signed WEBC instead of downloading from the store
        #[arg(long, conflicts_with = "version")]
        file: Option<PathBuf>,
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
        /// Exact release version (defaults to the latest published version)
        #[arg(long, value_name = "MAJOR.MINOR.PATCH")]
        version: Option<String>,
        #[arg(long = "type", value_name = "TYPE", default_value = "app", value_parser = ["app", "lib"])]
        kind: String,
    },
    /// Update an installed package from its original publisher
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
        #[arg(long = "type", value_name = "TYPE", default_value = "app", value_parser = ["app", "lib"])]
        kind: String,
    },
    /// Remove a package, retaining its data and dependencies
    Remove {
        /// Package short name or canonical publisher/name
        target: String,
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
        #[arg(long = "type", value_name = "TYPE", default_value = "app", value_parser = ["app", "lib"])]
        kind: String,
    },
    /// List installed packages (both types by default)
    List {
        /// Query packages currently loaded by Pishoo
        #[arg(long)]
        loaded: bool,
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
        #[arg(long = "type", value_name = "TYPE", value_parser = ["app", "lib"])]
        kind: Option<String>,
    },
    /// Validate a local signed WEBC through the selected Pishoo service
    Check {
        file: PathBuf,
        #[arg(short, long)]
        id: Option<String>,
        #[arg(long = "type", value_parser = ["app", "lib"], required = true)]
        kind: String,
    },
    /// Show an installed package, including its exact dependencies
    Info {
        /// Package short name or canonical publisher/name
        target: String,
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
        #[arg(long = "type", value_name = "TYPE", default_value = "app", value_parser = ["app", "lib"])]
        kind: String,
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

    let options = Options::parse();

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
        Options::Package { command } => match command {
            PackageCommand::Build {
                path,
                output,
                id,
                no_build,
            } => pack::run(path, output, id, no_build).await?,
            PackageCommand::Publish { file, id } => upload::run(file, id).await?,
            PackageCommand::Install {
                target,
                file,
                id,
                version,
                kind,
            } => {
                if let Some(file) = file {
                    let value = install::local_package(Some(&target), &file, id, &kind).await?;
                    println!("{}", value);
                } else {
                    install::run("install", Some(target), id, version, Some(kind)).await?;
                }
            }
            PackageCommand::Update {
                target,
                id,
                version,
                kind,
            } => install::run("update", Some(target), id, version, Some(kind)).await?,
            PackageCommand::Remove { target, id, kind } => {
                install::run("remove", Some(target), id, None, Some(kind)).await?
            }
            PackageCommand::Info { target, id, kind } => {
                install::run("info", Some(target), id, None, Some(kind)).await?
            }
            PackageCommand::List { id, kind, loaded } => {
                install::run(if loaded { "loaded" } else { "list" }, None, id, None, kind).await?
            }
            PackageCommand::Check { file, id, kind } => {
                println!("{}", install::local_package(None, &file, id, &kind).await?);
            }
        },
        Options::Server { command } => server::run(command).await?,
        Options::Nslookup(options) => genmeta_nslookup::run(options).await?,
        Options::Proxy(options) => genmeta_proxy::run(options).await?,
        Options::Version {} => println!("{}", env!("CARGO_PKG_VERSION")),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Options, PackageCommand, install_process_crypto_provider};

    #[test]
    fn installs_rustls_crypto_provider() {
        install_process_crypto_provider();

        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn launcher_accepts_identity_global_flag() {
        let parsed = Options::try_parse_from(["genmeta", "identity", "--global", "list"]);
        assert!(parsed.is_ok(), "{parsed:?}");
    }

    #[test]
    fn launcher_accepts_identity_alias() {
        let canonical = Options::try_parse_from(["genmeta", "identity", "apply", "alice.smith"])
            .expect("canonical identity command should parse");
        let alias = Options::try_parse_from(["genmeta", "id", "apply", "alice.smith"])
            .expect("id alias should parse");

        assert!(matches!(canonical, Options::Identity(_)));
        assert!(matches!(alias, Options::Identity(_)));
    }

    #[test]
    fn launcher_accepts_scheduled_identity_renewal_for_both_scopes() {
        let user = Options::try_parse_from(["genmeta", "identity", "renew", "--all"]);
        let global = Options::try_parse_from(["genmeta", "identity", "--global", "renew", "--all"]);

        assert!(user.is_ok(), "{user:?}");
        assert!(global.is_ok(), "{global:?}");
    }

    #[test]
    fn launcher_accepts_identity_site_commands() {
        let enable =
            Options::try_parse_from(["genmeta", "identity", "ensite", "--id", "alice.smith"]);
        let disable =
            Options::try_parse_from(["genmeta", "identity", "dissite", "--id", "alice.smith"]);
        let global = Options::try_parse_from([
            "genmeta",
            "identity",
            "--global",
            "ensite",
            "--id",
            "alice.smith",
        ]);

        assert!(enable.is_ok(), "{enable:?}");
        assert!(disable.is_ok(), "{disable:?}");
        assert!(global.is_ok(), "{global:?}");
    }

    #[test]
    fn launcher_help_exposes_identity_alias() {
        let help = Options::command().render_long_help().to_string();
        assert!(help.contains("identity"), "{help}");
        assert!(help.contains("id"), "{help}");
    }

    #[test]
    fn help_and_version_flags_work_at_every_command_level() {
        use clap::error::ErrorKind;

        for command in [
            vec![],
            vec!["identity"],
            vec!["id"],
            vec!["doctor"],
            vec!["access"],
            vec!["curl"],
            vec!["discover"],
            vec!["nslookup"],
            vec!["proxy"],
            vec!["package"],
            vec!["package", "publish"],
            vec!["package", "build"],
            vec!["doctor", "net"],
        ] {
            for (flag, kind) in [
                ("--help", ErrorKind::DisplayHelp),
                ("-h", ErrorKind::DisplayHelp),
                ("--version", ErrorKind::DisplayVersion),
                ("-V", ErrorKind::DisplayVersion),
            ] {
                let mut args = vec!["genmeta"];
                args.extend(command.iter().copied());
                args.push(flag);
                let error = Options::try_parse_from(&args).unwrap_err();
                assert_eq!(error.kind(), kind, "{args:?}: {error}");
            }
        }
        for command in [
            vec!["version"],
            vec!["identity", "version"],
            vec!["doctor", "version"],
        ] {
            assert!(Options::try_parse_from(std::iter::once("genmeta").chain(command)).is_ok());
        }
    }
    #[test]
    fn launcher_rejects_removed_ssh_command() {
        assert!(Options::try_parse_from(["genmeta", "ssh", "alice.pilot"]).is_err());
        assert!(Options::command().find_subcommand("ssh").is_none());
    }

    #[test]
    fn launcher_accepts_pack_defaults_and_explicit_paths() {
        let options = Options::try_parse_from(["genmeta", "package", "build"]).unwrap();
        assert!(
            matches!(options, Options::Package { command: PackageCommand::Build { path, output: None, id: None, no_build: false } } if path == std::path::Path::new("."))
        );
        let options = Options::try_parse_from([
            "genmeta",
            "package",
            "build",
            "project with spaces/wasmer.toml",
            "-o",
            "out file.webc",
            "-i",
            "dev.dhttp.net",
        ])
        .unwrap();
        assert!(
            matches!(options, Options::Package { command: PackageCommand::Build { path, output: Some(output), id: Some(id), no_build: false } }
            if path == std::path::Path::new("project with spaces/wasmer.toml")
                && output == std::path::Path::new("out file.webc") && id == "dev.dhttp.net")
        );
        for arg in ["--force", "--unsigned", "--kind", "--home", "--upload"] {
            assert!(Options::try_parse_from(["genmeta", "package", "build", arg]).is_err());
        }
    }
}
