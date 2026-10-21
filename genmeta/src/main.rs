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
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
        /// Exact release version (defaults to the latest published version)
        #[arg(long, value_name = "MAJOR.MINOR.PATCH")]
        version: Option<String>,
        /// Select an App (the default)
        #[arg(long, conflicts_with = "lib")]
        app: bool,
        /// Select a Lib
        #[arg(long, conflicts_with = "app")]
        lib: bool,
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
        /// Select an App (the default)
        #[arg(long, conflicts_with = "lib")]
        app: bool,
        /// Select a Lib
        #[arg(long, conflicts_with = "app")]
        lib: bool,
    },
    /// Remove a package, retaining its data and dependencies
    Uninstall {
        /// Package short name or canonical publisher/name
        target: String,
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
        /// Select an App (the default)
        #[arg(long, conflicts_with = "lib")]
        app: bool,
        /// Select a Lib
        #[arg(long, conflicts_with = "app")]
        lib: bool,
    },
    /// List installed packages (both types by default)
    List {
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
        #[arg(long, conflicts_with = "lib")]
        app: bool,
        #[arg(long, conflicts_with = "app")]
        lib: bool,
    },
    /// Show an installed package, including its exact dependencies
    Info {
        /// Package short name or canonical publisher/name
        target: String,
        /// Local identity hosting the packages (defaults to the configured identity)
        #[arg(short, long)]
        id: Option<String>,
        /// Select an App (the default)
        #[arg(long, conflicts_with = "lib")]
        app: bool,
        /// Select a Lib
        #[arg(long, conflicts_with = "app")]
        lib: bool,
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
        Options::Package(command) => match command {
            PackageCommand::Build {
                path,
                output,
                id,
                no_build,
            } => pack::run(path, output, id, no_build).await?,
            PackageCommand::Publish { file, id } => upload::run(file, id).await?,
            PackageCommand::Install {
                target,
                id,
                version,
                app: _,
                lib,
            } => {
                let kind = if lib { "lib" } else { "app" }.to_owned();
                install::run("install", Some(target), id, version, Some(kind)).await?;
            }
            PackageCommand::Update {
                target,
                id,
                version,
                app: _,
                lib,
            } => {
                install::run(
                    "update",
                    Some(target),
                    id,
                    version,
                    Some(if lib { "lib" } else { "app" }.into()),
                )
                .await?
            }
            PackageCommand::Uninstall {
                target,
                id,
                app: _,
                lib,
            } => {
                install::run(
                    "remove",
                    Some(target),
                    id,
                    None,
                    Some(if lib { "lib" } else { "app" }.into()),
                )
                .await?
            }
            PackageCommand::Info {
                target,
                id,
                app: _,
                lib,
            } => {
                install::run(
                    "info",
                    Some(target),
                    id,
                    None,
                    Some(if lib { "lib" } else { "app" }.into()),
                )
                .await?
            }
            PackageCommand::List { id, app, lib } => {
                let kind = if lib {
                    Some("lib".into())
                } else if app {
                    Some("app".into())
                } else {
                    None
                };
                install::run("list", None, id, None, kind).await?
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
    fn launcher_exposes_listen_mount_and_unmount() {
        use super::server::Command;
        for mode in ["internal", "external", "all", "off"] {
            let parsed =
                Options::try_parse_from(["genmeta", "listen", "--id", "alice.smith", mode])
                    .unwrap();
            assert!(
                matches!(parsed, Options::Server(Command::Listen {mode: Some(saved), ..}) if saved == mode)
            );
        }
        assert!(matches!(
            Options::try_parse_from(["genmeta", "listen", "--global", "--id", "alice.smith"])
                .unwrap(),
            Options::Server(Command::Listen {
                mode: None,
                global: true,
                ..
            })
        ));
        assert!(matches!(
            Options::try_parse_from([
                "genmeta",
                "mount",
                "--id",
                "alice.smith",
                "/api",
                "127.0.0.1:8080"
            ])
            .unwrap(),
            Options::Server(Command::Mount { .. })
        ));
        assert!(matches!(
            Options::try_parse_from(["genmeta", "mount"]).unwrap(),
            Options::Server(Command::Mount {
                location: None,
                target: None,
                ..
            })
        ));
        assert!(matches!(
            Options::try_parse_from(["genmeta", "unmount", "/api", "127.0.0.1:8080", "--yes"])
                .unwrap(),
            Options::Server(Command::Unmount { yes: true, .. })
        ));
        for args in [
            vec!["listen"],
            vec!["listen", "--id", "alice.smith", "auto"],
            vec!["listen", "--id", "alice.smith", "loopback"],
            vec!["listen", "--id", "alice.smith", "list"],
            vec!["unlisten", "--id", "alice.smith"],
            vec!["forward"],
            vec!["mount", "/api"],
            vec!["unmount", "/api"],
        ] {
            assert!(Options::try_parse_from(std::iter::once("genmeta").chain(args)).is_err());
        }
        let command = Options::command();
        for name in ["listen", "mount", "unmount"] {
            assert!(command.find_subcommand(name).is_some());
        }
        for name in ["server", "unlisten", "forward"] {
            assert!(command.find_subcommand(name).is_none());
        }
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
            vec!["publish"],
            vec!["build"],
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
        let options = Options::try_parse_from(["genmeta", "build"]).unwrap();
        assert!(
            matches!(options, Options::Package(PackageCommand::Build { path, output: None, id: None, no_build: false }) if path == std::path::Path::new("."))
        );
        let options = Options::try_parse_from([
            "genmeta",
            "build",
            "project with spaces/wasmer.toml",
            "-o",
            "out file.webc",
            "-i",
            "dev.dhttp.net",
        ])
        .unwrap();
        assert!(
            matches!(options, Options::Package(PackageCommand::Build { path, output: Some(output), id: Some(id), no_build: false })
            if path == std::path::Path::new("project with spaces/wasmer.toml")
                && output == std::path::Path::new("out file.webc") && id == "dev.dhttp.net")
        );
        for arg in ["--force", "--unsigned", "--kind", "--home", "--upload"] {
            assert!(Options::try_parse_from(["genmeta", "build", arg]).is_err());
        }
    }
}
