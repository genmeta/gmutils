use std::io::IsTerminal;

use clap::Parser;
use snafu::Whatever;

mod display;
mod install;
mod jade;
mod pack;
mod server;

#[cfg(test)]
#[path = "../tests/support/upload_credentials.rs"]
mod test_credentials;
mod upload;

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
    /// Create projects, build signed packages, and publish releases
    #[command(version)]
    Jade {
        #[command(subcommand)]
        command: jade::Command,
    },
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
        Options::Jade { .. } | Options::Package(_) | Options::Server(_) | Options::Version {}
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
        Options::Jade { command } => jade::run(command).await?,
        Options::Package(command) => match command {
            PackageCommand::Install {
                target,
                list,
                info,
                id,
                version,
            } => {
                if list {
                    install::run("list", None, id, None).await?;
                } else if let Some(name) = info {
                    install::run("info", Some(name), id, None).await?;
                } else {
                    install::run("install", target, id, version).await?;
                }
            }
            PackageCommand::Update {
                target,
                id,
                version,
            } => install::run("update", Some(target), id, version).await?,
            PackageCommand::Uninstall { target, id } => {
                install::run("remove", Some(target), id, None).await?
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

    use super::{Cli, Options, install_process_crypto_provider, jade};

    #[test]
    fn debug_flag_is_global_and_propagates_to_nested_commands() {
        for command in [
            vec!["access", "list"],
            vec!["curl", "https://example.com/"],
            vec!["discover"],
            vec!["doctor", "net"],
            vec!["identity", "list"],
            vec!["id", "apply", "alice.smith"],
            vec!["nslookup", "localhost", "system"],
            vec!["proxy"],
            vec!["install", "--list"],
            vec!["update", "workspace"],
            vec!["uninstall", "workspace"],
            vec!["jade", "create", "hello", "--id", "alice~"],
            vec!["jade", "build"],
            vec!["jade", "publish", "workspace.waz"],
            vec!["listen", "--id", "alice.smith"],
            vec!["mount"],
            vec!["unmount", "/api", "127.0.0.1:8080"],
            vec!["version"],
        ] {
            let default =
                Cli::try_parse_from(std::iter::once("genmeta").chain(command.iter().copied()))
                    .unwrap();
            assert!(!default.verb, "{command:?}");
            for args in [
                [vec!["genmeta", "--verb"], command.clone()].concat(),
                [vec!["genmeta"], command.clone(), vec!["--verb"]].concat(),
            ] {
                let parsed = Cli::try_parse_from(&args).unwrap();
                assert!(parsed.verb, "{args:?}");
                match parsed.options {
                    Options::Identity(options) => assert!(options.verb, "{args:?}"),
                    Options::Doctor {
                        options: genmeta_doctor::Options::Net(options),
                    } => assert!(options.verb, "{args:?}"),
                    _ => {}
                }
            }
        }
    }

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
            vec!["jade", "publish"],
            vec!["jade", "build"],
            vec!["jade", "create"],
            vec!["jade"],
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
    fn launcher_accepts_jade_build_defaults_and_explicit_paths() {
        let options = Options::try_parse_from(["genmeta", "jade", "build"]).unwrap();
        assert!(
            matches!(options, Options::Jade { command: jade::Command::Build { path, output: None, id: None, no_build: false } } if path == std::path::Path::new("."))
        );
        let options = Options::try_parse_from([
            "genmeta",
            "jade",
            "build",
            "project with spaces/wasmer.toml",
            "-o",
            "out file.waz",
            "-i",
            "dev.dhttp.net",
        ])
        .unwrap();
        assert!(
            matches!(options, Options::Jade { command: jade::Command::Build { path, output: Some(output), id: Some(id), no_build: false } }
            if path == std::path::Path::new("project with spaces/wasmer.toml")
                && output == std::path::Path::new("out file.waz") && id == "dev.dhttp.net")
        );
        for arg in ["--force", "--unsigned", "--kind", "--home", "--upload"] {
            assert!(Options::try_parse_from(["genmeta", "jade", "build", arg]).is_err());
        }
    }

    #[test]
    fn launcher_groups_project_commands_under_jade() {
        let command = Options::command();
        let jade = command.find_subcommand("jade").unwrap();
        for name in ["create", "build", "publish"] {
            assert!(jade.find_subcommand(name).is_some());
            assert!(command.find_subcommand(name).is_none());
            assert!(Options::try_parse_from(["genmeta", name]).is_err());
        }
        for name in ["install", "update", "uninstall"] {
            assert!(command.find_subcommand(name).is_some());
            assert!(jade.find_subcommand(name).is_none());
        }
        assert!(Options::try_parse_from(["genmeta", "jade"]).is_err());
        assert!(Options::try_parse_from(["genmeta", "jade", "create", "hello"]).is_err());
        assert!(matches!(
            Options::try_parse_from(["genmeta", "jade", "build", "--no-build"]).unwrap(),
            Options::Jade {
                command: jade::Command::Build { no_build: true, .. }
            }
        ));
    }
}
