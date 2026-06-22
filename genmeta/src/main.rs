use clap::{Arg, ArgAction, Command as ClapCommand, CommandFactory, FromArgMatches, Parser};
use snafu::Whatever;

#[derive(Parser, Debug, Clone)]
#[command(disable_help_flag = true, disable_version_flag = true)]
enum Options {
    Access(genmeta_access::Options),
    Curl(genmeta_curl::Options),
    Discover(genmeta_discover::Options),
    Doctor {
        #[command(subcommand)]
        options: genmeta_doctor::Options,
    },
    Identity(genmeta_identity::Cli),
    Nslookup(genmeta_nslookup::Options),
    Proxy(genmeta_proxy::Options),
    Ssh(genmeta_ssh::Options),
    Version {},
}

#[derive(snafu::Snafu, Debug)]
enum Error {
    #[snafu(transparent)]
    Access { source: genmeta_access::Error },
    #[snafu(transparent)]
    Curl { source: genmeta_curl::Error },
    #[snafu(transparent)]
    Discover { source: genmeta_discover::Error },
    #[snafu(transparent)]
    Doctor { source: genmeta_doctor::Error },
    #[snafu(transparent)]
    Identity { source: genmeta_identity::Error },
    #[snafu(transparent)]
    Nslookup { source: genmeta_nslookup::Error },
    #[snafu(transparent)]
    Proxy { source: genmeta_proxy::Error },
    #[snafu(transparent)]
    Ssh { source: genmeta_ssh::Error },
    #[snafu(transparent)]
    Whatever { source: Whatever },
}

/// Re-add `--help` (and `--version` when a version is set) to a command and all
/// its descendants. This counteracts the propagation of `disable_help_flag` from
/// launcher-level commands, so that independent subcommands still expose flags.
fn enable_help(mut cmd: ClapCommand) -> ClapCommand {
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|sc| sc.get_name().to_string())
        .collect();
    for name in names {
        cmd = cmd.mut_subcommand(&name, enable_help);
    }
    cmd = cmd.arg(
        Arg::new("help_flag")
            .short('h')
            .long("help")
            .action(ArgAction::HelpLong)
            .help("Print help"),
    );
    if cmd.get_version().is_some() {
        cmd = cmd.arg(
            Arg::new("version_flag")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .help("Print version"),
        );
    }
    cmd
}

/// Apply [`enable_help`] to every non-launcher subcommand of a launcher command.
fn enable_help_for_subcommands(mut cmd: ClapCommand) -> ClapCommand {
    let names: Vec<String> = cmd
        .get_subcommands()
        .filter(|sc| !matches!(sc.get_name(), "version"))
        .map(|sc| sc.get_name().to_string())
        .collect();
    for name in names {
        cmd = cmd.mut_subcommand(&name, enable_help);
    }
    cmd
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

    let mut cmd = Options::command();

    for name in ["access", "curl", "discover", "nslookup", "proxy", "ssh"] {
        cmd = cmd.mut_subcommand(name, enable_help);
    }
    cmd = cmd.mut_subcommand("doctor", enable_help_for_subcommands);
    cmd = cmd.mut_subcommand("identity", enable_help_for_subcommands);

    let matches = cmd.get_matches();
    let options = Options::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    run(options).await.inspect_err(|error| {
        tracing::debug!(?error, "Exit with error");
    })
}

async fn run(options: Options) -> Result<(), Error> {
    match options {
        Options::Access(options) => genmeta_access::run(options).await?,
        Options::Curl(options) => genmeta_curl::run(options).await?,
        Options::Discover(options) => genmeta_discover::run(options).await?,
        Options::Doctor { options } => genmeta_doctor::run(options).await?,
        Options::Identity(options) => genmeta_identity::run(options).await?,
        Options::Nslookup(options) => genmeta_nslookup::run(options).await?,
        Options::Proxy(options) => genmeta_proxy::run(options).await?,
        Options::Ssh(options) => genmeta_ssh::run(options).await?,
        Options::Version {} => println!("{}", env!("CARGO_PKG_VERSION")),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Options, install_process_crypto_provider};

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
}
