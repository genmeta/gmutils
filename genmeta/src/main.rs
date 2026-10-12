use clap::Parser;
use snafu::Whatever;

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
    Nslookup(genmeta_nslookup::Options),
    Proxy(genmeta_proxy::Options),
    Version {},
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
        Options::Nslookup(options) => genmeta_nslookup::run(options).await?,
        Options::Proxy(options) => genmeta_proxy::run(options).await?,
        Options::Version {} => println!("{}", env!("CARGO_PKG_VERSION")),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

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
}
