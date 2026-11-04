use clap::{CommandFactory, Parser};

use super::{Cli, Options, install_process_crypto_provider};

#[test]
fn identity_developer_entry_points_are_removed() {
    for identity in ["identity", "id"] {
        for args in [
            vec!["genmeta", identity, "developer", "dev.alex.chen", "apply"],
            vec!["genmeta", identity, "apply", "dev.alex.chen", "--developer"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }
    let mut command = Cli::command();
    let identity = command.find_subcommand_mut("identity").unwrap();
    assert!(
        !identity
            .render_long_help()
            .to_string()
            .contains("developer")
    );
    let apply = identity.find_subcommand_mut("apply").unwrap();
    assert!(!apply.render_long_help().to_string().contains("--developer"));
}

#[test]
fn package_list_verbose_is_separate_from_debug_logging() {
    for flag in ["--verbose", "-v"] {
        let parsed = Cli::try_parse_from(["genmeta", "install", "--list", flag]).unwrap();
        assert!(!parsed.verb);
        assert!(matches!(
            parsed.options,
            Options::Package(super::PackageCommand::Install {
                list: true,
                verbose: true,
                ..
            })
        ));
        assert!(Cli::try_parse_from(["genmeta", "install", "workspace", flag]).is_err());
    }
    assert!(Cli::try_parse_from(["genmeta", "install", "--list", "--verbe"]).is_err());
}

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
        vec!["listen", "--id", "alice.smith"],
        vec!["mount"],
        vec!["unmount", "/api", "127.0.0.1:8080"],
        vec!["version"],
    ] {
        let default =
            Cli::try_parse_from(std::iter::once("genmeta").chain(command.iter().copied())).unwrap();
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
            Options::try_parse_from(["genmeta", "listen", "--id", "alice.smith", mode]).unwrap();
        assert!(
            matches!(parsed, Options::Server(Command::Listen {mode: Some(saved), ..}) if saved == mode)
        );
    }
    assert!(matches!(
        Options::try_parse_from(["genmeta", "listen", "--global", "--id", "alice.smith"]).unwrap(),
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
        Options::try_parse_from(["genmeta", "unmount", "/api", "127.0.0.1:8080", "--yes"]).unwrap(),
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
fn launcher_keeps_project_commands_in_the_standalone_jade_binary() {
    let command = Options::command();
    for name in ["jade", "create", "build", "publish"] {
        assert!(command.find_subcommand(name).is_none());
        assert!(Options::try_parse_from(["genmeta", name]).is_err());
    }
    for name in ["install", "update", "uninstall"] {
        assert!(command.find_subcommand(name).is_some());
    }
}
