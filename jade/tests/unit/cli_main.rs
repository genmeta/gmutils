use clap::{CommandFactory, error::ErrorKind};

use super::*;

#[test]
fn exposes_only_project_commands() {
    let command = Cli::command();
    assert_eq!(
        command
            .get_subcommands()
            .map(|command| command.get_name())
            .collect::<Vec<_>>(),
        ["create", "build", "run", "publish"]
    );
    for args in [
        vec!["jade", "create", "hello"],
        vec!["jade", "build"],
        vec!["jade", "run"],
        vec!["jade", "run", "--fresh"],
        vec!["jade", "publish", "hello.waz"],
    ] {
        assert!(Cli::try_parse_from(args).is_ok());
    }
    for args in [
        vec!["jade", "create", "hello", "--id", "dev.alex.chen"],
        vec!["jade", "run", "--id", "dev.alex.chen"],
        vec!["jade", "build", "--id", "dev.alex.chen"],
        vec!["jade", "publish", "--id", "dev.alex.chen"],
        vec!["jade", "run", "-i", "dev.alex.chen"],
        vec!["jade", "build", "-i", "dev.alex.chen"],
        vec!["jade", "publish", "-i", "dev.alex.chen"],
        vec!["jade", "build", "--no-build"],
        vec!["jade", "run", "--no-watch"],
        vec!["jade", "build", "--manifest-path", "jade.toml"],
        vec!["jade", "developer", "dev.alex.chen", "apply"],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn global_output_flags_and_help_work_at_every_level() {
    for args in [
        vec!["jade", "--json", "--verb", "build"],
        vec!["jade", "build", "--json", "--verb"],
    ] {
        let parsed = Cli::try_parse_from(args).unwrap();
        assert!(parsed.json && parsed.verb);
    }
    for command in [
        None,
        Some("create"),
        Some("build"),
        Some("run"),
        Some("publish"),
    ] {
        for (flag, kind) in [
            ("--help", ErrorKind::DisplayHelp),
            ("--version", ErrorKind::DisplayVersion),
        ] {
            let mut args = vec!["jade"];
            args.extend(command);
            args.push(flag);
            assert_eq!(Cli::try_parse_from(args).unwrap_err().kind(), kind);
        }
    }
}
