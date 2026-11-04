use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{CommandFactory, Parser};
use dhttp_home::{DhttpHome, HomeScope};
use dhttp_identity::{
    certificate::CertificateChainKey,
    identity::Identity,
    name::{DhttpName, Name},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::{Apply, Cli, Default, Error, Info, Options, cert_server_base_url};
use crate::DHTTP_CA_SERVICE;

fn unique_test_home_path(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "genmeta-identity-cli-{test_name}-{}-{nonce}",
        std::process::id()
    ))
}

#[test]
fn cert_server_base_url_uses_compile_time_bootstrap_url() {
    let url = cert_server_base_url();
    assert_eq!(url, DHTTP_CA_SERVICE);
}

#[test]
fn removed_public_options_do_not_parse_or_appear_in_help() {
    let help = Cli::command().render_long_help().to_string();
    for removed in [
        "--auth",
        "--send-code",
        "--replace-local",
        "--allow-nonready",
        "--register-if-missing",
    ] {
        assert!(
            !help.contains(removed),
            "{removed} leaked into help:\n{help}"
        );
    }

    for argv in [
        vec!["genmeta", "apply", "alice.smith", "--auth", "email"],
        vec!["genmeta", "apply", "alice.smith", "--send-code"],
        vec!["genmeta", "apply", "alice.smith", "--replace-local"],
        vec!["genmeta", "default", "alice.smith", "--allow-nonready"],
    ] {
        assert!(Options::try_parse_from(argv).is_err());
    }
}

#[test]
fn force_is_scoped_to_apply_renew_and_named_default() {
    assert!(Options::try_parse_from(["genmeta", "apply", "alice.smith", "--force"]).is_ok());
    assert!(Options::try_parse_from(["genmeta", "renew", "alice.smith", "-f"]).is_ok());
    assert!(Options::try_parse_from(["genmeta", "default", "alice.smith", "--force"]).is_ok());
    assert!(Options::try_parse_from(["genmeta", "default", "-v", "--force"]).is_err());
}

#[test]
fn hidden_verify_code_still_parses_without_help_exposure() {
    let help = Apply::command().render_long_help().to_string();
    assert!(!help.contains("--verify-code"), "{help}");
    assert!(
        Options::try_parse_from([
            "genmeta",
            "apply",
            "alice.smith",
            "--email",
            "alice@example.test",
            "--verify-code",
            "000000",
        ])
        .is_ok()
    );
}

#[test]
fn apply_rejects_removed_kind_option() {
    let help = Apply::command().render_long_help().to_string();
    assert!(!help.contains("--kind"), "{help}");
    for value in ["primary", "secondary"] {
        let error = Options::try_parse_from(["genmeta", "apply", "alice.smith", "--kind", value])
            .unwrap_err();
        assert!(error.to_string().contains("--kind"), "{error}");
    }
}

#[test]
fn identity_commands_do_not_expose_server_configuration() {
    for command in ["ensite", "dissite", "listen"] {
        assert!(Options::try_parse_from(["genmeta", command, "--id", "alice.smith"]).is_err());
        assert!(Options::command().find_subcommand(command).is_none());
    }
}

fn local_identity_with_dhttp_ski() -> Identity {
    Identity::new(
        Name::try_from("client.example.com.dhttp.net").unwrap(),
        vec![CertificateDer::from(
            include_bytes!("../fixtures/valid.der").to_vec(),
        )],
        PrivateKeyDer::Pkcs8(b"dummy".to_vec().into()),
    )
}

fn dummy_cert_server() -> crate::cert_server::CertServer {
    _ = rustls::crypto::ring::default_provider().install_default();
    crate::cert_server::CertServer::new("https://license.genmeta.net").unwrap()
}

#[test]
fn certificate_chain_key_from_identity_reads_dhttp_ski() {
    let identity = local_identity_with_dhttp_ski();
    let chain_key = certificate_chain_key_from_identity(&identity)
        .unwrap()
        .unwrap();

    assert_eq!(chain_key.usage().kind_flag(), "0");
    assert_eq!(chain_key.sequence().get(), 0);
}

#[test]
fn apply_does_not_expose_register_if_missing() {
    let help = Apply::command().render_long_help().to_string();
    assert!(!help.contains("register-if-missing"), "{help}");

    let error = Options::try_parse_from([
        "genmeta",
        "apply",
        "phone.alice.smith",
        "--register-if-missing",
    ])
    .unwrap_err();
    assert!(error.to_string().contains("unexpected argument"));
}

#[test]
fn create_subcommand_aliases_apply() {
    assert!(Options::try_parse_from(["genmeta", "create", "alice.smith"]).is_ok());
}

#[test]
fn global_flag_accepts_short_alias() {
    assert!(Cli::try_parse_from(["genmeta", "-g", "list"]).is_ok());
}

#[test]
fn renew_uses_optional_positional_identity_without_default_flag() {
    assert!(Options::try_parse_from(["genmeta", "renew"]).is_ok());
    assert!(Options::try_parse_from(["genmeta", "renew", "alice.smith"]).is_ok());
    assert!(Options::try_parse_from(["genmeta", "renew", "--all"]).is_ok());
    assert!(Options::try_parse_from(["genmeta", "renew", "alice.smith", "--all"]).is_err());
    assert!(Options::try_parse_from(["genmeta", "renew", "--default"]).is_err());
}

#[test]
fn default_verbose_is_query_only() {
    assert!(Options::try_parse_from(["genmeta", "default", "-v"]).is_ok());
    assert!(Options::try_parse_from(["genmeta", "default", "--verbose"]).is_ok());
    assert!(Options::try_parse_from(["genmeta", "default", "alice.smith", "-v"]).is_err());
}

#[test]
fn helper_style_read_and_write_subcommands_are_rejected() {
    for command in ["read", "write"] {
        let error = Options::try_parse_from(["genmeta", command]).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains(command), "{rendered}");
    }
}

#[test]
fn renew_rejects_kind_and_sequence_flags() {
    for (flag, value) in [("--kind", "primary"), ("--sequence", "1")] {
        let error =
            Options::try_parse_from(["genmeta", "renew", "alice.smith", flag, value]).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains(flag), "{rendered}");
    }
}

#[test]
fn apply_rejects_sequence_flag() {
    let error = Options::try_parse_from(["genmeta", "apply", "alice.smith", "--sequence", "1"])
        .unwrap_err();
    let rendered = error.to_string();
    assert!(rendered.contains("--sequence"), "{rendered}");
}

#[test]
fn apply_and_renew_reject_default_flag() {
    let apply_error = Options::try_parse_from(["genmeta", "apply", "--default"]).unwrap_err();
    assert!(apply_error.to_string().contains("--default"));

    assert!(Options::try_parse_from(["genmeta", "renew", "--default"]).is_err());
}

#[tokio::test]
async fn save_settings_creates_missing_home_directory() {
    let home_path = unique_test_home_path("save-settings");
    let dhttp_home = DhttpHome::new(home_path.clone());
    let mut settings = dhttp_home.new_settings();
    settings
        .settings_mut()
        .set_default_identity_name(DhttpName::try_from("alice.smith").unwrap());

    super::save_settings(&settings).await.unwrap();

    assert!(home_path.join("settings.toml").exists());
}

#[tokio::test]
async fn info_reports_unsaved_identity_with_business_message() {
    let home_path = unique_test_home_path("info-unsaved");
    let dhttp_home = DhttpHome::new(home_path);
    let command = Info {
        name: Some("alice.smith".to_string()),
    };

    let error = command
        .run(&dhttp_home, &dummy_cert_server())
        .await
        .unwrap_err();
    let rendered = error.to_string();

    assert!(
        rendered.contains("alice.smith is not saved here"),
        "{rendered}"
    );
    assert!(
        rendered.contains("apply alice.smith here first"),
        "{rendered}"
    );
}

#[tokio::test]
async fn default_reports_unsaved_identity_non_interactively() {
    for force in [false, true] {
        let home_path = unique_test_home_path("default-unsaved");
        let dhttp_home = DhttpHome::new(home_path);
        let command = Default {
            name: Some("alice.smith".to_string()),
            verbose: false,
            force,
        };

        let error = command
            .run(&dhttp_home, HomeScope::User, &dummy_cert_server())
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Failed to set default identity: alice.smith not found!"
        );
    }
}

#[tokio::test]
async fn default_named_saved_identity_sets_default_non_interactively() {
    let home_path = unique_test_home_path("default-saved-noninteractive");
    let dhttp_home = DhttpHome::new(home_path.clone());
    let name = DhttpName::try_from("alice.smith").unwrap();
    let profile = dhttp_home
        .identity_profile((name.borrow()).as_full())
        .expect("validated identity name");
    tokio::fs::create_dir_all(profile.path()).await.unwrap();

    let command = Default {
        name: Some("alice.smith".to_string()),
        verbose: false,
        force: true,
    };

    command
        .run(&dhttp_home, HomeScope::User, &dummy_cert_server())
        .await
        .unwrap();

    let settings = dhttp_home.load_settings().await.unwrap();
    assert_eq!(
        settings
            .settings()
            .default_identity_name()
            .map(|name| name.as_partial()),
        Some("alice.smith")
    );

    tokio::fs::remove_dir_all(home_path).await.unwrap();
}

#[test]
fn cli_accepts_global_before_and_after_subcommand() {
    let before = Cli::try_parse_from(["genmeta", "--global", "list"]).unwrap();
    let after = Cli::try_parse_from(["genmeta", "list", "--global"]).unwrap();

    assert_eq!(before.home_scope(), dhttp_home::HomeScope::Global);
    assert_eq!(after.home_scope(), dhttp_home::HomeScope::Global);
}

#[test]
fn cli_accepts_scheduled_all_renewal_for_both_scopes() {
    let user = Cli::try_parse_from(["genmeta-identity", "renew", "--all"]);
    let global = Cli::try_parse_from(["genmeta-identity", "--global", "renew", "--all"]);

    assert!(user.is_ok(), "{user:?}");
    assert!(global.is_ok(), "{global:?}");
}

#[test]
fn write_commands_are_marked_for_global_warning() {
    for argv in [
        ["genmeta", "apply", "alice.smith"].as_slice(),
        ["genmeta", "renew", "alice.smith"].as_slice(),
        ["genmeta", "default", "alice.smith"].as_slice(),
    ] {
        let cli = Cli::try_parse_from(argv).unwrap();
        assert!(cli.options.writes_home());
    }

    let info = Cli::try_parse_from(["genmeta", "info", "alice.smith"]).unwrap();
    assert!(!info.options.writes_home());
}

fn certificate_chain_key_from_identity(
    identity: &dhttp_identity::identity::Identity,
) -> Result<Option<CertificateChainKey>, Error> {
    match identity.dhttp_subject_key_identifier() {
        Ok(ski) => Ok(Some(ski.chain().clone())),
        Err(_) => Ok(None),
    }
}
