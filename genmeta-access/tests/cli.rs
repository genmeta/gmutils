use std::path::PathBuf;

use clap::{CommandFactory, Parser};
use dhttp::{
    access::db::{identity::Name, identity_access_db_path},
    home::{DhttpHome, identity::settings::SaveDhttpSettingsError},
};
use genmeta_access::{Options, run_for_home};
use snafu::Report;

struct TestHome {
    path: PathBuf,
}

impl TestHome {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "genmeta-access-tests-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn home(&self) -> DhttpHome {
        DhttpHome::new(self.path.clone())
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

async fn run_cli(home: &DhttpHome, command: &str) -> String {
    let mut args = vec!["access"];
    args.extend(command.split_whitespace());
    let options = Options::try_parse_from(&args).unwrap();
    run_for_home(home, options)
        .await
        .unwrap_or_else(|error| panic!("{}", Report::from_error(error)))
}

async fn run_cli_args(home: &DhttpHome, command: &[&str]) -> String {
    let mut args = vec!["access"];
    args.extend(command.iter().copied());
    let options = Options::try_parse_from(&args).unwrap();
    run_for_home(home, options)
        .await
        .unwrap_or_else(|error| panic!("{}", Report::from_error(error)))
}

async fn try_run_cli(home: &DhttpHome, command: &str) -> Result<String, genmeta_access::Error> {
    let mut args = vec!["access"];
    args.extend(command.split_whitespace());
    let options = Options::try_parse_from(&args).unwrap();
    run_for_home(home, options).await
}

async fn try_run_cli_args(
    home: &DhttpHome,
    command: &[&str],
) -> Result<String, genmeta_access::Error> {
    let mut args = vec!["access"];
    args.extend(command.iter().copied());
    let options = Options::try_parse_from(&args).unwrap();
    run_for_home(home, options).await
}

async fn set_default_identity(
    home: &DhttpHome,
    identity: &str,
) -> Result<(), SaveDhttpSettingsError> {
    let identity: Name<'static> = identity.parse().unwrap();
    let mut settings = home.new_settings();
    settings.settings_mut().set_default_identity_name(identity);
    settings.save().await
}

#[tokio::test]
async fn inline_default_identity_auto_init_creates_store() {
    let test_home = TestHome::new("auto-init");
    let home = test_home.home();
    let identity: Name<'static> = "alice.pilot".parse().unwrap();
    let identity_profile = home.identity_profile(identity.borrow());

    assert!(!identity_access_db_path(&identity_profile).is_file());
    set_default_identity(&home, "alice.pilot").await.unwrap();
    run_cli(&home, "list").await;
    assert!(identity_access_db_path(&identity_profile).is_file());
}

#[tokio::test]
async fn invalid_identity_input_error() {
    let error =
        Options::try_parse_from(["access", "--identity", "invalid identity", "list"]).unwrap_err();
    let error = error.to_string();
    assert!(
        error.contains("name contains invalid characters")
            || error.contains("name is missing required suffix")
    );
}

#[tokio::test]
async fn inline_path_crud_flow() {
    let test_home = TestHome::new("cli-path-crud");
    let home = test_home.home();
    set_default_identity(&home, "alice.pilot").await.unwrap();

    run_cli(&home, "/api deny *?").await;
    let listed = run_cli(&home, "/api list").await;
    assert!(listed.contains("/api"));
    assert!(listed.contains("deny *?"));

    let all = run_cli(&home, "list --wide").await;
    assert!(all.contains("/api"));

    run_cli(&home, "/api remove 0").await;
    let after_remove = run_cli(&home, "/api list").await;
    assert!(after_remove.contains("- /api"));
    assert!(!after_remove.contains("deny *?"));
}

#[tokio::test]
async fn inline_explicit_identity_overrides_default_identity() {
    let test_home = TestHome::new("cli-isolation");
    let home = test_home.home();
    set_default_identity(&home, "alice.pilot").await.unwrap();

    run_cli(&home, "--identity bob.pilot /api allow *?").await;

    let alice_rules = run_cli(&home, "list --wide").await;
    let bob_rules = run_cli(&home, "--identity bob.pilot list --wide").await;

    assert!(!alice_rules.contains("/api"));
    assert!(bob_rules.contains("/api"));
}

#[tokio::test]
async fn inline_remove_path_flow() {
    let test_home = TestHome::new("remove-path");
    let home = test_home.home();
    set_default_identity(&home, "alice.pilot").await.unwrap();

    run_cli(&home, "/api allow *?").await;
    assert!(run_cli(&home, "list --wide").await.contains("/api"));

    run_cli(&home, "remove /api").await;

    assert!(!run_cli(&home, "list --wide").await.contains("/api"));
}

#[tokio::test]
async fn inline_remove_path_all_flow() {
    let test_home = TestHome::new("remove-path-all");
    let home = test_home.home();
    set_default_identity(&home, "alice.pilot").await.unwrap();

    run_cli(&home, "/api allow *?").await;
    assert!(run_cli(&home, "list --wide").await.contains("/api"));

    run_cli(&home, "/api remove --all").await;

    assert!(!run_cli(&home, "list --wide").await.contains("/api"));
}

#[tokio::test]
async fn inline_expr_preserves_quoted_and_hyphen_prefixed_values() {
    let test_home = TestHome::new("quoted-expr");
    let home = test_home.home();
    set_default_identity(&home, "alice.pilot").await.unwrap();

    run_cli_args(
        &home,
        &["/quoted", "allow", "*?", "with", "method", "\"not\""],
    )
    .await;
    run_cli_args(&home, &["/quoted", "deny", "--bot"]).await;

    let listed = run_cli_args(&home, &["/quoted", "list"]).await;
    assert!(listed.contains(r#"allow *? with method "not""#));
    assert!(listed.contains("deny --bot"));
}

#[tokio::test]
async fn inline_path_preserves_shell_quoted_pattern_with_spaces() {
    let test_home = TestHome::new("quoted-path");
    let home = test_home.home();
    set_default_identity(&home, "alice.pilot").await.unwrap();

    let pattern = "~ ^/api v[0-9]+$";
    run_cli_args(&home, &[pattern, "allow", r#"*? with method "not""#]).await;

    let listed = run_cli_args(&home, &[pattern, "list"]).await;
    assert!(listed.contains(pattern));
    assert!(listed.contains(r#"allow *? with method "not""#));
}

#[tokio::test]
async fn inline_path_operation_errors_use_clap_style() {
    let test_home = TestHome::new("path-clap-error");
    let home = test_home.home();

    let error = try_run_cli_args(&home, &["/api", "remove", "--all", "0"])
        .await
        .unwrap_err();
    let rendered = Report::from_error(error).to_string();

    assert!(rendered.contains("cannot be used with"));
    assert!(rendered.contains("Usage:"));
}

#[tokio::test]
async fn inline_path_operation_help_is_rendered_as_output() {
    let test_home = TestHome::new("path-help");
    let home = test_home.home();

    let output = run_cli_args(&home, &["/api", "allow", "--help"]).await;

    assert!(output.contains("Usage:"));
    assert!(output.contains("<EXPR>"));
}

#[tokio::test]
async fn missing_default_identity_is_actionable() {
    let test_home = TestHome::new("missing-default");
    let home = test_home.home();

    let error = try_run_cli(&home, "list").await.unwrap_err();
    let rendered = Report::from_error(error).to_string();

    assert!(rendered.contains("no default identity configured"));
    assert!(rendered.contains("genmeta identity default <name>"));
}

#[test]
fn help_output_shows_inline_usage() {
    let mut help = Vec::new();
    Options::command().write_long_help(&mut help).unwrap();
    let help = String::from_utf8(help).unwrap();

    assert!(help.contains("genmeta access [OPTIONS] <path> <operation>"));
    assert!(help.contains("genmeta access \"/\" allow luffy.pilot"));
}

#[test]
fn global_flag_parses_and_is_described_in_help() {
    assert!(Options::try_parse_from(["access", "--global", "list"]).is_ok());

    let mut help = Vec::new();
    Options::command().write_long_help(&mut help).unwrap();
    let help = String::from_utf8(help).unwrap();

    assert!(help.contains("--global"));
    assert!(help.contains("global dhttp home"));
}

#[tokio::test]
async fn bare_word_is_rejected_as_location_pattern() {
    let test_home = TestHome::new("bare-word");
    let home = test_home.home();
    set_default_identity(&home, "alice.pilot").await.unwrap();

    let error = try_run_cli(&home, "banana allow *?").await.unwrap_err();
    let rendered = Report::from_error(error).to_string();

    assert!(rendered.contains("invalid value 'banana' for '<PATTERN>'"));
    assert!(rendered.contains("expected common pattern"));
}
