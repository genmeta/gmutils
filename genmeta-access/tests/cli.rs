use std::path::PathBuf;

use clap::Parser;
use firewall_db::{identity::Name, identity_access_db_path, init_access_database_for};
use genmeta_access::{Options, run_for_home};
use genmeta_home::GenmetaHome;

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

    fn home(&self) -> GenmetaHome {
        GenmetaHome::new(self.path.clone())
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

async fn run_cli(home: &GenmetaHome, command: &str) -> String {
    let mut args = vec!["access"];
    args.extend(command.split_whitespace());
    let options = Options::parse_from(&args);
    run_for_home(home, options)
        .await
        .unwrap_or_else(|error| panic!("{}", snafu::Report::from_error(error)))
}

#[tokio::test]
async fn cli_identity_init_creates_store() {
    let test_home = TestHome::new("cli-init");
    let home = test_home.home();
    let identity: Name<'static> = "alice.pilot".parse().unwrap();

    run_cli(&home, "init alice.pilot").await;

    let identity_home = home.identity_home(identity.borrow());
    assert!(identity_access_db_path(&identity_home).is_file());
}

#[tokio::test]
async fn cli_identity_command_fails_without_store() {
    let test_home = TestHome::new("cli-missing-store");
    let home = test_home.home();

    let error = run_for_home(
        &home,
        Options::parse_from(["access", "alice.pilot", "rulesets", "list"]),
    )
    .await
    .unwrap_err();

    let rendered = format!("{}", snafu::Report::from_error(error));
    assert!(rendered.contains("access store does not exist"));
}

#[tokio::test]
async fn invalid_identity_input_error() {
    let error = Options::try_parse_from(["access", "invalid identity", "rulesets", "list"])
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("name contains invalid characters")
    );
}

#[tokio::test]
async fn cli_ruleset_crud_flow() {
    let test_home = TestHome::new("cli-ruleset-crud");
    let home = test_home.home();
    let identity: Name<'static> = "alice.pilot".parse().unwrap();
    let identity_home = home.identity_home(identity.borrow());
    init_access_database_for(&identity_home).await.unwrap();

    run_cli(&home, "alice.pilot ruleset /api deny *?").await;
    let listed = run_cli(&home, "alice.pilot ruleset /api rules list").await;
    assert!(listed.contains("/api"));
    assert!(listed.contains("deny *?"));

    let all = run_cli(&home, "alice.pilot rulesets list --wide").await;
    assert!(all.contains("/api"));

    run_cli(&home, "alice.pilot ruleset /api rules remove 0").await;
    let after_remove = run_cli(&home, "alice.pilot ruleset /api rules list").await;
    assert!(after_remove.contains("- /api"));
    assert!(!after_remove.contains("deny *?"));
}

#[tokio::test]
async fn end_to_end_identity_store_isolation() {
    let test_home = TestHome::new("cli-isolation");
    let home = test_home.home();

    run_cli(&home, "init alice.pilot").await;
    run_cli(&home, "init bob.pilot").await;
    run_cli(&home, "alice.pilot ruleset /api allow *?").await;

    let alice_rules = run_cli(&home, "alice.pilot rulesets list --wide").await;
    let bob_rules = run_cli(&home, "bob.pilot rulesets list --wide").await;

    assert!(alice_rules.contains("/api"));
    assert!(!bob_rules.contains("/api"));
}
