use std::path::PathBuf;

use clap::Parser;
use dhttp_home::DhttpHome;
use firewall_db::{identity::Name, identity_access_db_path};
use genmeta_access::{Options, run_for_home};

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
    let options = Options::parse_from(&args);
    run_for_home(home, options)
        .await
        .unwrap_or_else(|error| panic!("{}", snafu::Report::from_error(error)))
}

#[tokio::test]
async fn auto_init_creates_store() {
    let test_home = TestHome::new("auto-init");
    let home = test_home.home();
    let identity: Name<'static> = "alice.pilot".parse().unwrap();
    let identity_home = home.identity_home(identity.borrow());

    assert!(!identity_access_db_path(&identity_home).is_file());
    run_cli(&home, "alice.pilot rulesets list").await;
    assert!(identity_access_db_path(&identity_home).is_file());
}

#[tokio::test]
async fn invalid_identity_input_error() {
    let error =
        Options::try_parse_from(["access", "invalid identity", "rulesets", "list"]).unwrap_err();
    let error = error.to_string();
    assert!(
        error.contains("name contains invalid characters")
            || error.contains("name is missing required suffix")
    );
}

#[tokio::test]
async fn cli_ruleset_crud_flow() {
    let test_home = TestHome::new("cli-ruleset-crud");
    let home = test_home.home();
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

    run_cli(&home, "alice.pilot ruleset /api allow *?").await;

    let alice_rules = run_cli(&home, "alice.pilot rulesets list --wide").await;
    let bob_rules = run_cli(&home, "bob.pilot rulesets list --wide").await;

    assert!(alice_rules.contains("/api"));
    assert!(!bob_rules.contains("/api"));
}
