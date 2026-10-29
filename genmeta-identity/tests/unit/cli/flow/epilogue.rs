use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use dhttp_home::DhttpHome;
use dhttp_identity::name::DhttpName;
use tokio::fs;

use super::{DefaultSuggestion, suggest_default_change};

fn unique_test_home_path(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "genmeta-identity-epilogue-{test_name}-{}-{nonce}",
        std::process::id()
    ))
}

#[test]
fn suggestion_defaults_and_help_match_current_default_state() {
    assert_eq!(
        suggest_default_change("alice.smith", None),
        Some(DefaultSuggestion {
            question: "Set this name(alice.smith) as default?".to_string(),
            help: "current: none".to_string(),
            default: true,
        })
    );
    assert_eq!(
        suggest_default_change("alice.smith", Some("meng.lin")),
        Some(DefaultSuggestion {
            question: "Set this name(alice.smith) as default?".to_string(),
            help: "current: meng.lin".to_string(),
            default: false,
        })
    );
    assert_eq!(
        suggest_default_change("alice.smith", Some("alice.smith")),
        None
    );
}

#[tokio::test]
async fn non_interactive_lifecycle_epilogue_keeps_default_unset_when_none_exists() {
    let home_path = unique_test_home_path("keeps-default-unset");
    let dhttp_home = DhttpHome::new(home_path.clone());
    let name = DhttpName::try_from("alice.smith").unwrap();
    let profile = dhttp_home
        .identity_profile((name.borrow()).as_full())
        .expect("validated identity name");
    fs::create_dir_all(profile.ssl_dir()).await.unwrap();

    super::run_lifecycle_epilogue(&dhttp_home, name.borrow(), false)
        .await
        .unwrap();

    assert!(
        super::current_default_name(&dhttp_home)
            .await
            .unwrap()
            .is_none()
    );

    fs::remove_dir_all(home_path).await.unwrap();
}
