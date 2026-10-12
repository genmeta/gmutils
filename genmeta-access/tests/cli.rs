use clap::{CommandFactory, Parser};
use dhttp_home::DhttpHome;
use genmeta_access::{Options, run_for_home};

#[test]
fn help_describes_authenticated_api_policy_management() {
    let help = Options::command().render_long_help().to_string();
    assert!(help.contains("authenticated DHTTP"));
    assert!(help.contains("--global"));
    assert!(help.contains("group@issuer"));
    assert!(help.contains("review"));
    assert!(!help.contains("rule ID"));
    assert!(!help.contains("--server"));
    assert!(Options::try_parse_from(["access", "--id", "alice.pilot", "list"]).is_ok());
    assert!(Options::try_parse_from(["access", "--server", "alice.pilot~", "list"]).is_err());
}

#[tokio::test]
async fn help_and_parse_errors_do_not_load_credentials_or_touch_database() {
    let temp = tempfile::tempdir().unwrap();
    let home = DhttpHome::new(temp.path().to_owned());
    let help = run_for_home(
        &home,
        Options::try_parse_from(["access", "/api", "review", "--help"]).unwrap(),
    )
    .await
    .unwrap();
    assert!(help.contains("<GRANTEE>"));
    assert!(help.contains("--method"));
    for args in [
        vec!["/api", "allow", "*?", "with", "method", "GET"],
        vec!["~ ^/api", "allow", "*?"],
        vec!["/api", "allow", "“*?”"],
        vec!["/api", "allow", "*?", "--method", "get"],
        vec!["/api", "remove", "--all", "*?"],
    ] {
        let options =
            Options::try_parse_from(std::iter::once("access").chain(args.iter().copied())).unwrap();
        assert!(
            matches!(
                run_for_home(&home, options).await,
                Err(genmeta_access::Error::ParseCommand { .. })
            ),
            "{args:?}"
        );
    }
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn authentication_requires_selected_or_default_local_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let home = DhttpHome::new(temp.path().to_owned());
    let options = Options::try_parse_from(["access", "list"]).unwrap();
    let error = run_for_home(&home, options).await.unwrap_err();
    assert!(error.to_string().contains("genmeta identity default"));
    let options = Options::try_parse_from(["access", "--identity", "alice.pilot", "list"]).unwrap();
    let error = run_for_home(&home, options).await.unwrap_err();
    assert!(matches!(error, genmeta_access::Error::LoadProfile { .. }));
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
}
