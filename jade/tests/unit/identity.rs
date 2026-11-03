use super::*;

#[test]
fn all_jade_commands_require_the_actual_development_child() {
    for (input, expected) in [
        ("dev.genmeta", "dev.genmeta.dhttp.net"),
        ("dev.alex.chen", "dev.alex.chen.dhttp.net"),
        ("dev.alex.chen.dhttp.net", "dev.alex.chen.dhttp.net"),
        (" DEV.Dev.Wang~ ", "dev.dev.wang.dhttp.net"),
        ("dev.dev.wang", "dev.dev.wang.dhttp.net"),
    ] {
        assert_eq!(developer_name(input).unwrap(), expected);
    }
    for input in [
        "alex.chen",
        "alex.chen.dhttp.net",
        "dev.wang",
        "dev.wang.dhttp.net",
    ] {
        assert_eq!(
            developer_name(input).unwrap_err().code,
            "E_IDENTITY_REQUIRED"
        );
    }
    assert!(developer_name("https://alex.chen/").is_err());
}

#[tokio::test]
async fn explicit_development_identity_matches_the_exact_configured_author() {
    assert_eq!(
        select(Some("dev.dev.wang"), Some("dev.dev.wang.dhttp.net"))
            .await
            .unwrap(),
        "dev.dev.wang.dhttp.net"
    );
    assert_eq!(
        select(Some("dev.dev.wang"), Some("dev.wang.dhttp.net"))
            .await
            .unwrap_err()
            .code,
        "E_IDENTITY_MISMATCH"
    );
}
