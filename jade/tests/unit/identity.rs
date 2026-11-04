use super::*;

#[test]
fn developer_setup_requires_the_actual_development_child() {
    for (input, expected) in [
        ("dev.genmeta.tech", "dev.genmeta.tech.dhttp.net"),
        ("dev.genmeta.tech.dhttp.net", "dev.genmeta.tech.dhttp.net"),
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
        "dev.genmeta",
        "dev.genmeta.dhttp.net",
    ] {
        assert_eq!(
            developer_name(input).unwrap_err().code,
            "E_IDENTITY_REQUIRED"
        );
    }
    assert!(developer_name("https://alex.chen/").is_err());
}

#[test]
fn official_author_requires_an_exact_match() {
    assert!(is_standard_author("dev.genmeta.tech.dhttp.net"));
    assert!(is_standard_author("std.dhttp.net"));
    for author in [
        "dev.genmeta.dhttp.net",
        "dev.tech.genmeta.dhttp.net",
        "dev.genmeta.tech.dhttp.net.attacker.dhttp.net",
        "dev.other.genmeta.tech.dhttp.net",
    ] {
        assert!(!is_standard_author(author));
    }
}

#[tokio::test]
async fn configured_author_is_normalized_without_loading_credentials() {
    for author in ["dev.alex.chen", "dev.alex.chen.dhttp.net"] {
        assert_eq!(
            select(Some(author)).await.unwrap(),
            "dev.alex.chen.dhttp.net"
        );
    }
    assert_eq!(
        select(Some("https://alex.chen/")).await.unwrap_err().code,
        "E_CONFIG_INVALID"
    );
}
