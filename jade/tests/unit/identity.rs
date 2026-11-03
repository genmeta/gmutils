use super::*;

#[test]
fn all_jade_commands_resolve_a_base_name_to_one_development_child() {
    for name in [
        "alex.chen",
        "alex.chen.dhttp.net",
        "dev.alex.chen",
        "dev.alex.chen.dhttp.net",
    ] {
        assert_eq!(developer_name(name).unwrap(), "dev.alex.chen.dhttp.net");
    }
    assert!(developer_name("https://alex.chen/").is_err());
}
