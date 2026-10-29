use super::*;
#[test]
fn options_accept_global_flag() {
    let options = Options::try_parse_from(["nat-detect", "--global"]).unwrap();
    assert_eq!(options.home_scope(), home::HomeScope::Global);
}
#[test]
fn interface_filter_selects_names_and_addresses() {
    let ip = "192.0.2.1".parse().unwrap();
    assert!(selected(&["*".into()], "eth0", ip));
    assert!(selected(&["eth0".into()], "eth0", ip));
    assert!(selected(&["192.0.2.1".into()], "eth0", ip));
    assert!(!selected(&["eth1".into()], "eth0", ip));
}
