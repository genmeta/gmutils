use clap::Parser;

use super::*;

#[test]
fn options_accept_global_flag() {
    let options = Options::try_parse_from(["genmeta-proxy", "--global"]).unwrap();

    assert_eq!(options.home_scope(), dhttp_home::HomeScope::Global);
}

#[test]
fn options_accept_legacy_bind_and_daemon_aliases() {
    let options =
        Options::try_parse_from(["genmeta-proxy", "--bind", "127.0.0.1:16081", "-d"]).unwrap();

    assert!(options.daemon);
}
