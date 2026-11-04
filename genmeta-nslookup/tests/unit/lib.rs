use clap::Parser;

use super::*;

#[test]
fn options_accept_global_flag() {
    let options = Options::try_parse_from(["nslookup", "--global", "alice.smith", "mdns"]).unwrap();

    assert_eq!(options.home_scope(), dhttp_home::HomeScope::Global);
}

#[test]
fn query_names_use_home_normalization_without_implicit_suffix() {
    for (input, expected) in [
        ("nat.example.cn", "nat.example.cn"),
        (" Alice.Smith~ ", "alice.smith.dhttp.net"),
        ("Alice.Smith.DHTTP.NET.", "alice.smith.dhttp.net"),
        ("alice.smith", "alice.smith"),
        ("localhost", "localhost"),
    ] {
        let options = Options::try_parse_from(["nslookup", input, "system"]).unwrap();
        assert_eq!(options.name, expected);
    }
    assert!(Options::try_parse_from(["nslookup", "alice~.example.cn"]).is_err());
}
