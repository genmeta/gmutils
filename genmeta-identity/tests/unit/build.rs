use super::*;

#[test]
fn missing_env_uses_genmeta_production_server() {
    let name = format!(
        "__GENMETA_IDENTITY_MISSING_BOOTSTRAP_{}",
        std::process::id()
    );

    assert_eq!(
        env_or_default(&name, DEFAULT_CA_SERVICE),
        "https://api.genmeta.net"
    );
}
