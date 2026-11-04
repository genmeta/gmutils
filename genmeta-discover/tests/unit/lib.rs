use super::{DHTTP_MDNS_SERVICE_DOMAIN, domain_with_default_mdns_service};

#[test]
fn domain_with_default_mdns_service_appends_configured_service_suffix() {
    assert_eq!(
        domain_with_default_mdns_service("reimu.pilot"),
        format!("reimu.pilot.{DHTTP_MDNS_SERVICE_DOMAIN}")
    );
}

#[test]
fn domain_with_default_mdns_service_keeps_empty_and_full_names() {
    assert_eq!(domain_with_default_mdns_service(""), "");
    assert_eq!(
        domain_with_default_mdns_service(DHTTP_MDNS_SERVICE_DOMAIN),
        DHTTP_MDNS_SERVICE_DOMAIN
    );
    let full_name = format!("reimu.pilot.{DHTTP_MDNS_SERVICE_DOMAIN}");
    assert_eq!(domain_with_default_mdns_service(&full_name), full_name);
}
