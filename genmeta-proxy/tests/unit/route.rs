use super::*;

fn router() -> Router {
    Router::new()
}

#[test]
fn test_is_genmeta_exact_suffix() {
    let r = router();
    assert!(r.is_genmeta("api.dhttp.net"));
    assert!(r.is_genmeta("API.Dhttp.Net"));
    assert!(r.is_genmeta("test.dhttp.net"));
    assert!(r.is_genmeta("a.b.dhttp.net"));
}

#[test]
fn test_is_genmeta_non_match() {
    let r = router();
    assert!(!r.is_genmeta("example.com"));
    assert!(!r.is_genmeta("dhttp.net.evil.com"));
    assert!(!r.is_genmeta("notdhttp.net"));
}

#[test]
fn test_is_genmeta_with_port() {
    let r = router();
    // is_genmeta takes host (no port), but let's be safe
    assert!(r.is_genmeta("api.dhttp.net:443"));
}

#[test]
fn test_is_genmeta_bare_domain() {
    // "dhttp.net" without subdomain — matches if suffix is ".dhttp.net"?
    // Depends on implementation. ".dhttp.net" suffix means subdomains only.
    // "dhttp.net" does NOT end with ".dhttp.net" — correct behavior.
    let r = router();
    assert!(!r.is_genmeta("dhttp.net"));
}
