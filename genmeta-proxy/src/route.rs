use dhttp::name::DhttpName as Name;
use http::{Method, Uri};
use hyper::body::Incoming;

/// Classification of an incoming proxy request.
#[derive(Debug)]
pub enum Route {
    /// Plain HTTP request to a DHTTP identity domain — forward via DHTTP/3
    GenmetaPlainHttp {
        authority: http::uri::Authority,
        uri: Uri,
    },
    /// CONNECT request to a DHTTP identity domain — return 502 (Phase 2: MITM)
    GenmetaConnect { authority: http::uri::Authority },
    /// CONNECT request to a non-DHTTP identity domain — standard TCP tunnel
    TunnelConnect { authority: http::uri::Authority },
    /// Plain HTTP request to a non-DHTTP identity domain — standard HTTP forward
    StandardForward { uri: Uri },
}

/// Routes incoming requests based on the DHTTP identity domain suffix.
pub struct Router {
    /// Reserved for future blacklist filtering (Phase 2+)
    _blacklist: Vec<String>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub fn new() -> Self {
        Self {
            _blacklist: Vec::new(),
        }
    }

    /// Check if a host (without port) matches any configured suffix.
    pub fn is_genmeta(&self, host: &str) -> bool {
        // strip port if present
        let host = host.split(':').next().unwrap_or(host);
        host.ends_with('~')
            || (host.len() >= Name::SUFFIX.len()
                && host[host.len() - Name::SUFFIX.len()..].eq_ignore_ascii_case(Name::SUFFIX))
    }

    /// Classify an incoming request into a Route variant.
    pub fn classify(&self, req: &hyper::Request<Incoming>) -> Route {
        let method = req.method();
        let uri = req.uri();

        if method == Method::CONNECT {
            // CONNECT: authority is in the URI path (host:port)
            if let Some(authority) = uri.authority() {
                if self.is_genmeta(authority.host()) {
                    return Route::GenmetaConnect {
                        authority: authority.clone(),
                    };
                } else {
                    return Route::TunnelConnect {
                        authority: authority.clone(),
                    };
                }
            }
        }

        // Plain HTTP: URI is absolute form (http://host/path)
        if let Some(authority) = uri.authority()
            && self.is_genmeta(authority.host())
        {
            return Route::GenmetaPlainHttp {
                authority: authority.clone(),
                uri: uri.clone(),
            };
        }

        Route::StandardForward { uri: uri.clone() }
    }
}

#[cfg(test)]
mod tests {
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
}
