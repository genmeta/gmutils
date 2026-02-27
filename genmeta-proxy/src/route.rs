use http::{Method, Uri};
use hyper::body::Incoming;

/// Classification of an incoming proxy request.
#[derive(Debug)]
pub enum Route {
    /// Plain HTTP request to a genmeta domain — forward via H3
    GenmetaPlainHttp {
        authority: http::uri::Authority,
        uri: Uri,
    },
    /// CONNECT request to a genmeta domain — return 502 (Phase 2: MITM)
    GenmetaConnect { authority: http::uri::Authority },
    /// CONNECT request to a non-genmeta domain — standard TCP tunnel
    TunnelConnect { authority: http::uri::Authority },
    /// Plain HTTP request to a non-genmeta domain — standard HTTP forward
    StandardForward { uri: Uri },
}

/// Routes incoming requests based on configured domain suffixes.
pub struct Router {
    domain_suffixes: Vec<String>,
    /// Reserved for future blacklist filtering (Phase 2+)
    _blacklist: Vec<String>,
}

impl Router {
    pub fn new(suffixes: Vec<String>) -> Self {
        Self {
            domain_suffixes: suffixes,
            _blacklist: Vec::new(),
        }
    }

    /// Check if a host (without port) matches any configured suffix.
    pub fn is_genmeta(&self, host: &str) -> bool {
        // strip port if present
        let host = host.split(':').next().unwrap_or(host);
        self.domain_suffixes.iter().any(|suffix| {
            if suffix.starts_with('.') {
                // leading dot means match subdomains only
                host.ends_with(suffix.as_str())
            } else {
                // no leading dot: match exact or subdomains
                host == suffix || host.ends_with(&format!(".{}", suffix))
            }
        })
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
        Router::new(vec![".genmeta.net".to_string()])
    }

    #[test]
    fn test_is_genmeta_exact_suffix() {
        let r = router();
        assert!(r.is_genmeta("api.genmeta.net"));
        assert!(r.is_genmeta("test.genmeta.net"));
        assert!(r.is_genmeta("a.b.genmeta.net"));
    }

    #[test]
    fn test_is_genmeta_non_match() {
        let r = router();
        assert!(!r.is_genmeta("example.com"));
        assert!(!r.is_genmeta("genmeta.net.evil.com"));
        assert!(!r.is_genmeta("notgenmeta.net"));
    }

    #[test]
    fn test_is_genmeta_with_port() {
        let r = router();
        // is_genmeta takes host (no port), but let's be safe
        assert!(r.is_genmeta("api.genmeta.net:443"));
    }

    #[test]
    fn test_is_genmeta_bare_domain() {
        // "genmeta.net" without subdomain — matches if suffix is ".genmeta.net"?
        // Depends on implementation. ".genmeta.net" suffix means subdomains only.
        // "genmeta.net" does NOT end with ".genmeta.net" — correct behavior.
        let r = router();
        assert!(!r.is_genmeta("genmeta.net"));
    }
}
