//! Extended bind pattern for flexible BindUri generation.
//!
//! [`Bind`] is a pattern-like extension of
//! [`BindUri`](h3x::gm_quic::qinterface::bind_uri::BindUri) that provides:
//!
//! 1. **Glob host** — `iface://v4.en*:8080` matches all interfaces starting with "en"
//! 2. **Omitted family** — `iface://enp17s0:8080` implies both V4 and V6
//! 3. **Omitted scheme** — `v4.enp17s0:8080` infers `iface://`, `127.0.0.1:8080` infers `inet://`
//! 4. **Omitted port** — `iface://v4.enp17s0` defaults to port 0 (system-assigned)
//! 5. **IPv6 bracket syntax** — `inet://[::1]:8080`, `[fe80::1]:443` (brackets required
//!    for IPv6 addresses with port, because `:` is a port separator)
//! 6. **Bare IP address** — `::1`, `::`, `127.0.0.1` are recognized directly as inet
//!    (no port, no path-and-query)
//!
//! All extensions compose freely: `en*:8080`, `*`, `v4.*:8080`, `[ew]*`, `[::1]:8080`, etc.

use std::{
    cell::LazyCell,
    collections::{HashMap, hash_map},
    fmt,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use derive_more::{Deref, DerefMut, From, Into};
use either::Either;
use globset::{Glob, GlobMatcher};
use h3x::gm_quic::{
    qbase::net::Family,
    qinterface::bind_uri::{BindUri, BindUriScheme},
};
use http::{
    Uri,
    uri::{Authority, PathAndQuery, Scheme},
};
use peg::{error::ParseError, str::LineCol};
use snafu::Snafu;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The host part of a [`Bind`] — a parsed IP address, a glob pattern, or an exact name.
///
/// Literal host names (e.g. `enp17s0`) are normally represented as
/// [`Glob`](BindHost::Glob) with a literal pattern (globset treats them as exact
/// matches).  [`Exact`](BindHost::Exact) serves as a fallback when `Glob::new`
/// fails for an unusual input.
#[derive(Debug, Clone)]
pub enum BindHost {
    /// A parsed IP address (IPv4 or IPv6).
    Ip {
        /// The parsed address.
        addr: IpAddr,
        /// String representation of the address (without brackets).
        repr: String,
    },
    /// A compiled glob pattern (e.g. `en*`, `[ew]*`, `*`, `enp17s0`).
    Glob {
        /// IP family filter, if present.
        family: Option<Family>,
        /// Compiled matcher for efficient matching.
        matcher: GlobMatcher,
    },
    /// Fallback exact match when glob compilation fails.
    Exact {
        /// IP family filter, if present.
        family: Option<Family>,
        /// The exact interface name.
        nic: String,
    },
}

impl BindHost {
    /// Build a [`BindHost`] from a raw host string, automatically classifying
    /// it as [`Ip`](BindHost::Ip), [`Glob`](BindHost::Glob), or
    /// [`Exact`](BindHost::Exact) (fallback).
    ///
    /// `family` is propagated into [`Glob`](BindHost::Glob) and
    /// [`Exact`](BindHost::Exact) variants; it is rejected for IP addresses
    /// (writing `v4.127.0.0.1` makes no sense).
    fn classify(raw: &str, family: Option<Family>) -> Result<Self, &'static str> {
        // Try direct IP parse (handles plain IPv4 like "127.0.0.1")
        if let Ok(addr) = raw.parse::<IpAddr>() {
            if family.is_some() {
                return Err("family prefix is not valid for IP addresses");
            }
            return Ok(Self::Ip {
                addr,
                repr: raw.to_owned(),
            });
        }

        // Try bracket-stripped IP parse (handles "[::1]")
        if let Some(inner) = raw.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
            && let Ok(addr) = inner.parse::<Ipv6Addr>()
        {
            if family.is_some() {
                return Err("family prefix is not valid for IP addresses");
            }
            return Ok(Self::Ip {
                addr: addr.into(),
                repr: inner.to_owned(),
            });
        }

        // Try glob compilation; fall back to plain string
        match Glob::new(raw) {
            Ok(glob) => Ok(Self::Glob {
                family,
                matcher: glob.compile_matcher(),
            }),
            Err(_) => Ok(Self::Exact {
                family,
                nic: raw.to_owned(),
            }),
        }
    }

    /// Returns `true` if this host contains glob meta-characters (`*`, `[`).
    #[must_use]
    pub fn is_glob(&self) -> bool {
        match self {
            Self::Ip { .. } | Self::Exact { .. } => false,
            Self::Glob { matcher, .. } => {
                let pat = matcher.glob().glob();
                pat.contains('*') || pat.contains('[')
            }
        }
    }

    /// Returns the underlying string regardless of variant.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ip { repr, .. } | Self::Exact { nic: repr, .. } => repr,
            Self::Glob { matcher, .. } => matcher.glob().glob(),
        }
    }

    /// Returns `true` if the host is a parsed IP address.
    #[must_use]
    pub fn is_ip_addr(&self) -> bool {
        matches!(self, Self::Ip { .. })
    }

    /// Returns the parsed [`IpAddr`] if this host is an IP address.
    #[must_use]
    pub fn as_ip_addr(&self) -> Option<IpAddr> {
        match self {
            Self::Ip { addr, .. } => Some(*addr),
            _ => None,
        }
    }

    /// Returns the IP family filter, if set.
    ///
    /// Only [`Glob`](BindHost::Glob) and [`Exact`](BindHost::Exact) carry a
    /// family; [`Ip`](BindHost::Ip) always returns `None`.
    #[must_use]
    pub fn family(&self) -> Option<Family> {
        match self {
            Self::Ip { .. } => None,
            Self::Glob { family, .. } | Self::Exact { family, .. } => *family,
        }
    }

    /// Returns the families this host covers.
    ///
    /// If a specific family is set, returns a single-element slice;
    /// otherwise returns both V4 and V6.
    #[must_use]
    pub fn families(&self) -> &'static [Family] {
        const V4_ONLY: [Family; 1] = [Family::V4];
        const V6_ONLY: [Family; 1] = [Family::V6];
        const BOTH: [Family; 2] = [Family::V4, Family::V6];
        match self.family() {
            Some(Family::V4) => &V4_ONLY,
            Some(Family::V6) => &V6_ONLY,
            None => &BOTH,
        }
    }

    /// Tests whether a concrete interface name matches this host.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        match self {
            Self::Ip { .. } => false,
            Self::Glob { matcher, .. } => matcher.is_match(name),
            Self::Exact { nic, .. } => nic == name,
        }
    }
}

impl PartialEq for BindHost {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ip { repr: a, .. }, Self::Ip { repr: b, .. }) => a == b,
            (
                Self::Glob {
                    family: fa,
                    matcher: ma,
                },
                Self::Glob {
                    family: fb,
                    matcher: mb,
                },
            ) => fa == fb && ma.glob().glob() == mb.glob().glob(),
            (
                Self::Exact {
                    family: fa,
                    nic: na,
                },
                Self::Exact {
                    family: fb,
                    nic: nb,
                },
            ) => fa == fb && na == nb,
            _ => false,
        }
    }
}

impl Eq for BindHost {}

impl fmt::Display for BindHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A flexible bind pattern parsed from a string.
///
/// See [module documentation](self) for the full syntax description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    /// The resolved scheme (`iface` or `inet`). Always present after parsing.
    pub scheme: BindUriScheme,
    /// Host part — exact name/IP or glob pattern (carries family if applicable).
    pub host: BindHost,
    /// Port number. `None` means default (0 = system-assigned).
    pub port: Option<u16>,
    /// Optional path-and-query suffix carried through to generated URIs,
    /// validated as [`PathAndQuery`] during parsing.
    pub path_and_query: Option<PathAndQuery>,
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl fmt::Display for Bind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", self.scheme)?;
        if let Some(family) = self.host.family() {
            let tag = match family {
                Family::V4 => "v4",
                Family::V6 => "v6",
            };
            write!(f, "{tag}.")?;
        }
        if self.host.as_ip_addr().is_some_and(|ip| ip.is_ipv6()) {
            write!(f, "[{}]", self.host)?;
        } else {
            write!(f, "{}", self.host)?;
        }
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        if let Some(ref pq) = self.path_and_query {
            write!(f, "{pq}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PEG parser
// ---------------------------------------------------------------------------

peg::parser! {
    grammar bind_parser() for str {
        // -- atoms --

        rule family() -> Family
            = "v4" { Family::V4 }
            / "V4" { Family::V4 }
            / "v6" { Family::V6 }
            / "V6" { Family::V6 }

        /// Scheme prefix like `iface://` or `inet://`.
        rule scheme() -> &'input str
            = s:$(['a'..='z' | 'A'..='Z']+) "://" { s }

        /// Port number after `:`.
        rule port() -> u16
            = ":" n:$(['0'..='9']+) {?
                n.parse().or(Err("valid port number"))
            }

        /// A host character — anything except `:`, `/`, `?`, `#`, `[`, `]`.
        rule host_char() -> char
            = c:[^ ':' | '/' | '?' | '#' | '[' | ']'] { c }

        /// A bracket segment: `[...]` (IPv6 address or glob character class).
        rule bracket_segment()
            = "[" [^ ']']+ "]"

        /// A single host token: bracket segment or plain character.
        rule host_token()
            = bracket_segment()
            / host_char()

        /// Host string — one or more host tokens captured as a single slice.
        rule host_str() -> &'input str
            = s:$(host_token()+) { s }

        /// Path-and-query remainder: everything from `/` or `?` onward.
        rule path_and_query() -> &'input str
            = s:$(['/' | '?'] [_]*) { s }

        // -- composite rules --

        /// `scheme://family.host:port/path?query`  (full form)
        pub rule full() -> Bind
            = s:scheme()
              fam:(f:family() "." { f })?
              h:host_str()
              p:port()?
              pq:path_and_query()?
            {?
                let host = BindHost::classify(h, fam)?;
                let scheme = infer_scheme(Some(s), &host);
                let path_and_query = pq
                    .map(|s| s.parse::<PathAndQuery>())
                    .transpose()
                    .map_err(|_| "valid path-and-query")?;
                Ok(Bind { scheme, host, port: p, path_and_query })
            }

        /// `family.host:port/path?query`  (no scheme)
        pub rule no_scheme() -> Bind
            = fam:(f:family() "." { f })?
              h:host_str()
              p:port()?
              pq:path_and_query()?
            {?
                let host = BindHost::classify(h, fam)?;
                let scheme = infer_scheme(None, &host);
                let path_and_query = pq
                    .map(|s| s.parse::<PathAndQuery>())
                    .transpose()
                    .map_err(|_| "valid path-and-query")?;
                Ok(Bind { scheme, host, port: p, path_and_query })
            }

        /// Top-level entry: bare IP first, then full form, then no-scheme.
        ///
        /// `bare_ip` has highest priority — its `{? ... }` semantic guard
        /// ensures only valid IP addresses match; everything else backtracks.
        pub rule bind() -> Bind
            = b:bare_ip() { b }
            / b:full() { b }
            / b:no_scheme() { b }

        /// Bare IP address: `::1`, `::`, `2001:db8::1`, `127.0.0.1`.
        ///
        /// Captures everything up to `/`, `?`, or `#` (or end of input) and
        /// validates it as an [`IpAddr`].  Falls back via PEG ordered choice
        /// if validation fails.
        rule bare_ip() -> Bind
            = s:$([^ '/' | '?' | '#']+) pq:path_and_query()? {?
                let addr = s.parse::<IpAddr>().or(Err("valid IP address"))?;
                let path_and_query = pq
                    .map(|s| s.parse::<PathAndQuery>())
                    .transpose()
                    .map_err(|_| "valid path-and-query")?;
                Ok(Bind {
                    scheme: BindUriScheme::Inet,
                    host: BindHost::Ip { addr, repr: s.to_owned() },
                    port: None,
                    path_and_query,
                })
            }
    }
}

// ---------------------------------------------------------------------------
// Scheme inference helper
// ---------------------------------------------------------------------------

/// Infer the bind scheme from an optional explicit scheme string and the host.
fn infer_scheme(explicit: Option<&str>, host: &BindHost) -> BindUriScheme {
    if let Some(s) = explicit {
        return match s.to_ascii_lowercase().as_str() {
            "iface" => BindUriScheme::Iface,
            "inet" => BindUriScheme::Inet,
            // Default unknown schemes to iface (can be extended later)
            _ => BindUriScheme::Iface,
        };
    }
    // No explicit scheme — infer from host variant
    if host.is_ip_addr() {
        BindUriScheme::Inet
    } else {
        BindUriScheme::Iface
    }
}

// ---------------------------------------------------------------------------
// FromStr
// ---------------------------------------------------------------------------

impl FromStr for Bind {
    type Err = ParseError<LineCol>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bind_parser::bind(s)
    }
}

// ---------------------------------------------------------------------------
// Bind → BindUri expansion
// ---------------------------------------------------------------------------

impl Bind {
    /// Returns the effective port (defaults to 0 when omitted).
    #[must_use]
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(0)
    }

    /// Returns the path-and-query as a `&str`.
    #[must_use]
    pub fn path_and_query_str(&self) -> Option<&str> {
        self.path_and_query.as_ref().map(|pq| pq.as_str())
    }

    fn bind_uri_template(&self) -> impl Fn(Authority) -> Option<BindUri> + use<> {
        let mut uri_template = Uri::from_static("iface://v4.lo:0/").into_parts();
        uri_template.scheme = Some(self.scheme.into());
        uri_template.path_and_query =
            (self.path_and_query.clone()).or(uri_template.path_and_query.clone());
        let uri_template = Uri::from_parts(uri_template).expect("valid URI template");

        let port = self.effective_port();
        move |authority: Authority| {
            let mut uri_parts = uri_template.clone().into_parts();
            uri_parts.authority = Some(authority);

            let mut bind_uri =
                (Uri::from_parts(uri_parts).ok()).and_then(|uri| BindUri::try_from(uri).ok())?;
            if port == 0 {
                bind_uri = bind_uri.alloc_port();
            }
            Some(bind_uri)
        }
    }

    fn bind_hosts_for_interface(&self, interface: &str) -> impl Iterator<Item = Authority> {
        match &self.host {
            BindHost::Ip { .. } => Either::Left(std::iter::empty()),
            host if !host.matches(interface) => Either::Left(std::iter::empty()),
            host => Either::Right(host.families().iter().filter_map(move |family| {
                format!("{family}.{interface}:{port}", port = self.effective_port())
                    .parse()
                    .ok()
            })),
        }
    }

    /// Expand this bind pattern into concrete [`BindUri`]s.
    ///
    /// For IP hosts, a single URI is produced directly.
    /// For glob / exact hosts, the `interfaces` list is filtered and each
    /// matching interface is expanded with the applicable IP families.
    pub fn to_bind_uris<'a, I>(
        &'a self,
        interfaces: I,
    ) -> impl Iterator<Item = BindUri> + use<'a, I>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let template = self.bind_uri_template();
        let port = self.effective_port();
        match &self.host {
            BindHost::Ip { addr, .. } => {
                let authority: Authority = if addr.is_ipv6() {
                    format!("[{addr}]:{port}")
                } else {
                    format!("{addr}:{port}")
                }
                .parse()
                .expect("valid authority");
                Either::Left(template(authority).into_iter())
            }
            BindHost::Glob { .. } | BindHost::Exact { .. } => Either::Right(
                interfaces
                    .into_iter()
                    .flat_map(move |iface| self.bind_hosts_for_interface(iface))
                    .flat_map(template),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error indicating that two [`Bind`] patterns expand to the same target
/// (identical IP + port, or identical family + NIC + port) but carry
/// different path-and-query values.
#[derive(Debug, Clone, Snafu)]
#[snafu(display(
    "conflicting bindings exist for bind target `{scheme}://{authority}`: `{e}` vs `{i}`",
    e = existing.as_ref().map_or("/", PathAndQuery::as_str),
    i = incoming.as_ref().map_or("/", PathAndQuery::as_str),
))]
pub struct BindConflictError {
    /// The scheme component of the conflicting bind target.
    pub scheme: Scheme,
    /// The authority component of the conflicting bind target.
    pub authority: Authority,
    /// The first encountered path-and-query.
    pub existing: Option<PathAndQuery>,
    /// The conflicting path-and-query.
    pub incoming: Option<PathAndQuery>,
}

// ---------------------------------------------------------------------------
// Binds
// ---------------------------------------------------------------------------

/// A collection of [`Bind`] patterns, typically populated from CLI arguments.
#[derive(Debug, Clone, PartialEq, Eq, Deref, DerefMut, From, Into)]
pub struct Binds {
    /// Bind patterns
    binds: Vec<Bind>,
}

impl Binds {
    /// Create a new [`Binds`] from a list of [`Bind`] patterns.
    pub fn new(binds: Vec<Bind>) -> Self {
        Self { binds }
    }

    /// Expand all contained [`Bind`] patterns into concrete [`BindUri`]s,
    /// checking for conflicting path-and-query on the same target.
    ///
    /// Two expanded URIs are considered "the same target" when their
    /// scheme and authority (IP + port, or family + NIC + port) are
    /// identical.  If such a pair carries different path-and-query
    /// values, a [`BindConflictError`] is returned.
    ///
    /// Duplicate URIs (same target *and* same path-and-query) are
    /// silently deduplicated.
    #[allow(clippy::result_large_err)]
    pub fn to_bind_uris<'a, I>(&'a self, interfaces: I) -> Result<Vec<BindUri>, BindConflictError>
    where
        I: IntoIterator<Item = &'a str> + Clone,
    {
        let mut seen: HashMap<(Scheme, Authority), Option<PathAndQuery>> = HashMap::new();
        let mut bind_uris = Vec::new();

        let mut push_bind_uri = |bind_uri: BindUri| {
            let inner = bind_uri.as_uri();
            let key = (
                inner.scheme().expect("BindUri always has a scheme").clone(),
                inner
                    .authority()
                    .expect("BindUri always has an authority")
                    .clone(),
            );
            let path_and_query = inner.path_and_query().cloned();

            match seen.entry(key) {
                hash_map::Entry::Occupied(entry) => {
                    if *entry.get() != path_and_query {
                        let (scheme, authority) = entry.key();
                        return Err(BindConflictError {
                            scheme: scheme.clone(),
                            authority: authority.clone(),
                            existing: entry.get().clone(),
                            incoming: path_and_query,
                        });
                    }
                    // Same target, same path-and-query → deduplicate
                    Ok(())
                }
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(path_and_query.clone());
                    bind_uris.push(bind_uri);
                    Ok(())
                }
            }
        };

        let bind_uri_templates =
            self.iter()
                .try_fold(Vec::with_capacity(self.len()), |mut templates, bind| {
                    match bind.host {
                        BindHost::Ip { addr, .. } => {
                            let template = bind.bind_uri_template();
                            let port = bind.effective_port();
                            let authority = format!("{addr}:{port}").parse();
                            if let Some(bind_uri) = authority.ok().and_then(template) {
                                push_bind_uri(bind_uri)?;
                            }
                        }
                        BindHost::Glob { .. } | BindHost::Exact { .. } => {
                            let template = LazyCell::new(|| bind.bind_uri_template());
                            templates.push((bind, template))
                        }
                    }
                    Ok(templates)
                })?;

        interfaces
            .into_iter()
            .flat_map(|interface| {
                bind_uri_templates.iter().flat_map(|(bind, template)| {
                    // clippy issue: https://github.com/rust-lang/rust-clippy/issues/16641
                    #[allow(clippy::redundant_closure)]
                    bind.bind_hosts_for_interface(interface)
                        .flat_map(|authority| template(authority))
                })
            })
            .try_for_each(push_bind_uri)?;

        Ok(bind_uris)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Parsing tests --

    #[test]
    fn parse_full_iface_with_family() {
        let b: Bind = "iface://v4.enp17s0:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), Some(Family::V4));
        assert_eq!(
            b.host,
            BindHost::classify("enp17s0", Some(Family::V4)).unwrap()
        );
        assert_eq!(b.port, Some(8080));
        assert!(b.path_and_query.is_none());
    }

    #[test]
    fn parse_full_iface_glob() {
        let b: Bind = "iface://v4.en*:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), Some(Family::V4));
        assert!(b.host.is_glob());
        assert_eq!(b.host.as_str(), "en*");
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_iface_no_family() {
        let b: Bind = "iface://enp17s0:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), None);
        assert!(!b.host.is_glob());
        assert_eq!(b.host.as_str(), "enp17s0");
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_iface_no_port() {
        let b: Bind = "iface://v4.enp17s0".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), Some(Family::V4));
        assert_eq!(b.host.as_str(), "enp17s0");
        assert_eq!(b.port, None);
    }

    #[test]
    fn parse_inet() {
        let b: Bind = "inet://127.0.0.1:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert_eq!(b.host.family(), None);
        assert_eq!(b.host.as_str(), "127.0.0.1");
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_no_scheme_ip() {
        let b: Bind = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert_eq!(b.host.as_str(), "127.0.0.1");
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_no_scheme_iface() {
        let b: Bind = "enp17s0:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), None);
        assert_eq!(b.host.as_str(), "enp17s0");
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_no_scheme_with_family() {
        let b: Bind = "v4.enp17s0:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), Some(Family::V4));
        assert_eq!(b.host.as_str(), "enp17s0");
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_glob_no_scheme() {
        let b: Bind = "en*:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), None);
        assert!(b.host.is_glob());
        assert_eq!(b.host.as_str(), "en*");
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_star_only() {
        let b: Bind = "*".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), None);
        assert!(b.host.is_glob());
        assert_eq!(b.host.as_str(), "*");
        assert_eq!(b.port, None);
    }

    #[test]
    fn parse_star_with_port() {
        let b: Bind = "*:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), None);
        assert!(b.host.is_glob());
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_v4_star() {
        let b: Bind = "v4.*".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), Some(Family::V4));
        assert!(b.host.is_glob());
        assert_eq!(b.port, None);
    }

    #[test]
    fn parse_v6_star_with_port() {
        let b: Bind = "v6.*:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), Some(Family::V6));
        assert!(b.host.is_glob());
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_no_scheme_no_port() {
        let b: Bind = "enp17s0".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), None);
        assert_eq!(b.host.as_str(), "enp17s0");
        assert_eq!(b.port, None);
    }

    #[test]
    fn parse_with_path_and_query() {
        let b: Bind = "iface://v4.en*:8080/?stun_server=stun.genmeta.net"
            .parse()
            .unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert_eq!(b.host.family(), Some(Family::V4));
        assert!(b.host.is_glob());
        assert_eq!(b.port, Some(8080));
        assert_eq!(
            b.path_and_query_str(),
            Some("/?stun_server=stun.genmeta.net")
        );
    }

    #[test]
    fn parse_with_query_only() {
        let b: Bind = "iface://v4.enp17s0:8080?stun=true".parse().unwrap();
        assert_eq!(b.path_and_query_str(), Some("?stun=true"));
    }

    // -- Display round-trip --

    #[test]
    fn display_full() {
        let b: Bind = "iface://v4.enp17s0:8080".parse().unwrap();
        assert_eq!(b.to_string(), "iface://v4.enp17s0:8080");
    }

    #[test]
    fn display_no_port() {
        let b: Bind = "iface://v4.enp17s0".parse().unwrap();
        assert_eq!(b.to_string(), "iface://v4.enp17s0");
    }

    #[test]
    fn display_no_family() {
        let b: Bind = "iface://enp17s0:8080".parse().unwrap();
        assert_eq!(b.to_string(), "iface://enp17s0:8080");
    }

    // -- Glob matching --

    #[test]
    fn glob_exact_match() {
        let host = BindHost::classify("enp17s0", None).unwrap();
        assert!(host.matches("enp17s0"));
        assert!(!host.matches("wlan0"));
    }

    #[test]
    fn glob_star_match() {
        let host = BindHost::classify("en*", None).unwrap();
        assert!(host.matches("enp17s0"));
        assert!(host.matches("eno1"));
        assert!(!host.matches("wlan0"));

        let star = BindHost::classify("*", None).unwrap();
        assert!(star.matches("anything"));
    }

    #[test]
    fn glob_bracket_class() {
        let host = BindHost::classify("[ew]*", None).unwrap();
        assert!(host.is_glob());
        assert!(host.matches("enp17s0"));
        assert!(host.matches("wlan0"));
        assert!(!host.matches("lo"));
    }

    #[test]
    fn glob_bracket_single() {
        let host = BindHost::classify("wlan[01]", None).unwrap();
        assert!(host.is_glob());
        assert!(host.matches("wlan0"));
        assert!(host.matches("wlan1"));
        assert!(!host.matches("wlan2"));
    }

    // -- Classify --

    #[test]
    fn classify_ipv4_as_ip() {
        let host = BindHost::classify("127.0.0.1", None).unwrap();
        assert!(host.is_ip_addr());
        assert!(!host.is_glob());
        assert_eq!(host.as_str(), "127.0.0.1");
    }

    #[test]
    fn classify_ipv6_bracket_as_ip() {
        let host = BindHost::classify("[::1]", None).unwrap();
        assert!(host.is_ip_addr());
        assert_eq!(host.as_str(), "::1");
        assert_eq!(host.as_ip_addr().unwrap(), "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn classify_bracket_non_ip_as_glob() {
        let host = BindHost::classify("[ew]", None).unwrap();
        assert!(host.is_glob());
        assert!(!host.is_ip_addr());
    }

    // -- Families --

    #[test]
    fn families_both() {
        let b: Bind = "enp17s0:8080".parse().unwrap();
        assert_eq!(b.host.families(), [Family::V4, Family::V6]);
    }

    #[test]
    fn families_v4_only() {
        let b: Bind = "v4.enp17s0:8080".parse().unwrap();
        assert_eq!(b.host.families(), [Family::V4]);
    }

    // -- BindUri generation (iterators) --

    #[test]
    fn expand_iface() {
        let b: Bind = "iface://v4.enp17s0:8080".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
        assert_eq!(uris, vec!["iface://v4.enp17s0:8080/"]);
    }

    #[test]
    fn expand_both_families() {
        let b: Bind = "iface://enp17s0:8080".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
        assert_eq!(
            uris,
            vec!["iface://v4.enp17s0:8080/", "iface://v6.enp17s0:8080/"]
        );
    }

    #[test]
    fn expand_auto_port() {
        let b: Bind = "iface://v4.enp17s0".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("iface://v4.enp17s0:0/"));
    }

    #[test]
    fn expand_inet() {
        let b: Bind = "127.0.0.1:8080".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
        assert_eq!(uris, vec!["inet://127.0.0.1:8080/"]);
    }

    #[test]
    fn expand_with_interfaces_glob() {
        let b: Bind = "en*:8080".parse().unwrap();
        let interfaces = ["enp17s0", "eno1", "wlan0", "lo"];
        let uris: Vec<_> = b.to_bind_uris(interfaces).collect();
        // en* matches enp17s0 and eno1, each with V4 + V6
        assert_eq!(uris.len(), 4);
    }

    #[test]
    fn expand_with_interfaces_star() {
        let b: Bind = "*:8080".parse().unwrap();
        let interfaces = ["enp17s0", "wlan0"];
        let uris: Vec<_> = b.to_bind_uris(interfaces).collect();
        // * matches all, each with V4 + V6
        assert_eq!(uris.len(), 4);
    }

    #[test]
    fn expand_path_and_query_passthrough() {
        let b: Bind = "iface://v4.en*:8080/?stun_server=stun.genmeta.net"
            .parse()
            .unwrap();
        let uris: Vec<_> = b.to_bind_uris(["enp17s0"]).map(|u| u.to_string()).collect();
        assert_eq!(
            uris,
            vec!["iface://v4.enp17s0:8080/?stun_server=stun.genmeta.net"]
        );
    }

    #[test]
    fn path_and_query_is_validated() {
        let b: Bind = "iface://v4.en*:8080/?key=value".parse().unwrap();
        let pq = b.path_and_query.as_ref().unwrap();
        assert_eq!(pq, "/?key=value");
    }

    // -- Bare IPv6 address tests --

    #[test]
    fn parse_bare_ipv6_loopback() {
        let b: Bind = "::1".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert!(b.host.is_ip_addr());
        assert_eq!(b.host.as_str(), "::1");
        assert_eq!(b.port, None);
        assert!(b.path_and_query.is_none());
    }

    #[test]
    fn parse_bare_ipv6_any() {
        let b: Bind = "::".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert!(b.host.is_ip_addr());
        assert_eq!(b.host.as_str(), "::");
        assert_eq!(b.port, None);
    }

    #[test]
    fn parse_bare_ipv6_full() {
        let b: Bind = "2001:db8::1".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert!(b.host.is_ip_addr());
        assert_eq!(b.host.as_str(), "2001:db8::1");
        assert_eq!(b.port, None);
    }

    #[test]
    fn parse_bare_ipv4() {
        // Bare IPv4 without port also works via the fast path
        let b: Bind = "192.168.1.1".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert!(b.host.is_ip_addr());
        assert_eq!(b.host.as_str(), "192.168.1.1");
        assert_eq!(b.port, None);
    }

    #[test]
    fn display_bare_ipv6() {
        let b: Bind = "::1".parse().unwrap();
        // Display wraps IPv6 in brackets
        assert_eq!(b.to_string(), "inet://[::1]");
    }

    #[test]
    fn expand_bare_ipv6() {
        let b: Bind = "::1".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("inet://[::1]:0/"));
    }

    // -- Glob bracket parsing --

    #[test]
    fn parse_glob_bracket_class() {
        let b: Bind = "[ew]*:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Iface);
        assert!(b.host.is_glob());
        assert_eq!(b.host.as_str(), "[ew]*");
        assert_eq!(b.port, Some(8080));
    }

    // -- IPv6 bracket syntax tests --

    #[test]
    fn parse_ipv6_full_scheme() {
        let b: Bind = "inet://[::1]:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert_eq!(b.host.family(), None);
        assert_eq!(b.host.as_str(), "::1");
        assert_eq!(b.port, Some(8080));
        assert!(b.host.is_ip_addr());
    }

    #[test]
    fn parse_ipv6_no_scheme() {
        let b: Bind = "[::1]:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert_eq!(b.host.as_str(), "::1");
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_ipv6_full_addr() {
        let b: Bind = "inet://[2001:db8::1]:443".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert_eq!(b.host.as_str(), "2001:db8::1");
        assert_eq!(b.port, Some(443));
        assert!(b.host.is_ip_addr());
    }

    #[test]
    fn parse_ipv6_link_local() {
        let b: Bind = "[fe80::1]:8080".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert_eq!(b.host.as_str(), "fe80::1");
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn parse_ipv6_any() {
        let b: Bind = "inet://[::]:0".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert_eq!(b.host.as_str(), "::");
        assert_eq!(b.port, Some(0));
    }

    #[test]
    fn parse_ipv6_no_port() {
        let b: Bind = "[::1]".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert_eq!(b.host.as_str(), "::1");
        assert_eq!(b.port, None);
    }

    #[test]
    fn parse_ipv6_with_path_and_query() {
        let b: Bind = "inet://[::1]:8080/?key=value".parse().unwrap();
        assert_eq!(b.scheme, BindUriScheme::Inet);
        assert_eq!(b.host.as_str(), "::1");
        assert_eq!(b.port, Some(8080));
        assert_eq!(b.path_and_query_str(), Some("/?key=value"));
    }

    #[test]
    fn display_ipv6_roundtrip() {
        let input = "inet://[::1]:8080";
        let b: Bind = input.parse().unwrap();
        assert_eq!(b.to_string(), input);
    }

    #[test]
    fn display_ipv6_full_addr() {
        let b: Bind = "inet://[2001:db8::1]:443".parse().unwrap();
        assert_eq!(b.to_string(), "inet://[2001:db8::1]:443");
    }

    #[test]
    fn expand_ipv6() {
        let b: Bind = "inet://[::1]:8080".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
        assert_eq!(uris, vec!["inet://[::1]:8080/"]);
    }

    #[test]
    fn expand_ipv6_auto_port() {
        let b: Bind = "[::1]".parse().unwrap();
        let uris: Vec<_> = b.to_bind_uris([]).map(|u| u.to_string()).collect();
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("inet://[::1]:0/"));
    }

    #[test]
    fn family_ip_rejected() {
        // v4.127.0.0.1 is not a valid bind pattern
        assert!("v4.127.0.0.1:8080".parse::<Bind>().is_err());
        assert!("inet://v6.[::1]:8080".parse::<Bind>().is_err());
    }

    #[test]
    fn ipv6_host_is_ip_addr() {
        let b: Bind = "[::1]:8080".parse().unwrap();
        assert!(b.host.is_ip_addr());
        assert!(b.host.as_ip_addr().unwrap().is_ipv6());
    }

    // -- Binds tests --

    #[test]
    fn binds_new_and_deref() {
        let v = vec![
            "iface://v4.enp17s0:8080".parse::<Bind>().unwrap(),
            "127.0.0.1:443".parse::<Bind>().unwrap(),
        ];
        let binds = Binds::new(v.clone());
        // Deref to &[Bind]
        assert_eq!(binds.len(), 2);
        assert_eq!(&*binds, &v[..]);
    }

    #[test]
    fn binds_deref_mut() {
        let mut binds = Binds::new(vec!["*:8080".parse().unwrap()]);
        binds.push("127.0.0.1:443".parse().unwrap());
        assert_eq!(binds.len(), 2);
    }

    #[test]
    fn binds_from_into_vec() {
        let v = vec!["*:8080".parse::<Bind>().unwrap()];
        let binds: Binds = v.clone().into();
        let out: Vec<Bind> = binds.into();
        assert_eq!(out, v);
    }

    #[test]
    fn binds_to_bind_uris_no_conflict() {
        let binds = Binds::new(vec![
            "iface://v4.enp17s0:8080".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ]);
        let uris = binds.to_bind_uris(["enp17s0"]).unwrap();
        assert_eq!(uris.len(), 2);
    }

    #[test]
    fn binds_to_bind_uris_dedup() {
        // Two identical binds should produce only one URI
        let binds = Binds::new(vec![
            "127.0.0.1:8080".parse().unwrap(),
            "inet://127.0.0.1:8080".parse().unwrap(),
        ]);
        let uris = binds.to_bind_uris([]).unwrap();
        assert_eq!(uris.len(), 1);
    }

    #[test]
    fn binds_to_bind_uris_conflict_different_pq() {
        // Same target, different path-and-query → conflict
        let binds = Binds::new(vec![
            "iface://v4.enp17s0:8080/?stun=true".parse().unwrap(),
            "iface://v4.enp17s0:8080/?stun=false".parse().unwrap(),
        ]);
        let err = binds.to_bind_uris(["enp17s0"]).unwrap_err();
        assert_eq!(err.scheme, "iface".parse::<Scheme>().unwrap());
        assert!(err.to_string().contains("conflicting"));
        assert!(err.to_string().contains("stun=true"));
        assert!(err.to_string().contains("stun=false"));
    }

    #[test]
    fn binds_to_bind_uris_conflict_pq_vs_none() {
        // Same target: one with path-and-query, one without → conflict
        let binds = Binds::new(vec![
            "iface://v4.enp17s0:8080".parse().unwrap(),
            "iface://v4.enp17s0:8080/?stun=true".parse().unwrap(),
        ]);
        let err = binds.to_bind_uris(["enp17s0"]).unwrap_err();
        assert!(err.to_string().contains("conflicting"));
        assert!(err.existing.is_none());
        assert!(err.incoming.is_some());
    }

    #[test]
    fn binds_to_bind_uris_same_pq_dedup() {
        // Same target, same path-and-query → deduplicated, no conflict
        let binds = Binds::new(vec![
            "iface://v4.enp17s0:8080/?stun=true".parse().unwrap(),
            "iface://v4.enp17s0:8080/?stun=true".parse().unwrap(),
        ]);
        let uris = binds.to_bind_uris(["enp17s0"]).unwrap();
        assert_eq!(uris.len(), 1);
    }

    #[test]
    fn binds_to_bind_uris_glob_conflict() {
        // Glob expanding to same interface with different pq
        let binds = Binds::new(vec![
            "v4.en*:8080/?a=1".parse().unwrap(),
            "v4.enp17s0:8080/?a=2".parse().unwrap(),
        ]);
        let err = binds.to_bind_uris(["enp17s0"]).unwrap_err();
        assert!(err.to_string().contains("conflicting"));
    }

    #[test]
    fn binds_to_bind_uris_different_targets_ok() {
        // Different targets with different pq → no conflict
        let binds = Binds::new(vec![
            "iface://v4.enp17s0:8080/?stun=true".parse().unwrap(),
            "iface://v6.enp17s0:8080/?stun=false".parse().unwrap(),
        ]);
        let uris = binds.to_bind_uris(["enp17s0"]).unwrap();
        assert_eq!(uris.len(), 2);
    }

    #[test]
    fn binds_conflict_error_display() {
        let err = BindConflictError {
            scheme: "iface".parse().unwrap(),
            authority: "v4.enp17s0:8080".parse().unwrap(),
            existing: Some("/?stun=true".parse().unwrap()),
            incoming: Some("/?stun=false".parse().unwrap()),
        };
        assert_eq!(
            err.to_string(),
            "conflicting bindings exist for bind target `iface://v4.enp17s0:8080`: `/?stun=true` vs `/?stun=false`"
        );
    }

    #[test]
    fn binds_conflict_error_display_none_pq() {
        let err = BindConflictError {
            scheme: "inet".parse().unwrap(),
            authority: "127.0.0.1:8080".parse().unwrap(),
            existing: None,
            incoming: Some("/?key=val".parse().unwrap()),
        };
        assert_eq!(
            err.to_string(),
            "conflicting bindings exist for bind target `inet://127.0.0.1:8080`: `/` vs `/?key=val`"
        );
    }
}
