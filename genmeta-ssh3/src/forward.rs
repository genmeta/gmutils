//! CLI forward rule types with OpenSSH-compatible syntax.
//!
//! Each type implements [`FromStr`] (via PEG parser) for use with clap's
//! `#[arg]` derive. The syntax follows OpenSSH's `-L`, `-R`, `-D` options.
//!
//! ## Dynamic forward (`-D`)
//!
//! ```text
//! [bind_address:]port
//! ```
//!
//! ## Local forward (`-L`)
//!
//! ```text
//! [bind_address:]port:host:hostport
//! [bind_address:]port:remote_socket
//! local_socket:host:hostport
//! local_socket:remote_socket
//! ```
//!
//! ## Remote forward (`-R`)
//!
//! ```text
//! [bind_address:]port:host:hostport
//! [bind_address:]port:local_socket
//! remote_socket:host:hostport
//! remote_socket:local_socket
//! [bind_address:]port              (dynamic/SOCKS)
//! ```

use std::fmt;
use std::str::FromStr;

/// A socket address: either TCP `host:port` or a Unix socket path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddr {
    Tcp { host: String, port: u16 },
    Unix { path: String },
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { host, port } => write!(f, "{host}:{port}"),
            Self::Unix { path } => write!(f, "{path}"),
        }
    }
}

/// A bind endpoint: optional address with a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindEndpoint {
    pub host: Option<String>,
    pub port: u16,
}

impl fmt::Display for BindEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Some(host) => write!(f, "{host}:{}", self.port),
            None => write!(f, "{}", self.port),
        }
    }
}

/// Dynamic port forwarding endpoint (`-D`).
///
/// Syntax: `[bind_address:]port`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicForwardEndpoint {
    pub bind: BindEndpoint,
}

impl fmt::Display for DynamicForwardEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.bind)
    }
}

impl FromStr for DynamicForwardEndpoint {
    type Err = peg::error::ParseError<peg::str::LineCol>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_parser::dynamic_forward(s)
    }
}

/// Local forward rule (`-L`).
///
/// Maps a local bind point to a remote destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalForwardRule {
    /// `[bind_address:]port:host:hostport` — TCP to TCP
    TcpToTcp {
        bind: BindEndpoint,
        dest_host: String,
        dest_port: u16,
    },
    /// `[bind_address:]port:remote_socket` — TCP to Unix
    TcpToUnix {
        bind: BindEndpoint,
        remote_socket: String,
    },
    /// `local_socket:host:hostport` — Unix to TCP
    UnixToTcp {
        local_socket: String,
        dest_host: String,
        dest_port: u16,
    },
    /// `local_socket:remote_socket` — Unix to Unix
    UnixToUnix {
        local_socket: String,
        remote_socket: String,
    },
}

impl fmt::Display for LocalForwardRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TcpToTcp { bind, dest_host, dest_port } => {
                write!(f, "{}:{dest_host}:{dest_port}", bind)
            }
            Self::TcpToUnix { bind, remote_socket } => {
                write!(f, "{}:{remote_socket}", bind)
            }
            Self::UnixToTcp { local_socket, dest_host, dest_port } => {
                write!(f, "{local_socket}:{dest_host}:{dest_port}")
            }
            Self::UnixToUnix { local_socket, remote_socket } => {
                write!(f, "{local_socket}:{remote_socket}")
            }
        }
    }
}

impl FromStr for LocalForwardRule {
    type Err = peg::error::ParseError<peg::str::LineCol>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_parser::local_forward(s)
    }
}

/// Remote forward rule (`-R`).
///
/// Maps a remote bind point to a local destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteForwardRule {
    /// `[bind_address:]port:host:hostport` — TCP to TCP
    TcpToTcp {
        bind: BindEndpoint,
        dest_host: String,
        dest_port: u16,
    },
    /// `[bind_address:]port:local_socket` — TCP to Unix
    TcpToUnix {
        bind: BindEndpoint,
        local_socket: String,
    },
    /// `remote_socket:host:hostport` — Unix to TCP
    UnixToTcp {
        remote_socket: String,
        dest_host: String,
        dest_port: u16,
    },
    /// `remote_socket:local_socket` — Unix to Unix
    UnixToUnix {
        remote_socket: String,
        local_socket: String,
    },
    /// `[bind_address:]port` — dynamic (remote SOCKS)
    Dynamic { bind: BindEndpoint },
}

impl fmt::Display for RemoteForwardRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TcpToTcp { bind, dest_host, dest_port } => {
                write!(f, "{}:{dest_host}:{dest_port}", bind)
            }
            Self::TcpToUnix { bind, local_socket } => {
                write!(f, "{}:{local_socket}", bind)
            }
            Self::UnixToTcp { remote_socket, dest_host, dest_port } => {
                write!(f, "{remote_socket}:{dest_host}:{dest_port}")
            }
            Self::UnixToUnix { remote_socket, local_socket } => {
                write!(f, "{remote_socket}:{local_socket}")
            }
            Self::Dynamic { bind } => write!(f, "{}", bind),
        }
    }
}

impl FromStr for RemoteForwardRule {
    type Err = peg::error::ParseError<peg::str::LineCol>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_parser::remote_forward(s)
    }
}

// ---------------------------------------------------------------------------
// PEG parser
// ---------------------------------------------------------------------------

peg::parser! {
    grammar forward_parser() for str {
        // A port number: 1..65535
        rule port() -> u16
            = n:$(['0'..='9']+) {?
                n.parse::<u16>().map_err(|_| "port number")
            }

        // A hostname: sequence of non-colon, non-slash characters
        rule hostname() -> &'input str
            = s:$([^ ':' | '/']+) { s }

        // A Unix socket path: starts with '/' (absolute path)
        rule unix_path() -> &'input str
            = s:$("/" [^ ':']*) { s }

        // An optional bind address before a port, e.g. "127.0.0.1:" or "*:" or empty
        // Returns (Option<host>, port)
        rule bind_endpoint() -> BindEndpoint
            // [bind_address:]port — try with address first
            = host:$([^ ':']+) ":" p:port() {?
                // Only valid if what we parsed as host is NOT a valid port on its own
                // and the remainder is a valid port
                Ok(BindEndpoint { host: Some(host.to_string()), port: p })
            }
            / p:port() {
                BindEndpoint { host: None, port: p }
            }

        // -D [bind_address:]port
        pub rule dynamic_forward() -> DynamicForwardEndpoint
            = bind:bind_endpoint() ![_] {
                DynamicForwardEndpoint { bind }
            }

        // -L rules (tried in order of specificity)
        pub rule local_forward() -> LocalForwardRule
            // local_socket:host:hostport (Unix to TCP)
            = sock:unix_path() ":" host:hostname() ":" p:port() ![_] {
                LocalForwardRule::UnixToTcp {
                    local_socket: sock.to_string(),
                    dest_host: host.to_string(),
                    dest_port: p,
                }
            }
            // local_socket:remote_socket (Unix to Unix)
            / sock:unix_path() ":" remote:unix_path() ![_] {
                LocalForwardRule::UnixToUnix {
                    local_socket: sock.to_string(),
                    remote_socket: remote.to_string(),
                }
            }
            // [bind_address:]port:host:hostport (TCP to TCP)
            / bind:bind_endpoint() ":" host:hostname() ":" p:port() ![_] {
                LocalForwardRule::TcpToTcp {
                    bind,
                    dest_host: host.to_string(),
                    dest_port: p,
                }
            }
            // [bind_address:]port:remote_socket (TCP to Unix)
            / bind:bind_endpoint() ":" remote:unix_path() ![_] {
                LocalForwardRule::TcpToUnix {
                    bind,
                    remote_socket: remote.to_string(),
                }
            }

        // -R rules (tried in order of specificity)
        pub rule remote_forward() -> RemoteForwardRule
            // remote_socket:host:hostport (Unix to TCP)
            = sock:unix_path() ":" host:hostname() ":" p:port() ![_] {
                RemoteForwardRule::UnixToTcp {
                    remote_socket: sock.to_string(),
                    dest_host: host.to_string(),
                    dest_port: p,
                }
            }
            // remote_socket:local_socket (Unix to Unix)
            / sock:unix_path() ":" local:unix_path() ![_] {
                RemoteForwardRule::UnixToUnix {
                    remote_socket: sock.to_string(),
                    local_socket: local.to_string(),
                }
            }
            // [bind_address:]port:host:hostport (TCP to TCP)
            / bind:bind_endpoint() ":" host:hostname() ":" p:port() ![_] {
                RemoteForwardRule::TcpToTcp {
                    bind,
                    dest_host: host.to_string(),
                    dest_port: p,
                }
            }
            // [bind_address:]port:local_socket (TCP to Unix)
            / bind:bind_endpoint() ":" local:unix_path() ![_] {
                RemoteForwardRule::TcpToUnix {
                    bind,
                    local_socket: local.to_string(),
                }
            }
            // [bind_address:]port (dynamic/SOCKS)
            / bind:bind_endpoint() ![_] {
                RemoteForwardRule::Dynamic { bind }
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Dynamic forward ----

    #[test]
    fn dynamic_port_only() {
        let d: DynamicForwardEndpoint = "1080".parse().unwrap();
        assert_eq!(d.bind, BindEndpoint { host: None, port: 1080 });
    }

    #[test]
    fn dynamic_with_bind_address() {
        let d: DynamicForwardEndpoint = "127.0.0.1:1080".parse().unwrap();
        assert_eq!(
            d.bind,
            BindEndpoint { host: Some("127.0.0.1".into()), port: 1080 }
        );
    }

    #[test]
    fn dynamic_wildcard() {
        let d: DynamicForwardEndpoint = "*:9090".parse().unwrap();
        assert_eq!(
            d.bind,
            BindEndpoint { host: Some("*".into()), port: 9090 }
        );
    }

    // ---- Local forward ----

    #[test]
    fn local_tcp_to_tcp() {
        let l: LocalForwardRule = "8080:example.com:80".parse().unwrap();
        assert_eq!(
            l,
            LocalForwardRule::TcpToTcp {
                bind: BindEndpoint { host: None, port: 8080 },
                dest_host: "example.com".into(),
                dest_port: 80,
            }
        );
    }

    #[test]
    fn local_tcp_to_tcp_with_bind() {
        let l: LocalForwardRule = "127.0.0.1:8080:example.com:80".parse().unwrap();
        assert_eq!(
            l,
            LocalForwardRule::TcpToTcp {
                bind: BindEndpoint { host: Some("127.0.0.1".into()), port: 8080 },
                dest_host: "example.com".into(),
                dest_port: 80,
            }
        );
    }

    #[test]
    fn local_tcp_to_unix() {
        let l: LocalForwardRule = "8080:/var/run/app.sock".parse().unwrap();
        assert_eq!(
            l,
            LocalForwardRule::TcpToUnix {
                bind: BindEndpoint { host: None, port: 8080 },
                remote_socket: "/var/run/app.sock".into(),
            }
        );
    }

    #[test]
    fn local_unix_to_tcp() {
        let l: LocalForwardRule = "/tmp/local.sock:example.com:80".parse().unwrap();
        assert_eq!(
            l,
            LocalForwardRule::UnixToTcp {
                local_socket: "/tmp/local.sock".into(),
                dest_host: "example.com".into(),
                dest_port: 80,
            }
        );
    }

    #[test]
    fn local_unix_to_unix() {
        let l: LocalForwardRule = "/tmp/local.sock:/var/run/remote.sock".parse().unwrap();
        assert_eq!(
            l,
            LocalForwardRule::UnixToUnix {
                local_socket: "/tmp/local.sock".into(),
                remote_socket: "/var/run/remote.sock".into(),
            }
        );
    }

    // ---- Remote forward ----

    #[test]
    fn remote_tcp_to_tcp() {
        let r: RemoteForwardRule = "8080:localhost:3000".parse().unwrap();
        assert_eq!(
            r,
            RemoteForwardRule::TcpToTcp {
                bind: BindEndpoint { host: None, port: 8080 },
                dest_host: "localhost".into(),
                dest_port: 3000,
            }
        );
    }

    #[test]
    fn remote_tcp_to_unix() {
        let r: RemoteForwardRule = "8080:/var/run/app.sock".parse().unwrap();
        assert_eq!(
            r,
            RemoteForwardRule::TcpToUnix {
                bind: BindEndpoint { host: None, port: 8080 },
                local_socket: "/var/run/app.sock".into(),
            }
        );
    }

    #[test]
    fn remote_dynamic() {
        let r: RemoteForwardRule = "8080".parse().unwrap();
        assert_eq!(
            r,
            RemoteForwardRule::Dynamic {
                bind: BindEndpoint { host: None, port: 8080 },
            }
        );
    }

    #[test]
    fn remote_unix_to_tcp() {
        let r: RemoteForwardRule = "/tmp/remote.sock:localhost:3000".parse().unwrap();
        assert_eq!(
            r,
            RemoteForwardRule::UnixToTcp {
                remote_socket: "/tmp/remote.sock".into(),
                dest_host: "localhost".into(),
                dest_port: 3000,
            }
        );
    }

    // ---- Display round-trip ----

    #[test]
    fn dynamic_display() {
        let d: DynamicForwardEndpoint = "127.0.0.1:1080".parse().unwrap();
        assert_eq!(d.to_string(), "127.0.0.1:1080");
    }

    #[test]
    fn local_display() {
        let l: LocalForwardRule = "8080:example.com:80".parse().unwrap();
        assert_eq!(l.to_string(), "8080:example.com:80");
    }

    #[test]
    fn remote_display() {
        let r: RemoteForwardRule = "0.0.0.0:2222:localhost:22".parse().unwrap();
        assert_eq!(r.to_string(), "0.0.0.0:2222:localhost:22");
    }
}
