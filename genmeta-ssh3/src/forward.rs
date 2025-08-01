use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};
mod parser;
pub use ssh3_proto::forward::*;
use ssh3_proto::messages::BindAddress;

use crate::error::Error;

/// 动态转发端点
#[derive(Debug, Clone, PartialEq)]
pub struct DynamicForwardEndpoint {
    pub addresses: Vec<SocketAddr>,
}

impl FromStr for DynamicForwardEndpoint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = s.rsplit_once(':').unwrap_or(("*", s));
        let port = port
            .parse::<u16>()
            .map_err(|e| Error::DynamicForwardParse {
                endpoint: s.to_string(),
                message: format!("Invalid port `{port}`: {e}"),
                backtrace: snafu::Backtrace::capture(),
            })?;

        let addresses = match host {
            "*" | "" => vec![
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port),
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port),
            ],
            ipaddr => {
                let ipaddr = ipaddr
                    .parse::<IpAddr>()
                    .map_err(|e| Error::DynamicForwardParse {
                        endpoint: s.to_string(),
                        message: format!("Invalid host `{host}`: {e}"),
                        backtrace: snafu::Backtrace::capture(),
                    })?;
                vec![SocketAddr::new(ipaddr, port)]
            }
        };

        Ok(DynamicForwardEndpoint { addresses })
    }
}

/// 本地转发规则
#[derive(Debug, Clone, PartialEq)]
pub struct LocalForwardRule {
    pub local_addresses: Vec<BindAddress>,
    pub remote_address: BindAddress,
}

impl FromStr for LocalForwardRule {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rule = s
            .parse::<parser::LocalForwardRule>()
            .map_err(|e| Error::LocalForwardParse {
                rule: s.to_string(),
                message: format!("{e:?}"),
                backtrace: snafu::Backtrace::capture(),
            })?;

        let remote_address = match rule.remote {
            parser::RemoteEndpoint::Host { host, port } => BindAddress::Host { host, port },
            parser::RemoteEndpoint::Unix { path } => BindAddress::Unix { path },
        };

        let local_addresses = match rule.local {
            parser::LocalEndpoint::Addr(socket_addr) => vec![BindAddress::Host {
                host: socket_addr.ip().to_string(),
                port: socket_addr.port(),
            }],
            parser::LocalEndpoint::Port(port) => vec![
                BindAddress::Host {
                    host: Ipv4Addr::UNSPECIFIED.to_string(),
                    port,
                },
                BindAddress::Host {
                    host: Ipv6Addr::UNSPECIFIED.to_string(),
                    port,
                },
            ],
            parser::LocalEndpoint::Unix(path) => vec![BindAddress::Unix { path }],
        };

        Ok(LocalForwardRule {
            local_addresses,
            remote_address,
        })
    }
}

/// 远程转发规则
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteForwardRule {
    pub local_address: Option<BindAddress>,
    pub remote_addresses: Vec<BindAddress>,
}

impl FromStr for RemoteForwardRule {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rule =
            s.parse::<parser::RemoteForwardRule>()
                .map_err(|e| Error::RemoteForwardParse {
                    rule: s.to_string(),
                    message: format!("{e:?}"),
                    backtrace: snafu::Backtrace::capture(),
                })?;

        let local_address = rule.local.map(|local| match local {
            parser::RemoteEndpoint::Host { host, port } => BindAddress::Host { host, port },
            parser::RemoteEndpoint::Unix { path } => BindAddress::Unix { path },
        });

        let remote_addresses = match rule.remote {
            parser::LocalEndpoint::Addr(socket_addr) => vec![BindAddress::Host {
                host: socket_addr.ip().to_string(),
                port: socket_addr.port(),
            }],
            parser::LocalEndpoint::Port(port) => vec![
                BindAddress::Host {
                    host: Ipv4Addr::UNSPECIFIED.to_string(),
                    port,
                },
                BindAddress::Host {
                    host: Ipv6Addr::UNSPECIFIED.to_string(),
                    port,
                },
            ],
            parser::LocalEndpoint::Unix(path) => vec![BindAddress::Unix { path }],
        };

        Ok(RemoteForwardRule {
            local_address,
            remote_addresses,
        })
    }
}

impl DynamicForwardEndpoint {
    /// 获取所有地址的切片
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

impl LocalForwardRule {
    /// 获取所有本地地址和远程地址的配对
    pub fn pairs(&self) -> impl Iterator<Item = (BindAddress, BindAddress)> + '_ {
        self.local_addresses
            .iter()
            .map(|local| (local.clone(), self.remote_address.clone()))
    }
}

impl RemoteForwardRule {
    /// 获取所有本地地址和远程地址的配对
    pub fn pairs(&self) -> impl Iterator<Item = (Option<BindAddress>, BindAddress)> + '_ {
        self.remote_addresses
            .iter()
            .map(move |remote| (self.local_address.clone(), remote.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::*;

    #[test]
    fn test_dynamic_forward_endpoint_parsing() {
        // Test simple port
        let endpoint: DynamicForwardEndpoint = "8080".parse().unwrap();
        assert_eq!(endpoint.addresses.len(), 2);
        assert!(
            endpoint
                .addresses
                .contains(&SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8080))
        );
        assert!(
            endpoint
                .addresses
                .contains(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 8080))
        );

        // Test with specific IP
        let endpoint: DynamicForwardEndpoint = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(endpoint.addresses.len(), 1);
        assert_eq!(endpoint.addresses[0], "127.0.0.1:8080".parse().unwrap());

        // Test with wildcard
        let endpoint: DynamicForwardEndpoint = "*:8080".parse().unwrap();
        assert_eq!(endpoint.addresses.len(), 2);
    }

    #[test]
    fn test_local_forward_rule_parsing() {
        // Test basic local forward
        let rule: LocalForwardRule = "8080:example.com:80".parse().unwrap();
        assert_eq!(rule.local_addresses.len(), 2); // IPv4 and IPv6 unspecified
        assert_eq!(
            rule.remote_address,
            ssh3_proto::messages::BindAddress::Host {
                host: "example.com".to_string(),
                port: 80
            }
        );

        // Test iterator functionality
        let pairs: Vec<_> = rule.pairs().collect();
        assert_eq!(pairs.len(), 2);

        // Test with specific bind address
        let rule: LocalForwardRule = "127.0.0.1:8080:example.com:80".parse().unwrap();
        assert_eq!(rule.local_addresses.len(), 1);
        assert_eq!(
            rule.local_addresses[0],
            ssh3_proto::messages::BindAddress::Host {
                host: "127.0.0.1".to_string(),
                port: 8080
            }
        );

        // Test iterator functionality with single address
        let pairs: Vec<_> = rule.pairs().collect();
        assert_eq!(pairs.len(), 1);
    }

    #[test]
    fn test_remote_forward_rule_parsing() {
        // Test SOCKS mode (no local endpoint)
        let rule: RemoteForwardRule = "8080".parse().unwrap();
        assert_eq!(rule.local_address, None);
        assert_eq!(rule.remote_addresses.len(), 2); // IPv4 and IPv6 unspecified

        // Test iterator functionality
        let pairs: Vec<_> = rule.pairs().collect();
        assert_eq!(pairs.len(), 2);
        // All pairs should have None as local address
        assert!(pairs.iter().all(|(local, _)| local.is_none()));

        // Test with local endpoint
        let rule: RemoteForwardRule = "8080:localhost:3000".parse().unwrap();
        assert_eq!(
            rule.local_address,
            Some(ssh3_proto::messages::BindAddress::Host {
                host: "localhost".to_string(),
                port: 3000
            })
        );

        // Test iterator with local endpoint
        let pairs: Vec<_> = rule.pairs().collect();
        assert_eq!(pairs.len(), 2); // Should still have IPv4 and IPv6 remote addresses
        // All pairs should have the same local address
        assert!(pairs.iter().all(|(local, _)| local.is_some()));
    }
}
