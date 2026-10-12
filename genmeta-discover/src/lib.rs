use std::{
    collections::{HashMap, HashSet},
    io::IsTerminal,
    string::String as BindPattern,
};

use clap::Parser;
use ddns::{
    core::parser::{
        packet::{Packet, be_packet},
        record::RData,
    },
    resolvers::DHTTP_MDNS_SERVICE_DOMAIN,
};
use socket2::{Domain, Socket, Type};
use tokio::net::UdpSocket;
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug, Clone)]
#[command(name = "discover", version, about)]
pub struct Options {
    /// Domain name to discover (e.g. _dhttp.local)
    #[arg(value_name = "DOMAIN", default_value = "")]
    domain: String,

    /// Bind patterns for local network interfaces
    #[arg(long = "interface", value_name = "bind", default_value = "*",
          hide = cfg!(not(debug_assertions)))]
    binds: Vec<BindPattern>,
}

fn domain_with_default_mdns_service(domain: &str) -> String {
    if domain.is_empty()
        || domain == DHTTP_MDNS_SERVICE_DOMAIN
        || domain.ends_with(&format!(".{DHTTP_MDNS_SERVICE_DOMAIN}"))
    {
        domain.to_owned()
    } else {
        format!("{domain}.{DHTTP_MDNS_SERVICE_DOMAIN}")
    }
}

fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (stderr, guard) = tracing_appender::non_blocking(std::io::stderr());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
                .with_writer(stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy()
                .add_directive(
                    "netlink_packet_route=error"
                        .parse()
                        .expect("BUG: static tracing directive is valid"),
                ),
        )
        .init();
    guard
}

pub async fn run(options: Options) {
    let _guard = init_tracing();

    if let Err(error) = dhttp::DhttpNetwork::init().await {
        tracing::error!(%error, "failed to initialize interfaces");
        return;
    }
    let mut sockets = Vec::new();
    for (bound, device) in dhttp::AddressBook::global().inner_bindings() {
        if !options
            .binds
            .iter()
            .any(|p| p == "*" || p == device.name() || p == &bound.ip().to_string())
        {
            continue;
        }
        match discovery_socket(bound.ip(), device.index().get()) {
            Ok(socket) => sockets.push(socket),
            Err(error) => {
                tracing::warn!(%error, device = device.name(), "failed to bind mDNS discovery")
            }
        }
    }
    let (sender, mut receiver) = tokio::sync::mpsc::channel(64);
    let mut tasks = tokio::task::JoinSet::new();
    let query = Packet::query(DHTTP_MDNS_SERVICE_DOMAIN.to_owned()).to_bytes();
    for (socket, target) in sockets {
        let sender = sender.clone();
        let query = query.clone();
        tasks.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            let mut buffer = [0u8; 9001];
            loop {
                tokio::select! {
                    _ = interval.tick() => { if let Err(error) = socket.send_to(&query, target).await { tracing::warn!(%error, "mDNS discovery query failed"); } }
                    received = socket.recv_from(&mut buffer) => {
                        let (size, source) = match received { Ok(result) => result, Err(_) => break };
                        if size > 9000 { continue; }
                        if let Ok((_, packet)) = be_packet(&buffer[..size])
                            && !packet.answers.is_empty() && sender.send((source, packet)).await.is_err() { break; }
                    }
                }
            }
        });
    }
    drop(sender);
    let with_suffix = domain_with_default_mdns_service(&options.domain);

    let matches_domain = |name: &str, domain: &str| {
        if domain.is_empty() {
            true
        } else {
            name == domain || name.ends_with(&format!(".{domain}"))
        }
    };

    let mut domain_set = HashSet::new();

    while let Some((_source, packet)) = receiver.recv().await {
        let records: HashMap<_, HashSet<_>> = packet
            .answers
            .iter()
            .filter(|a| {
                matches_domain(&a.name(), &options.domain)
                    || matches_domain(&a.name(), with_suffix.as_str())
            })
            .fold(HashMap::new(), |mut map, record| {
                map.entry(record.name().to_string())
                    .or_default()
                    .insert(record.data().clone());
                map
            });
        for (name, rdata_set) in records {
            if !domain_set.insert(name.clone()) {
                continue;
            }
            println!("Name: {name}");
            for rdata in rdata_set {
                match rdata {
                    RData::A(ip) => println!("{ip}"),
                    RData::AAAA(ip) => println!("{ip}"),
                    RData::E(ep) => println!("{ep}"),
                    _ => continue,
                }
            }
        }
    }
}

fn discovery_socket(
    ip: std::net::IpAddr,
    index: u32,
) -> std::io::Result<(UdpSocket, std::net::SocketAddr)> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
    let socket = Socket::new(
        if ip.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        None,
    )?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;
    let target = match ip {
        IpAddr::V4(ip) => {
            socket.bind(&SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 5353).into())?;
            let group = Ipv4Addr::new(224, 0, 0, 251);
            socket.join_multicast_v4(&group, &ip)?;
            socket.set_multicast_if_v4(&ip)?;
            socket.set_multicast_loop_v4(true)?;
            SocketAddr::new(group.into(), 5353)
        }
        IpAddr::V6(_) => {
            socket.set_only_v6(true)?;
            socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 5353).into())?;
            let group = "ff02::fb".parse::<Ipv6Addr>().unwrap();
            socket.join_multicast_v6(&group, index)?;
            socket.set_multicast_if_v6(index)?;
            socket.set_multicast_loop_v6(true)?;
            SocketAddrV6::new(group, 5353, 0, index).into()
        }
    };
    Ok((UdpSocket::from_std(socket.into())?, target))
}

#[cfg(test)]
mod tests {
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
}
