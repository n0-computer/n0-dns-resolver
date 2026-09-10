//! System DNS configuration from Windows network adapters.
//!
//! # Known limitations
//!
//! No split-DNS: every adapter that is up contributes to one flat tier, so a
//! LAN resolver's fast NXDOMAIN can win the race for a VPN-only name. The
//! interface metric Windows prefers by is in `ipconfig` but unread, and
//! connection-specific suffixes (DHCP option 15) are unreachable, since
//! `ipconfig` 0.3 exposes no `DnsSuffix`. Both need per-name nameserver
//! selection. hickory main has the same limitations.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use super::{Config, DnsProtocol, Hosts, Nameserver};

/// Deprecated IPv6 site-local anycast addresses still configured by Windows.
///
/// Windows still configures these site-local addresses as soon as an IPv6 loopback
/// interface is configured. We do not want to use these DNS servers, the chances of them
/// being usable are almost always close to zero, while the chance of DNS configuration
/// **only** relying on these servers and not also being configured normally are also almost
/// zero. The chance of the DNS resolver accidentally trying one of these and taking a
/// bunch of timeouts to figure out they're no good are on the other hand very high.
const WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS: [IpAddr; 3] = [
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3)),
];

/// Reads the DNS servers from the Windows network adapter configuration.
///
/// Also reads the hosts file.
pub(super) fn read_system_dns() -> Result<Config, std::io::Error> {
    let adapters = ipconfig::get_adapters().map_err(std::io::Error::other)?;

    let mut servers = Vec::new();
    for adapter in adapters {
        // Only consider adapters that are up
        if adapter.oper_status() != ipconfig::OperStatus::IfOperStatusUp {
            continue;
        }
        for dns_server in adapter.dns_servers() {
            let ip = IpAddr::from(*dns_server);
            if WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS.contains(&ip) {
                continue;
            }
            // `dns_servers()` drops the zone, so take it from the adapter; a
            // link-local resolver is unreachable without it.
            let addr =
                match ip {
                    IpAddr::V6(ip) if ip.is_unicast_link_local() => SocketAddr::V6(
                        SocketAddrV6::new(ip, DnsProtocol::Udp.port(), 0, adapter.ipv6_if_index()),
                    ),
                    ip => SocketAddr::new(ip, DnsProtocol::Udp.port()),
                };
            servers.push(Nameserver::new(addr, DnsProtocol::Udp));
        }
    }

    // Deduplicate -- multiple adapters may report the same DNS server.
    // Use a HashSet since dedup_by_key only removes consecutive duplicates.
    let mut seen = std::collections::HashSet::new();
    servers.retain(|ns| seen.insert(ns.addr));

    // Read search domains from the Windows registry (comma-separated SearchList key).
    // Falls back to the primary domain if no search list is configured.
    let search_domains = ipconfig::computer::get_search_list()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let search_domains = if search_domains.is_empty() {
        ipconfig::computer::get_domain()
            .ok()
            .flatten()
            .filter(|s| !s.is_empty())
            .into_iter()
            .collect()
    } else {
        search_domains
    };

    Ok(Config {
        nameservers: servers,
        search_domains,
        ndots: None,
        hosts: Hosts::from_system(),
    })
}
