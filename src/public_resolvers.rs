//! The public DNS resolvers offered as ready-made fallback nameservers.
//!
//! [`Provider`] names one public resolver operator and hands out its addresses
//! and nameservers; it holds no ordering policy beyond "primary address first".
//! [`Nameserver::interleave`] merges per-provider lists round-robin, and
//! [`default_order`] is this crate's opinionated order for a selection of
//! providers — the one [`Builder::default_fallback_nameservers`] installs.
//!
//! ```
//! use n0_dns_resolver::{
//!     DnsProtocol, Nameserver,
//!     public_resolvers::{self, Provider},
//! };
//!
//! // This crate's order for two providers.
//! let servers = public_resolvers::default_order(vec![Provider::Quad9, Provider::Cloudflare]);
//!
//! // Or pick the transport and the order yourself: DNS-over-TLS only.
//! let servers = Nameserver::interleave([
//!     Provider::Quad9.nameservers(DnsProtocol::Tls),
//!     Provider::Cloudflare.nameservers(DnsProtocol::Tls),
//! ]);
//! ```
//!
//! [`Builder::default_fallback_nameservers`]: crate::Builder::default_fallback_nameservers

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{DnsProtocol, Nameserver};

/// A public DNS resolver operator.
///
/// Each provider runs an anycast service on two IPv4 and two IPv6 addresses,
/// reachable over every [`DnsProtocol`] this crate speaks. The encrypted
/// entries are addressed by IP (see `transport::https_query`): all three
/// providers list the anycast IPs used here as `iPAddress` SANs in their
/// certificates, so IP-addressed DoT and DoH validate without a hostname.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Provider {
    /// Cloudflare's `1.1.1.1` resolver.
    Cloudflare,
    /// Google Public DNS, `8.8.8.8`.
    Google,
    /// Quad9's `9.9.9.9` resolver.
    Quad9,
}

impl Provider {
    /// Every provider this crate knows about.
    pub const ALL: &'static [Provider] = &[Provider::Cloudflare, Provider::Google, Provider::Quad9];

    /// The provider's IPv4 addresses, primary first.
    fn ipv4_addrs(self) -> [Ipv4Addr; 2] {
        match self {
            Provider::Cloudflare => [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
            Provider::Google => [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            Provider::Quad9 => [Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
        }
    }

    /// The provider's IPv6 addresses, primary first.
    fn ipv6_addrs(self) -> [Ipv6Addr; 2] {
        match self {
            Provider::Cloudflare => [
                Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
                Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
            ],
            Provider::Google => [
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
            ],
            Provider::Quad9 => [
                Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe),
                Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0009),
            ],
        }
    }

    /// The provider's nameservers reachable over `protocol`, ordered IPv4
    /// primary, IPv6 primary, IPv4 secondary, IPv6 secondary.
    ///
    /// All three providers answer on every protocol this crate speaks, so the
    /// list is always four entries long. It is empty for a provider that does
    /// not offer `protocol`.
    pub fn nameservers(self, protocol: DnsProtocol) -> Vec<Nameserver> {
        let [v4_primary, v4_secondary] = self.ipv4_addrs().map(IpAddr::V4);
        let [v6_primary, v6_secondary] = self.ipv6_addrs().map(IpAddr::V6);
        [v4_primary, v6_primary, v4_secondary, v6_secondary]
            .into_iter()
            .map(|ip| Nameserver::new(SocketAddr::new(ip, protocol.port()), protocol))
            .collect()
    }
}

/// Returns this crate's default nameserver order for `providers`.
///
/// This is the order [`Builder::default_fallback_nameservers`] installs, over
/// [`Provider::ALL`]. It is one opinion, not the only sensible one; the pieces
/// it is assembled from are public, so a caller who disagrees can build their
/// own order with [`Provider::nameservers`] and [`Nameserver::interleave`].
///
/// The opinion is this. Plain DNS across the providers, round-robin, comes
/// first, because on a working network UDP answers in a few milliseconds. But
/// the resolver keeps only `MAX_CONCURRENT_QUERIES` (3) attempts in flight, and
/// a nameserver that silently drops UDP/53 holds its slot for `UDP_TIMEOUT`
/// plus the TCP retry behind it — several seconds. Three UDP entries would
/// therefore fill the first raced wave and stall every encrypted attempt behind
/// them. So one DNS-over-HTTPS entry per provider is spliced in after the first
/// two UDP entries, where it lands inside that first wave: on a filtered
/// network DoH is racing within 200ms, and on a working network the UDP entries
/// have answered long before the staggered DoH attempts start. The resolver
/// tracks per-server round-trip time, so whatever works on the current network
/// floats to the front from the second lookup onwards.
///
/// Duplicate providers are not filtered; pass each one once.
///
/// [`Builder::default_fallback_nameservers`]: crate::Builder::default_fallback_nameservers
pub fn default_order(providers: Vec<Provider>) -> Vec<Nameserver> {
    #[cfg_attr(not(transport_https), allow(unused_mut))]
    let mut servers =
        Nameserver::interleave(providers.iter().map(|p| p.nameservers(DnsProtocol::Udp)));
    // One DoH entry per provider, at the provider's primary IPv4 address,
    // placed just inside the first raced wave.
    #[cfg(transport_https)]
    {
        let doh: Vec<Nameserver> = providers
            .iter()
            .filter_map(|p| p.nameservers(DnsProtocol::Https).into_iter().next())
            .collect();
        let at = servers.len().min(2);
        servers.splice(at..at, doh);
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default order over every provider is the crate's default fallback
    /// list. Pinned in full: it is load-bearing (see [`default_order`])
    /// and easy to perturb by accident when the assembly changes.
    #[test]
    fn default_order_for_all_providers() {
        let actual: Vec<String> = default_order(Provider::ALL.to_vec())
            .iter()
            .map(|ns| format!("{} {:?}", ns.addr(), ns.protocol()))
            .collect();
        let expected = [
            "1.1.1.1:53 Udp",
            "8.8.8.8:53 Udp",
            #[cfg(transport_https)]
            "1.1.1.1:443 Https",
            #[cfg(transport_https)]
            "8.8.8.8:443 Https",
            #[cfg(transport_https)]
            "9.9.9.9:443 Https",
            "9.9.9.9:53 Udp",
            "[2606:4700:4700::1111]:53 Udp",
            "[2001:4860:4860::8888]:53 Udp",
            "[2620:fe::fe]:53 Udp",
            "1.0.0.1:53 Udp",
            "8.8.4.4:53 Udp",
            "149.112.112.112:53 Udp",
            "[2606:4700:4700::1001]:53 Udp",
            "[2001:4860:4860::8844]:53 Udp",
            "[2620:fe::9]:53 Udp",
        ];
        assert_eq!(actual, expected);
    }

    /// A selection of one provider still yields all four of its addresses, and
    /// nothing from the others.
    #[test]
    fn single_provider_selection_is_self_contained() {
        let servers = default_order(vec![Provider::Quad9]);
        let ips: Vec<IpAddr> = servers.iter().map(|ns| ns.addr().ip()).collect();
        for addr in Provider::Quad9.ipv4_addrs() {
            assert!(ips.contains(&IpAddr::V4(addr)));
        }
        for addr in Provider::Quad9.ipv6_addrs() {
            assert!(ips.contains(&IpAddr::V6(addr)));
        }
        assert!(!ips.contains(&IpAddr::V4(Provider::Google.ipv4_addrs()[0])));
    }

    /// Every protocol yields four entries on the provider's own addresses, at
    /// the port that protocol is served on.
    #[test]
    fn nameservers_per_protocol_cover_all_addresses() {
        let protocols = [
            DnsProtocol::Udp,
            DnsProtocol::Tcp,
            #[cfg(transport_tls)]
            DnsProtocol::Tls,
            #[cfg(transport_https)]
            DnsProtocol::Https,
        ];
        for &provider in Provider::ALL {
            for protocol in protocols {
                let servers = provider.nameservers(protocol);
                assert_eq!(servers.len(), 4, "{provider:?} {protocol:?}");
                assert!(servers.iter().all(|ns| ns.addr().port() == protocol.port()));
                assert!(servers.iter().all(|ns| ns.protocol() == protocol));
                assert_eq!(servers[0].addr().ip(), IpAddr::V4(provider.ipv4_addrs()[0]));
            }
        }
    }

    /// DoH must land in the first raced wave (`MAX_CONCURRENT_QUERIES`, 3),
    /// otherwise a network that silently drops UDP/53 stalls it behind several
    /// seconds of UDP timeout. This has to hold for a selection of any size,
    /// since callers pick their own providers.
    #[cfg(transport_https)]
    #[test]
    fn doh_lands_in_first_wave() {
        for count in 1..=Provider::ALL.len() {
            let servers = default_order(Provider::ALL[..count].to_vec());
            let wave = &servers[..3.min(servers.len())];
            assert!(
                wave.iter().any(|ns| ns.protocol() == DnsProtocol::Https),
                "expected a DoH entry within the first 3 of {count} providers, got {wave:?}",
            );
        }
    }
}
