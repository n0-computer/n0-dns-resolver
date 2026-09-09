//! Reading the host system's DNS configuration.
//!
//! The source is platform-specific: `/etc/resolv.conf` on Unix, the
//! SystemConfiguration framework on Apple platforms, the network adapters on
//! Windows, and a Java Native Interface (JNI) call on Android. The per-platform
//! readers live in the submodules; this module dispatches to them via
//! [`read_system`]. The [`Config`] they produce lives in [`crate::config`].

use tracing::warn;

use super::{DnsProtocol, Nameserver, config::Config};

/// Parses a nameserver address that may carry an IPv6 zone id.
///
/// Accepts the forms the platform readers see: a bare address (`8.8.8.8`,
/// `fe80::1`), one with a port (`8.8.8.8:5353`, `[::1]:5353`), and either of
/// those with a zone (`fe80::1%eth0`, `fe80::1%2`, `[fe80::1%eth0]:5353`).
/// `default_port` is used when no port is given.
///
/// The zone is the point of this. A router that advertises a link-local
/// resolver over RDNSS is the whole DNS configuration on an IPv6-only network,
/// and `fe80::1` is ambiguous without knowing which interface it is on:
/// `sin6_scope_id` in the destination address is exactly what selects that, so
/// dropping it leaves an address that can never be reached. std parses only the
/// bracketed numeric form, hence the hand-rolled split here.
///
/// Returns `None` when the address does not parse, or when a named zone does
/// not correspond to an interface on this host.
///
/// Only the readers that see addresses as text need this. Windows takes the
/// zone from the adapter an address came from, and Android from `getScopeId`.
#[cfg(all(unix, not(target_os = "android")))]
pub(crate) fn parse_nameserver_addr(text: &str, default_port: u16) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr, SocketAddrV6};

    // `[addr]:port`, which std handles itself for a numeric zone.
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr);
    }
    // `[addr%zone]:port` with a named zone: unwrap the brackets and recurse on
    // the address, then apply the port that was outside them.
    if let Some(rest) = text.strip_prefix('[')
        && let Some((inner, port)) = rest.rsplit_once("]:")
    {
        let port = port.parse().ok()?;
        return parse_nameserver_addr(inner, port);
    }
    // `addr:port` for IPv4, or a bare address, both without a zone.
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    // What is left is a bare scoped address, `addr%zone`.
    let (ip, zone) = text.split_once('%')?;
    let ip = ip.parse().ok()?;
    let scope_id = parse_zone_id(zone)?;
    Some(SocketAddr::V6(SocketAddrV6::new(
        ip,
        default_port,
        0,
        scope_id,
    )))
}

/// Resolves an IPv6 zone to its numeric scope id.
///
/// A zone is written either as the index itself or as an interface name, which
/// is what `/etc/resolv.conf` and the Apple dynamic store both carry.
#[cfg(all(unix, not(target_os = "android")))]
fn parse_zone_id(zone: &str) -> Option<u32> {
    if let Ok(index) = zone.parse::<u32>() {
        return Some(index);
    }
    if_nametoindex(zone)
}

/// Returns the interface index for `name`, or `None` if there is no such interface.
#[cfg(all(unix, not(target_os = "android")))]
fn if_nametoindex(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `if_nametoindex` reads the NUL-terminated string it is given and
    // writes nothing. `CString` guarantees the NUL, and the pointer is valid
    // for the length of this call because `name` outlives it. The call returns
    // 0 for an unknown interface, which is never a valid index.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(any(target_os = "android", doc))]
mod android;
#[cfg(target_vendor = "apple")]
mod apple;
mod hosts;
#[cfg(all(unix, not(any(target_os = "android", target_vendor = "apple"))))]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "android", doc))]
pub use android::install_android_jni_context;
#[cfg(target_os = "android")]
use android::read_system_dns;
#[cfg(target_vendor = "apple")]
use apple::read_system_dns;
pub(crate) use hosts::Hosts;
#[cfg(all(unix, not(any(target_os = "android", target_vendor = "apple"))))]
use unix::read_system_dns;
#[cfg(windows)]
use windows::read_system_dns;

/// Reads the host system's DNS configuration using the platform-specific reader.
///
/// A reader failure (a missing or unreadable `/etc/resolv.conf`, an
/// uninitialized JNI context on Android) is logged and yields an otherwise-empty
/// configuration, so the resolver falls back to public resolvers. The hosts file
/// is still read in that case, since a missing resolv.conf does not imply a
/// missing hosts file.
pub(crate) fn read_system() -> Config {
    match read_system_dns() {
        Ok(config) => config,
        Err(err) => {
            warn!(%err, "failed to read system DNS configuration, using fallback");
            Config {
                hosts: Hosts::from_system(),
                ..Default::default()
            }
        }
    }
}
