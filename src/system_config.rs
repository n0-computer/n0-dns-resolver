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
/// Accepts `8.8.8.8`, `fe80::1`, `8.8.8.8:5353`, `[::1]:5353`, `fe80::1%eth0`,
/// `fe80::1%2` and `[fe80::1%eth0]:5353`. `default_port` applies when unset.
///
/// The zone is the point: `sin6_scope_id` is what selects the interface a
/// link-local resolver is on, so dropping it leaves an unreachable address. std
/// parses only the bracketed numeric form, hence the hand-rolled split.
///
/// Returns `None` when the address does not parse or names no local interface.
/// Windows takes the zone from the adapter instead, and Android from
/// `getScopeId`.
#[cfg(all(unix, not(target_os = "android")))]
pub(crate) fn parse_nameserver_addr(text: &str, default_port: u16) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr, SocketAddrV6};

    // std handles `[addr]:port`, including a numeric zone.
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr);
    }
    // `[addr%zone]:port` with a named zone.
    if let Some(rest) = text.strip_prefix('[')
        && let Some((inner, port)) = rest.rsplit_once("]:")
    {
        let port = port.parse().ok()?;
        return parse_nameserver_addr(inner, port);
    }
    // A bare address, or IPv4 with a port.
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    // `addr%zone`.
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

/// Resolves an IPv6 zone, written as an index or an interface name, to its id.
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
    // SAFETY: reads the NUL-terminated string and writes nothing. `CString`
    // guarantees the NUL and outlives the call. Returns 0 if unknown.
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
