//! System DNS configuration from the Apple SystemConfiguration framework.
//!
//! Used on all Apple platforms (macOS, iOS, tvOS, watchOS). They do not keep
//! `/etc/resolv.conf` in sync with the live resolver configuration (and on iOS
//! the sandbox hides it entirely), so reading that file (as the generic Unix
//! reader does) can miss the nameservers the system is actually using. Instead
//! we read the primary resolver from the dynamic store key
//! `State:/Network/Global/DNS`, the way the old hickory-resolver path did on
//! Apple targets. That key holds the default resolver's `ServerAddresses` and
//! `SearchDomains`.
//!
//! # Known limitations
//!
//! Supplemental (split-DNS) resolvers are not read. A split-DNS VPN publishes
//! its resolver under `State:/Network/Service/<id>/DNS` with
//! `SupplementalMatchDomains`, and configd merges those into the list that
//! `scutil --dns` and libresolv use, but they never appear in the global key.
//! So a VPN-only name is sent to the primary ISP or home resolver, reported
//! NXDOMAIN, and after escalation leaked to the public fallbacks, while `ping`
//! on the same machine resolves it.
//!
//! Honoring them means routing a name under a match domain to that resolver set
//! and no further, which needs a resolver that selects nameservers per name
//! rather than racing one tier. hickory-resolver reads only the global key too
//! (as of main, 2026-09-06), so this is not a regression against the resolver
//! this replaced; it is a deliberate follow-up.
//!
//! Note that unlike hickory, a scoped address such as `fe80::1%en0` keeps its
//! zone here rather than having it stripped: without it a link-local resolver
//! cannot be reached at all.

use std::borrow::Cow;

use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::{FromVoid, ItemRef, TCFType},
        dictionary::CFDictionary,
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
};
use tracing::warn;

use super::{Config, DnsProtocol, Hosts, Nameserver};

/// Reads the primary system DNS configuration from SystemConfiguration.
///
/// Also reads the hosts file.
pub(super) fn read_system_dns() -> Result<Config, std::io::Error> {
    let store = SCDynamicStoreBuilder::new("iroh-dns")
        .build()
        .ok_or_else(|| {
            std::io::Error::other("failed to access SystemConfiguration dynamic store")
        })?;
    let dns_cfg = store
        .get("State:/Network/Global/DNS")
        .and_then(|value| value.downcast_into::<CFDictionary>())
        .ok_or_else(|| std::io::Error::other("no DNS dictionary in SystemConfiguration"))?;

    // `ServerAddresses` carries a link-local resolver in scoped form,
    // `fe80::1%en0`, which `IpAddr::from_str` rejects outright: such an entry
    // used to be dropped with a warning, and on an IPv6-only network it may be
    // the only resolver there is. The zone is what selects the interface, so
    // keep it (see `super::parse_nameserver_addr`).
    let nameservers = read_string_array(&dns_cfg, "ServerAddresses")
        .into_iter()
        .filter_map(|s| {
            match super::parse_nameserver_addr(&s, DnsProtocol::Udp.port()) {
                Some(addr) => Some(Nameserver::new(addr, DnsProtocol::Udp)),
                None => {
                    warn!(nameserver = %s, "ignoring unparsable nameserver from SystemConfiguration");
                    None
                }
            }
        })
        .collect();

    let search_domains = read_string_array(&dns_cfg, "SearchDomains");

    Ok(Config {
        nameservers,
        search_domains,
        ndots: None,
        hosts: Hosts::from_system(),
    })
}

/// Reads a `CFArray`-of-`CFString` value from `dict` by key.
///
/// Returns an empty vector when the key is absent or holds another type.
fn read_string_array(dict: &CFDictionary, key: &'static str) -> Vec<String> {
    let Some(value) = dict.find(CFString::from_static_string(key).as_CFTypeRef()) else {
        return Vec::new();
    };
    // SAFETY: the SystemConfiguration DNS dictionary stores ServerAddresses and
    // SearchDomains as CFArrays of CFString, per the documented schema. See
    // https://developer.apple.com/documentation/systemconfiguration/kscpropnetdnsserveraddresses-swift.var
    let array: ItemRef<'_, CFArray<CFString>> = unsafe { CFArray::from_void(*value) };
    let mut out = Vec::with_capacity(array.len() as usize);
    for item in &*array {
        out.push(Cow::from(&*item).into_owned());
    }
    out
}
