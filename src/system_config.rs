//! Reading the host system's DNS configuration.
//!
//! Reading the system DNS configuration is platform-specific: `/etc/resolv.conf`
//! on Unix, the SystemConfiguration framework on Apple platforms, the network
//! adapters on Windows, and a JNI call on Android. The per-platform readers live
//! in the submodules; this module dispatches to them via [`read_system`]. The
//! [`DnsConfig`] they produce lives in [`crate::config`].

use super::{
    DnsProtocol, Nameserver,
    config::{DNS_PORT, DnsConfig},
};

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
/// # Errors
///
/// Returns the platform reader's error when the configuration cannot be read,
/// for example a missing or unreadable `/etc/resolv.conf`, or an uninitialized
/// JNI context on Android. The caller decides how to recover; the resolver logs
/// the failure and falls back to public resolvers.
pub(crate) fn read_system() -> Result<DnsConfig, std::io::Error> {
    read_system_dns()
}

/// Drives arbitrary bytes through the `resolv.conf` parser, for the fuzz suite.
///
/// The parser lives in the Unix submodule and works on `&str`, so the bytes are
/// decoded with [`String::from_utf8_lossy`] first. On platforms without an
/// `/etc/resolv.conf` reader there is no parser to exercise, so the call decodes
/// the bytes and returns. Gated on the `fuzzing` feature.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_resolv_conf(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    #[cfg(all(unix, not(any(target_os = "android", target_vendor = "apple"))))]
    unix::fuzz_parse_resolv_conf(&text);
    #[cfg(not(all(unix, not(any(target_os = "android", target_vendor = "apple")))))]
    let _ = &text;
}

/// Drives arbitrary bytes through the hosts-file parser, for the fuzz suite.
///
/// As with [`fuzz_resolv_conf`], the bytes are decoded with
/// [`String::from_utf8_lossy`] before parsing. Gated on the `fuzzing` feature.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_hosts(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    Hosts::fuzz_parse(&text);
}
