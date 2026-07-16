//! Hidden fuzzing entry points for the cargo-fuzz suite under `fuzz/`.
//!
//! Each function drives arbitrary, untrusted bytes through one of the crate's
//! internal parsers and discards the result. The parsers are not public, so the
//! real work lives in `pub(crate)` shims in the modules that can reach them; the
//! functions here are the thin, out-of-crate-callable surface the fuzz targets
//! invoke. The whole module is gated behind the `fuzzing` feature, so the normal
//! build and the public API are unchanged.
//!
//! The contract every function upholds is the point of the fuzz suite: no input,
//! however malformed, may panic. A parser must return an error or an empty result
//! instead.

/// Drives arbitrary bytes through the DNS response parsers.
///
/// Covers [`parse_records`] for every record kind, the header-peek helpers that
/// run on raw datagrams, and the packet-level response checks.
pub fn parse_response(data: &[u8]) {
    crate::resolver::fuzz_parse_response(data);
}

/// Drives arbitrary bytes through the `resolv.conf` parser.
///
/// The bytes are turned into text with [`String::from_utf8_lossy`] first, since
/// the parser works on `&str`.
pub fn resolv_conf(data: &[u8]) {
    crate::system_config::fuzz_resolv_conf(data);
}

/// Drives arbitrary bytes through the hosts-file parser.
///
/// As with [`resolv_conf`], the bytes are decoded with
/// [`String::from_utf8_lossy`] before parsing.
pub fn hosts(data: &[u8]) {
    crate::system_config::fuzz_hosts(data);
}

/// Drives arbitrary bytes through the DNSSEC wire and crypto toolkit.
///
/// Parses the bytes as an NSEC3 RDATA blob and as a DNS packet, then runs the
/// canonical-form, signature, and denial-of-existence code over whatever records
/// the packet yields.
#[cfg(feature = "dnssec")]
pub fn dnssec(data: &[u8]) {
    crate::dnssec::fuzz_dnssec(data);
}
