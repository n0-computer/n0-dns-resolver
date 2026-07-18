//! Integration test that resolves a real name over DNS-over-HTTPS, run both
//! natively and on the browser wasm target.
//!
//! It uses the same `test` macro on both: `tokio::test` natively and
//! `wasm_bindgen_test` on wasm. DoH is the only transport available on wasm, so
//! the test needs the `transport-https` feature and is empty without it. It hits
//! the real Cloudflare DoH endpoint, so it requires network access.

#![cfg(transport_https)]

use n0_dns_resolver::{DnsProtocol, DnsResolver};
#[cfg(not(wasm_browser))]
use tokio::test;
#[cfg(wasm_browser)]
use wasm_bindgen_test::wasm_bindgen_test as test;

/// Resolves `n0.computer` over DNS-over-HTTPS against Cloudflare and checks it
/// returns at least one IPv4 address.
#[test]
async fn resolve_n0_computer_over_doh() {
    #[cfg(wasm_browser)]
    console_error_panic_hook::set_once();

    let resolver = DnsResolver::builder()
        .without_system_defaults()
        .disable_fallback()
        .nameserver_with_name(
            "1.1.1.1:443".parse().expect("valid socket addr"),
            DnsProtocol::Https,
            "cloudflare-dns.com",
        )
        .build();

    let addrs: Vec<_> = resolver
        .lookup_ipv4("n0.computer".to_string())
        .await
        .expect("resolving n0.computer over DoH")
        .collect();
    assert!(
        !addrs.is_empty(),
        "n0.computer should resolve to an IPv4 address"
    );
}
