# n0-dns-resolver

A small async DNS stub resolver built on [`simple-dns`] and tokio, used in
[iroh].

It resolves DNS records against the system's configured nameservers 
(or an explicit list), and is meant to be a lightweight, dependency-light
yet fully-featured DNS resolver. It does not perform recursive resolution.

## Features

- Reads the system DNS configuration: `/etc/resolv.conf` on Unix, the
  SystemConfiguration framework on Apple platforms, the network adapters on
  Windows, and a JNI call on Android. The system nameservers form a primary
  tier; a fallback tier of public resolvers (Cloudflare, Google, Quad9) is
  queried only when the primary tier cannot answer.
- Consults the system hosts file (`/etc/hosts` and the Windows equivalent)
  ahead of the network.
- Follows `CNAME` chains, applies `search`/`ndots` expansion, and honours TTLs
  with a small positive cache.
- Races nameservers happy-eyeballs style, ordered by measured round-trip time,
  and falls back from UDP to TCP on truncation.
- With a crypto provider enabled, also speaks DNS-over-TLS and
  DNS-over-HTTPS, pooling and reusing connections.

It does not do negative caching. DNSSEC validation is available as an opt-in
feature; see [DNSSEC validation](#dnssec-validation) below.

## Usage

```rust,no_run
use std::net::SocketAddr;

use n0_dns_resolver::{DnsProtocol, SimpleDnsResolver};

# async fn run() -> Result<(), n0_dns_resolver::Error> {
// Cross-platform defaults: the system configuration, then the public-resolver
// fallback.
let resolver = SimpleDnsResolver::new();
let addrs: Vec<_> = resolver.lookup_ipv4("example.com".to_string()).await?.collect();

// Or query a single explicit nameserver, with no system config and no fallback.
let ns: SocketAddr = "1.1.1.1:53".parse().unwrap();
let resolver = SimpleDnsResolver::builder()
    .without_system_defaults()
    .disable_fallback()
    .nameserver(ns, DnsProtocol::Udp)
    .build();
# Ok(())
# }
```

By default the fallback tier is used only when the primary nameservers fail or
time out. Change that on the builder: `always_use_fallback` races the
fallback alongside the primary servers, `disable_fallback` removes it, and
`fallback_nameservers` replaces the default public resolvers with your own.

## Feature flags

- `tls-ring`: enables DNS-over-TLS and DNS-over-HTTPS using the `ring` crypto
  provider.
- `tls-aws-lc-rs`: the same, using the `aws-lc-rs` provider.
- `dnssec`: enables DNSSEC validation (see below). Pulls in `ring` for the
  signature and digest primitives.

None is enabled by default; without a crypto provider the resolver speaks plain
DNS over UDP and TCP only, and without `dnssec` it performs no validation.

## DNSSEC validation

With the `dnssec` feature enabled, the builder's `validate_dnssec` turns on
DNSSEC validation. Every answer is then checked against the chain of trust from
the embedded IANA root key-signing keys down to the signing zone, and a lookup
returns an error unless the answer is provably secure.

Validation is fail-closed. It verifies the RRSIG signatures over the answer
RRset (RSA/SHA-256 and RSA/SHA-512, ECDSA P-256 and P-384, and Ed25519), walks
the DS and DNSKEY records up to the root, and uses NSEC and NSEC3 records to
prove wildcard expansions, insecure unsigned delegations, and NODATA denials.
Anything it cannot prove secure is rejected.

The validator is deliberately strict and covers the common signed-lookup case
rather than being a full recursive validator. Its limitations:

- It requires answers to be secure. An unsigned name, or a negative answer it
  cannot authenticate, is rejected rather than returned, so enable validation
  only for names you expect to be signed.
- A NODATA answer (the name exists but lacks the queried type) is authenticated
  against the signing zone's NSEC or NSEC3 and accepted only when the denial is
  proven. NXDOMAIN is surfaced as an error before validation runs, so it is not
  authenticated, though the NSEC and NSEC3 proof code for it is present and
  tested.
- Only the final answer RRset is validated. CNAME hops are followed but not
  each checked individually.
- The root trust anchors are compiled in (KSK-2017 and KSK-2024), so a build
  must be updated after a root key rollover.
- Deprecated algorithms (RSA/SHA-1 and DSA) are unsupported, and RSA keys
  shorter than 2048 bits are rejected, which can reject zones still on 1024-bit
  keys.
- NSEC3 opt-out is honoured only for insecure delegations, empty non-terminal
  NODATA is not proven, and NSEC3 records above 100 iterations are skipped.


## License

Copyright 2025 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[`simple-dns`]: https://docs.rs/simple-dns
[iroh]: https://github.com/n0-computer/iroh
