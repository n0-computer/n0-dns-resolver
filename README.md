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
- Resolves A, AAAA, TXT, NS, SRV, MX, CAA, SVCB, and HTTPS records, follows
  `CNAME` chains, and applies `search`/`ndots` expansion.
- Caches positive results by TTL and negative results (NODATA, NXDOMAIN) per
  RFC 2308, deriving the negative TTL from the authority SOA. Optionally
  serves expired entries when every nameserver fails (RFC 8767 serve-stale)
  and floors very low TTLs, both off by default.
- Races nameservers happy-eyeballs style, ordered by measured round-trip time.
  A truncated or failed UDP query falls back to TCP on the same server, so
  lookups survive networks that block UDP/53, and a FORMERR triggers a retry
  without EDNS before the next server is tried.
- Speaks DNS-over-TLS and DNS-over-HTTPS (on by default, see feature flags),
  pooling and reusing connections.

It does not perform DNSSEC validation.

## Usage

```rust,no_run
use std::net::SocketAddr;

use n0_dns_resolver::{DnsProtocol, DnsResolver};

# async fn run() -> Result<(), n0_dns_resolver::Error> {
// Cross-platform defaults: the system configuration, then the public-resolver
// fallback.
let resolver = DnsResolver::new();
let addrs: Vec<_> = resolver.lookup_ipv4("example.com".to_string()).await?.collect();

// Or query a single explicit nameserver, with no system config and no fallback.
let ns: SocketAddr = "1.1.1.1:53".parse().unwrap();
let resolver = DnsResolver::builder()
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

Plain DNS over UDP and TCP is always available. The encrypted transports are
feature-gated:

- `transport-tls`: DNS-over-TLS, via rustls.
- `transport-https`: DNS-over-HTTPS, via reqwest with rustls.
- `tls-ring` / `tls-aws-lc-rs`: the rustls crypto provider used to build the
  default TLS client config when none is supplied on the builder.

The default features are `transport-tls`, `transport-https`, and `tls-ring`,
so DoT and DoH work out of the box. With `default-features = false` the
resolver speaks plain DNS only. Enabling a transport without a crypto
provider also works, but then a TLS client config must be supplied on the
builder.


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
