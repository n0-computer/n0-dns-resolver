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

It does not currently perform DNSSEC validation or negative caching.

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

Neither is enabled by default; without a crypto provider the resolver speaks
plain DNS over UDP and TCP only.


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
