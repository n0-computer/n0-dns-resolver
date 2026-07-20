//! A small async DNS stub resolver built on [`simple-dns`] and tokio.
//!
//! The main export is [`DnsResolver`], a stub resolver that reads the
//! system DNS configuration (or an explicit nameserver list), resolves the
//! common record kinds (see [`RecordKind`]) through
//! [`DnsResolver::lookup_record`], follows CNAME chains, caches positive
//! results, races nameservers happy-eyeballs style, and falls back to public
//! resolvers. It speaks plain DNS over UDP and TCP, and, with the
//! `transport-tls` and `transport-https` features, DNS-over-TLS and
//! DNS-over-HTTPS.
//!
//! Construct a resolver with [`DnsResolver::new`] for cross-platform
//! defaults, or with [`DnsResolver::builder`] to configure the nameservers
//! and the fallback behavior. See [`Builder`] for the available settings.
//!
//! # Browser wasm
//!
//! On the `wasm32-unknown-unknown` target only DNS-over-HTTPS is available: the
//! browser has no UDP/TCP sockets and no native TLS stack, so DoH goes through
//! reqwest's fetch backend, where the browser performs DNS resolution and TLS.
//! Build with `--no-default-features --features transport-https` (the default
//! features pull in the native TLS stack, which does not compile on wasm), and
//! set `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'` when building the
//! consuming binary. Configure DoH nameservers explicitly; a UDP or TCP
//! nameserver returns an unsupported-transport error.
//!
//! [`simple-dns`]: https://docs.rs/simple-dns
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(n0_dns_resolver_docsrs, feature(doc_cfg))]

mod builder;
mod config;
mod error;
mod records;
mod resolver;
mod system_config;

#[cfg(test)]
mod tests;

#[cfg(any(target_os = "android", doc))]
pub use self::system_config::install_android_jni_context;
pub use self::{
    builder::{Builder, DnsProtocol, FallbackMode, Nameserver},
    error::{Error, ResponseCode},
    records::{
        CaaRecordData, HttpsRecord, MxRecordData, Record, RecordKind, SrvRecordData,
        SvcbRecordData, TxtRecordData,
    },
    resolver::{DnsResolver, TransportError},
};
