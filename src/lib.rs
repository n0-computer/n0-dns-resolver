//! A small async DNS stub resolver built on [`simple-dns`] and tokio.
//!
//! The main export is [`SimpleDnsResolver`], a stub resolver that reads the
//! system DNS configuration (or an explicit nameserver list), resolves the
//! common record kinds (see [`RecordKind`]) through
//! [`SimpleDnsResolver::lookup_record`], follows CNAME chains, caches positive
//! results, races nameservers happy-eyeballs style, and falls back to public
//! resolvers. It
//! speaks plain DNS over UDP and TCP, and (with a crypto provider enabled)
//! DNS-over-TLS and DNS-over-HTTPS.
//!
//! Construct a resolver with [`SimpleDnsResolver::new`] for cross-platform
//! defaults, or with [`SimpleDnsResolver::builder`] to configure the nameservers
//! and the fallback behavior. See [`Builder`] for the available settings.
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
    error::Error,
    records::{
        CaaRecordData, HttpsRecord, MxRecordData, Record, RecordKind, SrvRecordData,
        SvcbRecordData, TxtRecordData,
    },
    resolver::SimpleDnsResolver,
};
