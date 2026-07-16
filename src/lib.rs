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
#![cfg_attr(n0_dns_resolver_docsrs, feature(doc_auto_cfg))]

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use simple_dns::rdata::{SVCB, SVCParam};

mod config;
mod error;
mod resolver;
mod system_config;

#[cfg(test)]
mod tests;

#[cfg(any(target_os = "android", doc))]
pub use self::system_config::install_android_jni_context;
pub use self::{error::Error, resolver::SimpleDnsResolver};

/// Builds a [`SimpleDnsResolver`].
///
/// The default builder reads the host system's DNS configuration and, when a
/// query cannot be answered there, escalates to a set of public resolvers. Get
/// one from [`SimpleDnsResolver::builder`], adjust it with the setters, and
/// finish with [`Builder::build`].
///
/// # Nameserver tiers
///
/// Nameservers form two tiers. The *primary* tier is what the system
/// configuration and [`Builder::nameserver`] provide. The *fallback* tier
/// defaults to public resolvers (Cloudflare, Google, Quad9). By default the
/// fallback is a lower-priority tier, queried only when the primary tier cannot
/// answer. [`Builder::fallback_mode`] selects among the [`FallbackMode`]
/// variants, with [`Builder::always_use_fallback`] and
/// [`Builder::disable_fallback`] as shorthands for the two most common. Override
/// the fallback nameservers with [`Builder::fallback_nameservers`].
///
/// # Examples
///
/// ```
/// use n0_dns_resolver::SimpleDnsResolver;
///
/// // System configuration first, public resolvers as a fallback.
/// let resolver = SimpleDnsResolver::builder().build();
/// ```
#[derive(Debug, Clone)]
pub struct Builder {
    use_system_defaults: bool,
    nameservers: Vec<Nameserver>,
    fallback: FallbackMode,
    fallback_nameservers: Option<Vec<Nameserver>>,
    #[cfg(with_crypto_provider)]
    tls_client_config: Option<rustls::ClientConfig>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            use_system_defaults: true,
            nameservers: Vec::new(),
            fallback: FallbackMode::default(),
            fallback_nameservers: None,
            #[cfg(with_crypto_provider)]
            tls_client_config: None,
        }
    }
}

impl Builder {
    /// Stops the resolver from reading the host system's DNS configuration.
    ///
    /// Only the nameservers added with [`Self::nameserver`] and
    /// [`Self::nameservers`], plus any fallback tier, are then queried, and the
    /// system hosts file is not consulted.
    #[must_use]
    pub fn without_system_defaults(mut self) -> Self {
        self.use_system_defaults = false;
        self
    }

    /// Adds a primary nameserver, addressed by IP.
    ///
    /// For DoT/DoH against a server whose certificate covers a hostname rather
    /// than its IP, use [`Self::nameserver_with_name`].
    #[must_use]
    pub fn nameserver(mut self, addr: SocketAddr, protocol: DnsProtocol) -> Self {
        self.nameservers.push(Nameserver::new(addr, protocol));
        self
    }

    /// Adds several primary nameservers, each addressed by IP.
    #[must_use]
    pub fn nameservers(
        mut self,
        nameservers: impl IntoIterator<Item = (SocketAddr, DnsProtocol)>,
    ) -> Self {
        self.nameservers.extend(
            nameservers
                .into_iter()
                .map(|(addr, protocol)| Nameserver::new(addr, protocol)),
        );
        self
    }

    /// Adds a primary DoT/DoH nameserver addressed by IP but validated against
    /// `server_name`.
    ///
    /// The connection is made to `addr`, while `server_name` drives the TLS SNI
    /// and certificate validation. Use this for providers whose certificates
    /// cover a hostname rather than the IP.
    #[cfg(any(with_crypto_provider, doc))]
    #[must_use]
    pub fn nameserver_with_name(
        mut self,
        addr: SocketAddr,
        protocol: DnsProtocol,
        server_name: impl Into<String>,
    ) -> Self {
        self.nameservers
            .push(Nameserver::with_server_name(addr, protocol, server_name));
        self
    }

    /// Sets how the fallback nameservers relate to the primary ones.
    ///
    /// The default is [`FallbackMode::Deferred`]. See [`FallbackMode`] for the
    /// available modes; [`Self::disable_fallback`] and
    /// [`Self::always_use_fallback`] are shorthands for the two most common.
    #[must_use]
    pub fn fallback_mode(mut self, mode: FallbackMode) -> Self {
        self.fallback = mode;
        self
    }

    /// Races the fallback nameservers alongside the primary ones instead of
    /// waiting for the primary tier to fail.
    ///
    /// This trades the primary tier's precedence for lower worst-case latency:
    /// on a network that silently drops plain DNS, the fallback (which can
    /// include DoH) is tried right away rather than after the primary
    /// nameservers time out. Shorthand for [`FallbackMode::Always`].
    #[must_use]
    pub fn always_use_fallback(self) -> Self {
        self.fallback_mode(FallbackMode::Always)
    }

    /// Removes the fallback tier, so only the primary nameservers are queried.
    ///
    /// Shorthand for [`FallbackMode::Never`].
    #[must_use]
    pub fn disable_fallback(self) -> Self {
        self.fallback_mode(FallbackMode::Never)
    }

    /// Replaces the default public-resolver fallback with `nameservers`.
    ///
    /// Has no effect when the fallback mode is [`FallbackMode::Never`].
    #[must_use]
    pub fn fallback_nameservers(
        mut self,
        nameservers: impl IntoIterator<Item = Nameserver>,
    ) -> Self {
        self.fallback_nameservers = Some(nameservers.into_iter().collect());
        self
    }

    /// Sets a custom TLS client config for DNS-over-TLS and DNS-over-HTTPS.
    ///
    /// Requires enabling either the `tls-ring` or `tls-aws-lc-rs` feature.
    #[cfg(any(with_crypto_provider, doc))]
    #[must_use]
    pub fn tls_client_config(mut self, config: rustls::ClientConfig) -> Self {
        self.tls_client_config = Some(config);
        self
    }

    /// Builds the resolver.
    pub fn build(self) -> SimpleDnsResolver {
        SimpleDnsResolver::from_builder(self)
    }
}

/// How the resolver uses its fallback nameservers relative to the primary ones.
///
/// The *primary* nameservers come from the system DNS configuration and
/// [`Builder::nameserver`]. The *fallback* nameservers default to public
/// resolvers, overridable with [`Builder::fallback_nameservers`]. Set the mode
/// with [`Builder::fallback_mode`].
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum FallbackMode {
    /// Never query the fallback nameservers.
    Never,
    /// Race the fallback nameservers alongside the primary ones from the start.
    Always,
    /// Use the fallback nameservers only when the system DNS configuration could
    /// not be loaded or configured no nameservers.
    ///
    /// A working system configuration is never supplemented: if its nameservers
    /// fail at query time the lookup fails rather than escalating.
    IfSystemUnavailable,
    /// Keep the fallback nameservers as a lower-priority tier, queried only once
    /// every primary nameserver has failed or timed out. This is the default.
    #[default]
    Deferred,
}

/// A configured nameserver: its address, transport, and an optional TLS server
/// name for DNS-over-TLS / DNS-over-HTTPS.
///
/// The connection is always made to `addr`. When `server_name` is set it is
/// used for the TLS SNI and certificate validation (and as the DoH URL
/// authority, with the address pinned); otherwise DoT/DoH are addressed by IP.
#[derive(Debug, Clone)]
pub struct Nameserver {
    pub(crate) addr: SocketAddr,
    pub(crate) protocol: DnsProtocol,
    /// Only used for DoT/DoH, which require a crypto provider.
    #[cfg(with_crypto_provider)]
    pub(crate) server_name: Option<String>,
}

impl Nameserver {
    /// A nameserver addressed by IP, with no TLS server name.
    pub fn new(addr: SocketAddr, protocol: DnsProtocol) -> Self {
        Self {
            addr,
            protocol,
            #[cfg(with_crypto_provider)]
            server_name: None,
        }
    }

    /// A DoT/DoH nameserver addressed by IP but validated against `server_name`.
    #[cfg(any(with_crypto_provider, doc))]
    pub fn with_server_name(
        addr: SocketAddr,
        protocol: DnsProtocol,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            addr,
            protocol,
            server_name: Some(server_name.into()),
        }
    }
}

/// Protocols over which DNS records can be resolved.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum DnsProtocol {
    /// DNS over UDP
    ///
    /// This is the classic DNS protocol and supported by most DNS servers.
    #[default]
    Udp,
    /// DNS over TCP
    ///
    /// This is specified in the original DNS RFCs, but is not supported by all DNS servers.
    Tcp,
    /// DNS over TLS
    ///
    /// Performs DNS lookups over TLS-encrypted TCP connections, as defined in [RFC 7858].
    ///
    /// [RFC 7858]: https://www.rfc-editor.org/rfc/rfc7858.html
    #[cfg(with_crypto_provider)]
    Tls,
    /// DNS over HTTPS
    ///
    /// Performs DNS lookups over HTTPS, as defined in [RFC 8484].
    ///
    /// [RFC 8484]: https://www.rfc-editor.org/rfc/rfc8484.html
    #[cfg(with_crypto_provider)]
    Https,
}

/// A DNS record kind the resolver can look up.
///
/// Pass one to [`SimpleDnsResolver::lookup_record`] to resolve records of that
/// kind. The typed methods ([`SimpleDnsResolver::lookup_ipv4`],
/// [`SimpleDnsResolver::lookup_ipv6`], [`SimpleDnsResolver::lookup_txt`]) each
/// resolve a fixed kind and are thin wrappers over `lookup_record`.
///
/// [`SimpleDnsResolver::lookup_record`]: crate::SimpleDnsResolver::lookup_record
/// [`SimpleDnsResolver::lookup_ipv4`]: crate::SimpleDnsResolver::lookup_ipv4
/// [`SimpleDnsResolver::lookup_ipv6`]: crate::SimpleDnsResolver::lookup_ipv6
/// [`SimpleDnsResolver::lookup_txt`]: crate::SimpleDnsResolver::lookup_txt
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum RecordKind {
    /// An IPv4 address record (A).
    A,
    /// An IPv6 address record (AAAA).
    Aaaa,
    /// A text record (TXT).
    Txt,
    /// A name server record (NS).
    Ns,
    /// A service location record (SRV).
    Srv,
    /// A mail exchange record (MX).
    Mx,
    /// A certification authority authorization record (CAA).
    Caa,
    /// A service binding record (SVCB).
    Svcb,
    /// An HTTPS service binding record (HTTPS).
    Https,
}

/// Parsed record data returned by [`SimpleDnsResolver::lookup_record`].
///
/// Each variant corresponds to a [`RecordKind`]. A single lookup returns only
/// records of the requested kind, so matching one variant is enough in
/// practice, but the enum is [`non_exhaustive`] so that adding kinds later is
/// not a breaking change.
///
/// [`SimpleDnsResolver::lookup_record`]: crate::SimpleDnsResolver::lookup_record
/// [`non_exhaustive`]: https://doc.rust-lang.org/reference/attributes/type_system.html
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Record {
    /// An IPv4 address from an A record.
    A(Ipv4Addr),
    /// An IPv6 address from an AAAA record.
    Aaaa(Ipv6Addr),
    /// The character strings of a TXT record.
    Txt(TxtRecordData),
    /// The name of an authoritative name server from an NS record.
    Ns(String),
    /// The target of an SRV record.
    Srv(SrvRecordData),
    /// The mail exchange of an MX record.
    Mx(MxRecordData),
    /// The policy of a CAA record.
    Caa(CaaRecordData),
    /// The service binding of an SVCB record.
    Svcb(SvcbRecordData),
    /// The service binding of an HTTPS record.
    Https(SvcbRecordData),
}

/// Record data for an SRV record, as defined in [RFC 2782].
///
/// [RFC 2782]: https://datatracker.ietf.org/doc/html/rfc2782
#[derive(Debug, Clone)]
pub struct SrvRecordData {
    /// The priority of this target; lower values are preferred.
    pub priority: u16,
    /// The relative weight for targets that share a priority.
    pub weight: u16,
    /// The port on the target host for this service.
    pub port: u16,
    /// The domain name of the target host.
    pub target: String,
}

/// Record data for an MX record, as defined in [RFC 1035 Section 3.3.9].
///
/// [RFC 1035 Section 3.3.9]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.9
#[derive(Debug, Clone)]
pub struct MxRecordData {
    /// The preference given to this mail exchange; lower values are preferred.
    pub preference: u16,
    /// The domain name of a host willing to act as a mail exchange.
    pub exchange: String,
}

/// Record data for a CAA record, as defined in [RFC 8659].
///
/// The resolver returns the record as it appears on the wire and does not
/// validate or interpret the `tag` or `value`.
///
/// [RFC 8659]: https://datatracker.ietf.org/doc/html/rfc8659
#[derive(Debug, Clone)]
pub struct CaaRecordData {
    /// The flags byte, whose high bit marks the record as critical.
    pub flag: u8,
    /// The property described by `value`, such as `issue`, `issuewild`, or `iodef`.
    pub tag: String,
    /// The raw value associated with the property, as it appears on the wire.
    pub value: Box<[u8]>,
}

/// Record data for an SVCB or HTTPS record, as defined in [RFC 9460].
///
/// Wraps the parsed record and exposes the commonly used parameters through
/// accessor methods. A [`priority`](Self::priority) of 0 marks the record as
/// being in AliasMode, whose redirection this resolver does not follow, so such
/// a record is returned with its [`target`](Self::target) as-is.
///
/// [RFC 9460]: https://datatracker.ietf.org/doc/html/rfc9460
#[derive(Debug, Clone)]
pub struct SvcbRecordData(SVCB<'static>);

impl SvcbRecordData {
    /// Wraps an owned `simple_dns` SVCB record.
    pub(crate) fn new(svcb: SVCB<'static>) -> Self {
        Self(svcb)
    }

    /// The priority of this record; lower values are preferred, and 0 marks
    /// AliasMode.
    pub fn priority(&self) -> u16 {
        self.0.priority
    }

    /// The alias target (in AliasMode) or the alternative endpoint (in
    /// ServiceMode).
    pub fn target(&self) -> String {
        self.0.target.to_string()
    }

    /// The application protocol identifiers from the `alpn` parameter, empty
    /// when the parameter is absent.
    pub fn alpn(&self) -> Vec<String> {
        self.0
            .iter_params()
            .find_map(|param| match param {
                SVCParam::Alpn(ids) => Some(ids.iter().map(|id| id.to_string()).collect()),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// The port from the `port` parameter, if present.
    pub fn port(&self) -> Option<u16> {
        self.0.iter_params().find_map(|param| match param {
            SVCParam::Port(port) => Some(*port),
            _ => None,
        })
    }

    /// The IPv4 addresses from the `ipv4hint` parameter, empty when the
    /// parameter is absent.
    pub fn ipv4hint(&self) -> Vec<Ipv4Addr> {
        self.0
            .iter_params()
            .find_map(|param| match param {
                SVCParam::Ipv4Hint(ips) => Some(ips.iter().map(|ip| Ipv4Addr::from(*ip)).collect()),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// The IPv6 addresses from the `ipv6hint` parameter, empty when the
    /// parameter is absent.
    pub fn ipv6hint(&self) -> Vec<Ipv6Addr> {
        self.0
            .iter_params()
            .find_map(|param| match param {
                SVCParam::Ipv6Hint(ips) => Some(ips.iter().map(|ip| Ipv6Addr::from(*ip)).collect()),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// The Encrypted ClientHello (ECH) config list from the `ech` parameter, if
    /// present.
    ///
    /// The bytes are the raw `ECHConfigList` (RFC 9460 registers the parameter;
    /// the value is opaque to DNS), returned for a TLS client to consume.
    pub fn ech(&self) -> Option<Vec<u8>> {
        self.0.iter_params().find_map(|param| match param {
            SVCParam::Ech(config) => Some(config.to_vec()),
            _ => None,
        })
    }

    /// The SvcParamKeys the `mandatory` parameter marks as required, in
    /// ascending order, empty when the parameter is absent.
    ///
    /// A client that does not understand every key listed here must treat the
    /// record as unusable (RFC 9460 Section 8).
    pub fn mandatory(&self) -> Vec<u16> {
        self.0
            .iter_params()
            .find_map(|param| match param {
                SVCParam::Mandatory(keys) => Some(keys.iter().copied().collect()),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// Whether the `no-default-alpn` parameter is set, meaning the default ALPN
    /// for the scheme must not be assumed and only [`Self::alpn`] applies.
    pub fn no_default_alpn(&self) -> bool {
        self.0
            .iter_params()
            .any(|param| matches!(param, SVCParam::NoDefaultAlpn))
    }
}

/// Record data for a TXT record.
///
/// This contains a list of character strings, as defined in [RFC 1035 Section 3.3.14].
///
/// [`TxtRecordData`] implements [`fmt::Display`], so you can call [`ToString::to_string`] to
/// convert the record data into a string. This will parse each character string with
/// [`String::from_utf8_lossy`] and then concatenate all strings without a separator.
///
/// If you want to process each character string individually, use [`Self::iter`].
///
/// [RFC 1035 Section 3.3.14]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14
#[derive(Debug, Clone)]
pub struct TxtRecordData(Box<[Box<[u8]>]>);

impl TxtRecordData {
    /// Returns an iterator over the character strings contained in this TXT record.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(|x| x.as_ref())
    }

    /// Consumes the record and returns its character strings as boxed byte slices.
    ///
    /// This hands over the backing storage without copying, so a caller that
    /// wants owned bytes (for example to build its own wrapper type) avoids the
    /// per-string allocation that [`Self::iter`] followed by `collect` incurs.
    pub fn into_boxed_slices(self) -> Box<[Box<[u8]>]> {
        self.0
    }
}

impl fmt::Display for TxtRecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for s in self.iter() {
            write!(f, "{}", String::from_utf8_lossy(s))?
        }
        Ok(())
    }
}

impl FromIterator<Box<[u8]>> for TxtRecordData {
    fn from_iter<T: IntoIterator<Item = Box<[u8]>>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl From<Vec<Box<[u8]>>> for TxtRecordData {
    fn from(value: Vec<Box<[u8]>>) -> Self {
        Self(value.into_boxed_slice())
    }
}

impl From<Vec<String>> for TxtRecordData {
    fn from(value: Vec<String>) -> Self {
        Self(
            value
                .into_iter()
                .map(|s| s.into_bytes().into_boxed_slice())
                .collect(),
        )
    }
}
