//! The [`Builder`] for configuring a [`DnsResolver`].

use std::{net::SocketAddr, time::Duration};

use crate::DnsResolver;

/// Builds a [`DnsResolver`].
///
/// The default builder reads the host system's DNS configuration and, when a
/// query cannot be answered there, escalates to a set of public resolvers. Get
/// one from [`DnsResolver::builder`], adjust it with the setters, and
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
/// use n0_dns_resolver::DnsResolver;
///
/// // System configuration first, public resolvers as a fallback.
/// let resolver = DnsResolver::builder().build();
/// ```
#[derive(Debug, Clone)]
pub struct Builder {
    pub(crate) use_system_defaults: bool,
    pub(crate) nameservers: Vec<Nameserver>,
    pub(crate) fallback: FallbackMode,
    pub(crate) fallback_nameservers: Option<Vec<Nameserver>>,
    /// When set, serve an expired cached answer within this window if live
    /// resolution fails (serve-stale, RFC 8767). `None` disables it.
    pub(crate) serve_stale: Option<Duration>,
    /// When set, floor every cached positive TTL to at least this long, so a
    /// burst of very-low-TTL answers does not re-query on every lookup. `None`
    /// keeps the server-supplied TTL.
    pub(crate) cache_min_ttl: Option<Duration>,
    #[cfg(with_rustls)]
    pub(crate) tls_client_config: Option<rustls::ClientConfig>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            use_system_defaults: true,
            nameservers: Vec::new(),
            fallback: FallbackMode::default(),
            fallback_nameservers: None,
            serve_stale: None,
            cache_min_ttl: None,
            #[cfg(with_rustls)]
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
    #[cfg(any(with_rustls, doc))]
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
    /// Requires the `transport-tls` or `transport-https` feature. Without a
    /// config, DoT/DoH use one built from the crypto provider (`tls-ring` or
    /// `tls-aws-lc-rs`); with neither a config nor a provider, they error.
    #[cfg(with_rustls)]
    #[must_use]
    pub fn tls_client_config(mut self, config: rustls::ClientConfig) -> Self {
        self.tls_client_config = Some(config);
        self
    }

    /// Serves an expired cached answer when live resolution fails (serve-stale,
    /// RFC 8767).
    ///
    /// When every nameserver fails or times out, a positive answer that expired
    /// no more than `max_age` ago is returned instead of an error, so a brief
    /// upstream outage does not break resolution. Only positive answers are
    /// served stale; an authoritative NXDOMAIN is never overridden. Off by
    /// default.
    #[must_use]
    pub fn serve_stale(mut self, max_age: Duration) -> Self {
        self.serve_stale = Some(max_age);
        self
    }

    /// Floors every cached positive time-to-live (TTL) to at least `min_ttl`.
    ///
    /// Absorbs bursts of lookups for records with very low (or zero) TTLs by
    /// holding them for at least this long, at the cost of serving a slightly
    /// staler answer. Off by default, since it trades freshness for fewer
    /// queries; leave it unset for records that change frequently.
    #[must_use]
    pub fn cache_min_ttl(mut self, min_ttl: Duration) -> Self {
        self.cache_min_ttl = Some(min_ttl);
        self
    }

    /// Builds the resolver.
    pub fn build(self) -> DnsResolver {
        DnsResolver::from_builder(self)
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
    /// Only used for DoT/DoH (the `transport-tls` or `transport-https` feature).
    #[cfg(any(with_rustls, doc))]
    pub(crate) server_name: Option<String>,
}

impl Nameserver {
    /// A nameserver addressed by IP, with no TLS server name.
    pub fn new(addr: SocketAddr, protocol: DnsProtocol) -> Self {
        Self {
            addr,
            protocol,
            #[cfg(any(with_rustls, doc))]
            server_name: None,
        }
    }

    /// A DoT/DoH nameserver addressed by IP but validated against `server_name`.
    #[cfg(any(with_rustls, doc))]
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
    #[cfg(transport_tls)]
    Tls,
    /// DNS over HTTPS
    ///
    /// Performs DNS lookups over HTTPS, as defined in [RFC 8484].
    ///
    /// [RFC 8484]: https://www.rfc-editor.org/rfc/rfc8484.html
    #[cfg(transport_https)]
    Https,
}
