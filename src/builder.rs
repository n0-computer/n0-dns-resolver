//! The [`Builder`] for configuring a [`DnsResolver`].

use std::{net::SocketAddr, time::Duration};

use crate::{DnsResolver, public_resolvers};

/// Builds a [`DnsResolver`].
///
/// A fresh builder is empty: it queries no nameservers and does not read the
/// host system, so every source is opted into explicitly. Get one from
/// [`DnsResolver::builder`], add nameservers, adjust the setters, and finish
/// with [`Builder::build`]. For the common case — the system configuration with
/// the public resolvers behind it — use [`DnsResolver::system_with_fallback`]
/// instead of assembling it by hand.
///
/// # Nameserver tiers
///
/// Nameservers form two tiers. The *primary* tier is what
/// [`Builder::use_system_config`], [`Builder::nameserver`] and
/// [`Builder::nameservers`] add. The *fallback* tier is what
/// [`Builder::fallback_nameservers`] and
/// [`Builder::default_fallback_nameservers`] add; both tiers start empty.
/// [`Builder::fallback_mode`] decides how the two relate: by default the
/// fallback tier is queried only once the primary tier cannot answer.
///
/// # Examples
///
/// ```
/// use n0_dns_resolver::{DnsResolver, public_resolvers, public_resolvers::Provider};
///
/// // The system configuration, with Quad9 behind it as a fallback.
/// let resolver = DnsResolver::builder()
///     .use_system_config()
///     .fallback_nameservers(public_resolvers::default_order(vec![Provider::Quad9]))
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct Builder {
    pub(crate) use_system_config: bool,
    pub(crate) nameservers: Vec<Nameserver>,
    pub(crate) fallback_nameservers: Vec<Nameserver>,
    pub(crate) fallback: FallbackMode,
    /// When set, serve an expired cached answer within this window if live
    /// resolution fails (serve-stale, RFC 8767). `None` disables it.
    pub(crate) serve_stale: Option<Duration>,
    /// When set, floor every cached positive TTL to at least this long, so a
    /// burst of very-low-TTL answers does not re-query on every lookup. `None`
    /// keeps the server-supplied TTL.
    pub(crate) cache_min_ttl: Option<Duration>,
    /// Cap on how long NXDOMAIN/NODATA is cached. `None` disables negative
    /// caching.
    pub(crate) negative_max_ttl: Option<Duration>,
    #[cfg(with_rustls)]
    pub(crate) tls_client_config: Option<rustls::ClientConfig>,
}

impl Builder {
    /// Reads the host system's DNS configuration into the primary tier.
    ///
    /// This adds the system's nameservers, and makes the resolver honor the
    /// system's `search` domains and `ndots` setting and consult the system
    /// hosts file. Without it none of the host's configuration is read.
    #[must_use]
    pub fn use_system_config(mut self) -> Self {
        self.use_system_config = true;
        self
    }

    /// Adds a primary nameserver.
    ///
    /// Build one with [`Nameserver::new`], or with
    /// [`Nameserver::with_server_name`] for a DoT/DoH server whose certificate
    /// covers a hostname rather than its IP.
    #[must_use]
    pub fn nameserver(mut self, nameserver: Nameserver) -> Self {
        self.nameservers.push(nameserver);
        self
    }

    /// Adds several primary nameservers.
    ///
    /// Appends, and takes the same [`Nameserver`] list as
    /// [`Self::fallback_nameservers`], so a selection of public resolvers can be
    /// the primary tier just as well as the fallback one.
    #[must_use]
    pub fn nameservers(mut self, nameservers: impl IntoIterator<Item = Nameserver>) -> Self {
        self.nameservers.extend(nameservers);
        self
    }

    /// Sets how the fallback nameservers relate to the primary ones.
    ///
    /// The default is [`FallbackMode::Deferred`]: the fallback tier waits for
    /// the primary one to fail. See [`FallbackMode`] for the alternatives. Has
    /// no effect while the fallback tier is empty.
    #[must_use]
    pub fn fallback_mode(mut self, mode: FallbackMode) -> Self {
        self.fallback = mode;
        self
    }

    /// Adds `nameservers` to the fallback tier.
    ///
    /// Appends, so it can be called repeatedly and combines with
    /// [`Self::default_fallback_nameservers`]. Build the list for a selection of
    /// public resolvers with [`public_resolvers::default_order`], or assemble your
    /// own from [`Provider::nameservers`] and [`Nameserver::interleave`].
    ///
    /// [`Provider::nameservers`]: public_resolvers::Provider::nameservers
    #[must_use]
    pub fn fallback_nameservers(
        mut self,
        nameservers: impl IntoIterator<Item = Nameserver>,
    ) -> Self {
        self.fallback_nameservers.extend(nameservers);
        self
    }

    /// Adds the crate's default public resolvers to the fallback tier.
    ///
    /// Shorthand for [`Self::fallback_nameservers`] with
    /// [`public_resolvers::default_order`] over [`Provider::ALL`]: Cloudflare,
    /// Google and Quad9, over UDP and DNS-over-HTTPS, on both address families.
    /// That function documents the order and the reasoning behind it.
    ///
    /// [`Provider::ALL`]: public_resolvers::Provider::ALL
    #[must_use]
    pub fn default_fallback_nameservers(self) -> Self {
        self.fallback_nameservers(public_resolvers::default_order(
            public_resolvers::Provider::ALL.to_vec(),
        ))
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

    /// Caps how long NXDOMAIN and NODATA answers are cached.
    ///
    /// Off by default, so a first NXDOMAIN does not hide a name that starts
    /// resolving a moment later. Pass a positive duration to cache negatives,
    /// capped by this value and by the response's SOA (RFC 2308).
    #[must_use]
    pub fn negative_max_ttl(mut self, max_ttl: Duration) -> Self {
        self.negative_max_ttl = Some(max_ttl);
        self
    }

    /// Builds the resolver.
    pub fn build(self) -> DnsResolver {
        DnsResolver::from_builder(self)
    }
}

/// How the resolver uses its fallback nameservers relative to the primary ones.
///
/// The *primary* nameservers come from [`Builder::use_system_config`] and
/// [`Builder::nameserver`]; the *fallback* nameservers from
/// [`Builder::fallback_nameservers`]. Set the mode with
/// [`Builder::fallback_mode`]. An empty fallback tier is unaffected by the mode:
/// to query no fallback at all, add none.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum FallbackMode {
    /// Race the fallback nameservers alongside the primary ones from the start.
    Eager,
    /// Use the fallback nameservers only when the system DNS configuration
    /// yielded no nameservers, whether because it could not be read or because
    /// it listed none.
    ///
    /// A system configuration that did yield nameservers is never supplemented:
    /// if those nameservers fail at query time the lookup fails rather than
    /// escalating. Without [`Builder::use_system_config`] there is no system
    /// configuration at all, which counts as empty, so this behaves like
    /// [`Self::Eager`].
    IfSystemEmpty,
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
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Nameserver {
    pub(crate) addr: SocketAddr,
    pub(crate) protocol: DnsProtocol,
    /// Only used for DoT/DoH (the `transport-tls` or `transport-https` feature).
    #[cfg(any(with_rustls, doc))]
    pub(crate) server_name: Option<String>,
}

impl Nameserver {
    /// A nameserver addressed by IP, with no TLS server name.
    pub const fn new(addr: SocketAddr, protocol: DnsProtocol) -> Self {
        Self {
            addr,
            protocol,
            #[cfg(any(with_rustls, doc))]
            server_name: None,
        }
    }

    /// Merges nameserver lists round-robin: every list's first entry, then
    /// every list's second, and so on, with exhausted lists skipped.
    ///
    /// Nameserver order is query order (see [`Builder::fallback_mode`] for how
    /// the tiers are raced), so interleaving per-provider lists spreads the
    /// early attempts across providers instead of exhausting one before trying
    /// the next. It applies no other policy — for this crate's opinionated
    /// order over the public resolvers, see [`public_resolvers::default_order`].
    ///
    /// ```
    /// use n0_dns_resolver::{DnsProtocol, Nameserver, public_resolvers::Provider};
    ///
    /// // DNS-over-TLS to Quad9 and Cloudflare, alternating between them.
    /// let servers = Nameserver::interleave([
    ///     Provider::Quad9.nameservers(DnsProtocol::Tls),
    ///     Provider::Cloudflare.nameservers(DnsProtocol::Tls),
    /// ]);
    /// ```
    pub fn interleave<L>(lists: impl IntoIterator<Item = L>) -> Vec<Nameserver>
    where
        L: IntoIterator<Item = Nameserver>,
    {
        // Fused so that a list which has run dry stays dry, whatever the
        // caller's iterator does after returning `None`.
        let mut lists: Vec<_> = lists.into_iter().map(|l| l.into_iter().fuse()).collect();
        // Each round takes one entry from every list that still has one, so the
        // rounds shrink as lists run out and an empty round ends the merge.
        std::iter::repeat_with(|| {
            lists
                .iter_mut()
                .filter_map(Iterator::next)
                .collect::<Vec<_>>()
        })
        .take_while(|round| !round.is_empty())
        .flatten()
        .collect()
    }

    /// The address this nameserver is queried at.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The transport this nameserver is queried over.
    pub fn protocol(&self) -> DnsProtocol {
        self.protocol
    }

    /// The TLS server name this nameserver's certificate is validated against,
    /// or `None` when it is addressed by IP.
    ///
    /// Only ever set by [`Self::with_server_name`], and only used for DoT/DoH.
    #[cfg(any(with_rustls, doc))]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
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
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash)]
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
    /// DNS over TLS (DoT)
    ///
    /// Performs DNS lookups over TLS-encrypted TCP connections, as defined in [RFC 7858].
    ///
    /// [RFC 7858]: https://www.rfc-editor.org/rfc/rfc7858.html
    #[cfg(transport_tls)]
    Tls,
    /// DNS over HTTPS (DoH)
    ///
    /// Performs DNS lookups over HTTPS, as defined in [RFC 8484].
    ///
    /// [RFC 8484]: https://www.rfc-editor.org/rfc/rfc8484.html
    #[cfg(transport_https)]
    Https,
}

impl DnsProtocol {
    /// The IANA-registered default port for this protocol: 53 for plain DNS
    /// over UDP or TCP, 853 for DNS-over-TLS, 443 for DNS-over-HTTPS.
    ///
    /// A [`Nameserver`] carries its own port, which need not be this one; this
    /// is what to use when only an IP address is known.
    pub const fn port(self) -> u16 {
        match self {
            // Do53, the classic DNS port.
            DnsProtocol::Udp | DnsProtocol::Tcp => 53,
            // DoT, RFC 7858.
            #[cfg(transport_tls)]
            DnsProtocol::Tls => 853,
            // DoH, RFC 8484.
            #[cfg(transport_https)]
            DnsProtocol::Https => 443,
        }
    }
}
