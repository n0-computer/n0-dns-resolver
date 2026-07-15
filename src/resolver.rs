//! Built-in DNS resolver using `simple-dns` for packet construction/parsing
//! and tokio for transport.

#[cfg(with_crypto_provider)]
use std::sync::{Arc, Mutex};
use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr},
    time::Instant,
};

use n0_error::{AnyError, e};
use n0_future::{
    FuturesUnordered, MaybeFuture, StreamExt,
    time::{self, Duration},
};
use simple_dns::TYPE;
use tracing::{debug, trace, warn};

use crate::{
    Builder, DnsProtocol, Error, FallbackMode, HttpsRecord, MxRecordData, Nameserver, Record,
    RecordKind, SrvRecordData, SvcbRecordData, TxtRecordData,
    config::DnsConfig,
    system_config::{self, Hosts},
};

mod cache;
#[cfg(feature = "dnssec")]
mod dnssec_validate;
mod pool;
mod query;
mod rtt_map;
mod transport;

use self::{
    cache::{CachedResult, DnsCache, NEGATIVE_TTL_SECS},
    pool::ConnPool,
    query::{MAX_CNAME_DEPTH, QueryError},
    rtt_map::RttMap,
    transport::TransportError,
};

impl RecordKind {
    /// Maps this kind onto the `simple_dns` query type used on the wire.
    fn dns_type(self) -> TYPE {
        match self {
            RecordKind::A => TYPE::A,
            RecordKind::Aaaa => TYPE::AAAA,
            RecordKind::Txt => TYPE::TXT,
            RecordKind::Ns => TYPE::NS,
            RecordKind::Srv => TYPE::SRV,
            RecordKind::Mx => TYPE::MX,
            RecordKind::Caa => TYPE::CAA,
            RecordKind::Svcb => TYPE::SVCB,
            RecordKind::Https => TYPE::HTTPS,
        }
    }
}

/// Maps a transport-layer failure onto the public [`Error`].
impl From<TransportError> for Error {
    fn from(err: TransportError) -> Self {
        e!(Error::Transport, AnyError::from_stack(err))
    }
}

/// Maps a query build or response-parse failure onto the public [`Error`].
impl From<QueryError> for Error {
    fn from(err: QueryError) -> Self {
        match err {
            QueryError::BuildQuery { source, .. } => e!(Error::InvalidQuery, source),
            QueryError::Malformed { .. } | QueryError::Unexpected { .. } => {
                e!(Error::InvalidResponse)
            }
            QueryError::NxDomain { .. } => e!(Error::NxDomain),
            QueryError::ServerFailure { rcode, .. } => e!(Error::ServerError { rcode }),
        }
    }
}

/// Per-nameserver timeout for a single attempt.
const NAMESERVER_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum number of nameserver queries in flight at once.
///
/// Bounds how many servers we race so that growing the nameserver list does
/// not turn every lookup into an N-way fan-out.
const MAX_CONCURRENT_QUERIES: usize = 3;

/// Delay before starting the next nameserver attempt, unless the in-flight
/// attempt fails first. Gives faster servers a head start without blasting
/// the whole list at once (happy-eyeballs style).
const QUERY_ATTEMPT_DELAY: Duration = Duration::from_millis(100);

/// Number of UDP retry attempts per nameserver before giving up.
/// UDP is unreliable, so a single dropped packet shouldn't be fatal.
const UDP_ATTEMPTS: usize = 2;

/// Default value for `ndots` per resolv.conf(5).
///
/// Names with at least this many dots are tried as absolute names first,
/// before appending search domains. Names with fewer dots try search
/// domains first. See <https://man7.org/linux/man-pages/man5/resolv.conf.5.html>.
const DEFAULT_NDOTS: usize = 1;

/// RFC 6761 Section 6.3: "localhost" and names under it resolve to loopback.
fn is_localhost(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost")
}

/// A stub DNS resolver over UDP/TCP (and, with a crypto provider, DoT/DoH).
///
/// See the [crate] docs for an overview. Construct one with [`Self::new`] for
/// cross-platform defaults, or with [`Self::builder`] to configure the
/// nameservers and fallback behavior.
#[derive(Debug)]
pub struct SimpleDnsResolver {
    /// The primary nameservers followed by the fallback ones. The two tiers are
    /// split at `primary_count`; see [`Self::send_query`] for how they are used.
    nameservers: Vec<Nameserver>,
    /// Number of leading entries in `nameservers` that form the primary tier.
    primary_count: usize,
    search_domains: Vec<String>,
    ndots: usize,
    #[cfg(with_crypto_provider)]
    tls_config: Option<Arc<rustls::ClientConfig>>,
    /// Lazily initialized, cached reqwest client for DNS-over-HTTPS queries.
    #[cfg(with_crypto_provider)]
    https_client: Mutex<Option<reqwest::Client>>,
    /// Smoothed RTT per nameserver (parallel to `nameservers`), used to order
    /// servers and re-probe demoted ones.
    rtt_map: RttMap,
    /// Pooled TCP/DoT connections, reused across queries.
    conn_pool: ConnPool,
    cache: DnsCache,
    /// Static name-to-address mappings from the system hosts file, consulted
    /// ahead of the cache for A/AAAA lookups. Empty unless system defaults are
    /// in use.
    hosts: Hosts,
    /// When set, every answer is validated against the DNSSEC chain of trust
    /// before it is returned. See [`Builder::validate_dnssec`].
    #[cfg(feature = "dnssec")]
    validate_dnssec: bool,
    /// The settings this resolver was built from, kept so [`Self::reset`] can
    /// rebuild against a changed network.
    builder: Builder,
}

impl SimpleDnsResolver {
    /// Creates a resolver with cross-platform defaults.
    ///
    /// Reads the system's DNS configuration and escalates to public resolvers
    /// when it cannot be read or a query goes unanswered. Equivalent to
    /// `SimpleDnsResolver::builder().build()`.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Returns a [`Builder`] for configuring a resolver.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Builds a resolver from `builder`, used by [`Builder::build`].
    pub(crate) fn from_builder(builder: Builder) -> Self {
        Self::build_inner(builder, DnsCache::new())
    }

    /// Builds a resolver from `builder`, reusing an existing [`DnsCache`].
    ///
    /// Used by [`Self::reset`] to rebuild the resolver on a network change while
    /// carrying the cache across, so lookups keep hitting cached records while
    /// the new nameservers settle (see issue #4037).
    fn build_inner(builder: Builder, cache: DnsCache) -> Self {
        // Primary tier: the system configuration (when enabled) plus any
        // explicitly configured nameservers. A failure to read the system
        // configuration is logged and treated as an empty one, so the fallback
        // can take over.
        let system = if builder.use_system_defaults {
            match system_config::read_system() {
                Ok(config) => config,
                Err(err) => {
                    warn!(%err, "failed to read system DNS configuration, using fallback");
                    DnsConfig::default()
                }
            }
        } else {
            DnsConfig::default()
        };
        let system_has_nameservers = !system.nameservers.is_empty();
        let mut nameservers = system.nameservers;
        nameservers.extend(builder.nameservers.iter().cloned());

        // Fallback tier: the configured (or default public) resolvers. Whether
        // to include them, and whether they defer behind the primary tier or
        // race alongside it, depends on the mode.
        let fallback_servers = || {
            builder
                .fallback_nameservers
                .clone()
                .unwrap_or_else(|| DnsConfig::fallback().nameservers)
        };
        // `defer` marks the fallback as a lower-priority second tier; otherwise
        // it merges into the primary tier and is raced from the start.
        let (mut fallback, defer) = match builder.fallback {
            FallbackMode::Never => (Vec::new(), false),
            FallbackMode::Always => (fallback_servers(), false),
            FallbackMode::Deferred => (fallback_servers(), true),
            FallbackMode::IfSystemUnavailable if system_has_nameservers => (Vec::new(), false),
            FallbackMode::IfSystemUnavailable => (fallback_servers(), false),
        };
        let primary_count = if defer {
            nameservers.len()
        } else {
            nameservers.len() + fallback.len()
        };
        nameservers.append(&mut fallback);

        debug!(
            ?nameservers,
            primary_count,
            search_domains = ?system.search_domains,
            ndots = ?system.ndots,
            "configured DNS resolver"
        );
        #[cfg(with_crypto_provider)]
        let tls_config = builder
            .tls_client_config
            .as_ref()
            .map(|c| Arc::new(c.clone()));
        let rtt_map = RttMap::new(nameservers.len());
        // The hosts file is part of the system resolver configuration, so we
        // only consult it when the caller opted into system defaults. Reading
        // it here mirrors reading /etc/resolv.conf above.
        let hosts = if builder.use_system_defaults {
            Hosts::from_system()
        } else {
            Hosts::default()
        };
        Self {
            nameservers,
            primary_count,
            search_domains: system.search_domains,
            ndots: system.ndots.unwrap_or(DEFAULT_NDOTS),
            #[cfg(with_crypto_provider)]
            tls_config,
            #[cfg(with_crypto_provider)]
            https_client: Mutex::new(None),
            rtt_map,
            conn_pool: ConnPool::new(),
            cache,
            hosts,
            #[cfg(feature = "dnssec")]
            validate_dnssec: builder.validate_dnssec,
            builder,
        }
    }

    /// Returns the list of candidate names to try for a given hostname,
    /// applying search domain expansion per resolv.conf(5) semantics.
    ///
    /// - If the name ends with `.` (FQDN), it is used as-is.
    /// - If the name has more labels than `ndots`, try the bare name first,
    ///   then each search domain suffix.
    /// - Otherwise, try each search domain suffix first, then the bare name.
    ///
    /// See <https://man7.org/linux/man-pages/man5/resolv.conf.5.html>.
    fn search_names(&self, host: &str) -> Vec<String> {
        // Explicit FQDN: no search domain expansion.
        if host.ends_with('.') || self.search_domains.is_empty() {
            return vec![host.to_string()];
        }

        // Label count = dots + 1 (e.g. "foo.bar" has 2 labels).
        // resolv.conf(5): "if the name has more dots than ndots, try as absolute first"
        // which is equivalent to num_labels > ndots.
        let num_labels = host.bytes().filter(|&b| b == b'.').count() + 1;
        let bare_first = num_labels > self.ndots;

        let mut names: Vec<String> = Vec::with_capacity(self.search_domains.len() + 1);

        // Append a candidate unless it is already present.
        fn push(names: &mut Vec<String>, name: String) {
            if !names.contains(&name) {
                names.push(name);
            }
        }

        if bare_first {
            push(&mut names, host.to_string());
        }
        for domain in &self.search_domains {
            let expanded = format!("{host}.{domain}");
            // Drop an expansion that cannot form a valid DNS name, such as an
            // over-long suffix or a `--` placeholder from systemd-resolved. One
            // bad search entry must not abort the lookup by producing an
            // InvalidQuery that the search loop treats as fatal; the bare name is
            // always kept so an invalid host still surfaces its own error.
            if simple_dns::Name::new(&expanded).is_ok() {
                push(&mut names, expanded);
            }
        }
        if !bare_first {
            push(&mut names, host.to_string());
        }

        names
    }

    /// Returns a clone of the cached reqwest client, creating it on first use.
    ///
    /// `reqwest::Client` uses an inner `Arc`, so cloning is cheap.
    #[cfg(with_crypto_provider)]
    fn get_or_init_https_client(&self) -> Result<reqwest::Client, Error> {
        let mut guard = self.https_client.lock().expect("poisoned");
        match guard.as_ref() {
            Some(client) => Ok(client.clone()),
            None => {
                // Pin each named DoH server to its address so reqwest does not
                // recursively resolve the hostname.
                let resolves: Vec<(String, std::net::SocketAddr)> = self
                    .nameservers
                    .iter()
                    .filter(|ns| ns.protocol == DnsProtocol::Https)
                    .filter_map(|ns| ns.server_name.clone().map(|name| (name, ns.addr)))
                    .collect();
                let client = transport::build_https_client(self.tls_config.as_ref(), &resolves)?;
                *guard = Some(client.clone());
                Ok(client)
            }
        }
    }

    /// Run a future with [`NAMESERVER_TIMEOUT`].
    async fn with_timeout<T, E: Into<AnyError>>(
        fut: impl Future<Output = Result<T, E>>,
    ) -> Result<T, Error> {
        time::timeout(NAMESERVER_TIMEOUT, fut)
            .await
            .map(|r| r.map_err(|e| e!(Error::Transport, e.into())))
            .map_err(|_| e!(Error::Timeout))?
    }

    /// Query a single nameserver, with UDP retry and truncation fallback.
    async fn query_nameserver(
        &self,
        ns: &Nameserver,
        query_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let addr = ns.addr;
        match ns.protocol {
            DnsProtocol::Udp => {
                let mut last_err = None;
                for attempt in 0..UDP_ATTEMPTS {
                    trace!(%addr, attempt, "sending UDP query");
                    match Self::with_timeout(transport::udp_query(addr, query_bytes)).await {
                        Ok((resp, maybe_truncated))
                            if maybe_truncated || query::is_truncated(&resp) =>
                        {
                            debug!(%addr, "UDP response truncated, retrying over TCP");
                            return Self::with_timeout(transport::tcp_query(
                                &self.conn_pool,
                                addr,
                                query_bytes,
                            ))
                            .await;
                        }
                        Ok((resp, _)) => return Ok(resp),
                        Err(e) => {
                            trace!(%addr, attempt, err = %e, "UDP query failed");
                            last_err = Some(e);
                        }
                    }
                }
                Err(last_err.unwrap_or_else(|| e!(Error::NoResponse)))
            }
            DnsProtocol::Tcp => {
                Self::with_timeout(transport::tcp_query(&self.conn_pool, addr, query_bytes)).await
            }
            #[cfg(with_crypto_provider)]
            DnsProtocol::Tls => {
                let tls_config = self
                    .tls_config
                    .as_ref()
                    .ok_or_else(|| e!(Error::MissingTlsConfig))?;
                Self::with_timeout(transport::tls_query(
                    &self.conn_pool,
                    addr,
                    query_bytes,
                    tls_config,
                    ns.server_name.as_deref(),
                ))
                .await
            }
            #[cfg(with_crypto_provider)]
            DnsProtocol::Https => {
                let client = self.get_or_init_https_client()?;
                Self::with_timeout(transport::https_query(
                    addr,
                    ns.server_name.as_deref(),
                    query_bytes,
                    &client,
                ))
                .await
            }
        }
    }

    /// Returns the given nameserver indices ordered fastest-first by smoothed RTT.
    fn order_indices(&self, indices: &[usize]) -> Vec<usize> {
        let mut order = indices.to_vec();
        order.sort_by(|&a, &b| {
            self.rtt_map
                .get_decayed(a)
                .total_cmp(&self.rtt_map.get_decayed(b))
        });
        order
    }

    /// Sends a query, trying the primary nameservers first and escalating to the
    /// fallback tier only if every primary nameserver fails or times out.
    ///
    /// The two tiers are the leading `primary_count` entries of `nameservers`
    /// and the rest. Only [`FallbackMode::Deferred`] produces a second tier; the
    /// other modes leave `primary_count == nameservers.len()`, so no escalation
    /// happens. When the primary tier is empty (for example the system
    /// configuration could not be read), escalation makes the fallback tier the
    /// effective primary.
    async fn send_query(&self, query_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if self.nameservers.is_empty() {
            return Err(e!(Error::NoResponse));
        }

        let primary: Vec<usize> = (0..self.primary_count).collect();
        match self.race(&primary, query_bytes).await {
            Ok(resp) => Ok(resp),
            Err(primary_err) => {
                if self.primary_count == self.nameservers.len() {
                    return Err(primary_err);
                }
                debug!(err = %primary_err, "primary nameservers failed, escalating to fallback");
                let fallback: Vec<usize> = (self.primary_count..self.nameservers.len()).collect();
                self.race(&fallback, query_bytes).await
            }
        }
    }

    /// Races the nameservers named by `indices` happy-eyeballs style: tries the
    /// historically fastest first, starts the next either [`QUERY_ATTEMPT_DELAY`]
    /// later or as soon as the in-flight attempt fails (fail-fast), and caps
    /// in-flight attempts at [`MAX_CONCURRENT_QUERIES`].
    ///
    /// The first successful response wins; UDP queries are retried per
    /// nameserver on failure. Per-server success and failure update the
    /// smoothed RTT used for ordering, so the server list is self-healing.
    async fn race(&self, indices: &[usize], query_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let order = self.order_indices(indices);
        // Index into `order` of the next nameserver to try.
        let mut next = 0;
        // In-flight attempts, each yielding (nameserver index, start, result).
        let mut dials = FuturesUnordered::new();
        let mut last_err = None;
        // Timer after which to start the next attempt, or `None` for immediately.
        let next_attempt = MaybeFuture::None;
        tokio::pin!(next_attempt);

        loop {
            // Start the next attempt if one is due (no pending delay), we are
            // under the concurrency cap, and a nameserver remains.
            if next_attempt.is_none() && dials.len() < MAX_CONCURRENT_QUERIES && next < order.len()
            {
                let idx = order[next];
                next += 1;
                let start = Instant::now();
                dials.push(async move {
                    let ns = &self.nameservers[idx];
                    (idx, start, self.query_nameserver(ns, query_bytes).await)
                });
                // Pace the following attempt, unless this was the last server.
                if next < order.len() {
                    next_attempt
                        .as_mut()
                        .set_future(time::sleep(QUERY_ATTEMPT_DELAY));
                }
            }

            if dials.is_empty() && next >= order.len() {
                return Err(last_err.unwrap_or_else(|| e!(Error::NoResponse)));
            }

            tokio::select! {
                biased;
                // A dial attempt completed.
                Some((idx, start, res)) = dials.next(), if !dials.is_empty() => match res {
                    Ok(resp) => {
                        // A SERVFAIL or REFUSED response means this server cannot
                        // answer for the name (overloaded, not authoritative, policy
                        // block). Treat it like a transport failure and race the next
                        // server rather than making it the final answer; another
                        // nameserver may still resolve the name.
                        if let Some(rcode) = query::server_failure_rcode(&resp) {
                            self.rtt_map.record_failure(idx);
                            last_err =
                                Some(e!(Error::ServerError { rcode: format!("{rcode:?}") }));
                            // Fail fast: start the next attempt now rather than waiting.
                            next_attempt.as_mut().set_none();
                        } else {
                            self.rtt_map.record_success(idx, start.elapsed());
                            return Ok(resp);
                        }
                    }
                    Err(e) => {
                        self.rtt_map.record_failure(idx);
                        last_err = Some(e);
                        // Fail fast: start the next attempt now rather than waiting.
                        next_attempt.as_mut().set_none();
                    }
                },
                // The next attempt is due.
                () = &mut next_attempt, if next_attempt.is_some() => {
                    next_attempt.as_mut().set_none();
                }
            }
        }
    }

    /// Send a query and follow CNAME chains recursively if the response contains
    /// a CNAME but no records of the requested type.
    async fn send_query_following_cnames(
        &self,
        host: String,
        qtype: TYPE,
    ) -> Result<Vec<u8>, Error> {
        let mut current_host = host;
        for _ in 0..MAX_CNAME_DEPTH {
            let name = simple_dns::Name::new(&current_host)
                .map_err(|e| e!(Error::InvalidQuery, AnyError::from_std(e)))?;
            #[cfg_attr(not(feature = "dnssec"), allow(unused_mut))]
            let (id, mut query_bytes) = query::build_query(&current_host, qtype)?;
            // With validation on, request the RRSIG records by setting the DO bit
            // so the answer carries the signatures the chain walk needs.
            #[cfg(feature = "dnssec")]
            if self.validate_dnssec {
                query::set_do_bit(&mut query_bytes);
            }
            let response = self.send_query(&query_bytes).await?;
            let packet =
                simple_dns::Packet::parse(&response).map_err(|_| e!(Error::InvalidResponse))?;

            // Validate the id, QR bit, question, and RCODE before trusting the
            // packet to decide the answer or the next CNAME target. This is the
            // only check of the response against the name we actually asked for.
            query::check_response(&packet, id, &name, qtype)?;

            let has_answer = packet
                .answers
                .iter()
                .any(|rr| rr.rdata.type_code() == qtype);

            if has_answer {
                // Validate the answer before trusting it. Fail-closed: an
                // unsigned or bogus answer becomes an error rather than a result.
                #[cfg(feature = "dnssec")]
                if self.validate_dnssec {
                    self.validate_answer(&current_host, qtype, &response)
                        .await?;
                }
                return Ok(response);
            }

            // No records of the requested type -- follow CNAME if present.
            let Some(target) = query::cname_target(&packet, &current_host) else {
                // An empty answer (NODATA) carries no record to validate, but
                // under DNSSEC it must still be authenticated: a forged or
                // unsigned empty answer for a signed name would otherwise suppress
                // a real record. Fail-closed if the denial cannot be proven.
                #[cfg(feature = "dnssec")]
                if self.validate_dnssec {
                    self.validate_nodata(&current_host, qtype, &response)
                        .await?;
                }
                return Ok(response);
            };
            debug!(from = %current_host, to = %target, "following CNAME");
            current_host = target;
        }
        Err(e!(Error::InvalidResponse))
    }

    /// Looks up the records of `kind` for `name`, following CNAME chains.
    ///
    /// This is the one generic lookup path. It checks the cache, expands search
    /// domains, races the nameservers, parses the response into [`Record`]s of
    /// the requested [`RecordKind`], and caches a positive result. The typed
    /// methods ([`Self::lookup_ipv4`], [`Self::lookup_ipv6`], [`Self::lookup_txt`])
    /// are thin wrappers over it.
    ///
    /// Unlike the typed methods, this does not apply the RFC 6761 `localhost`
    /// rule or the hosts-file override; those are specific to A and AAAA lookups
    /// and live in [`Self::lookup_ipv4`] and [`Self::lookup_ipv6`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NxDomain`] when the name does not exist, and the other
    /// [`Error`] variants when every nameserver fails to answer.
    pub async fn lookup_record(
        &self,
        name: String,
        kind: RecordKind,
    ) -> Result<Vec<Record>, Error> {
        match self.cache.get(&name, kind) {
            Some(CachedResult::Positive(records)) => {
                trace!(%name, records = records.len(), ?kind, "cache hit");
                return Ok(records);
            }
            Some(CachedResult::NoData) => {
                trace!(%name, ?kind, "cache hit (NODATA)");
                return Ok(Vec::new());
            }
            Some(CachedResult::NxDomain) => {
                trace!(%name, ?kind, "cache hit (NXDOMAIN)");
                return Err(e!(Error::NxDomain));
            }
            None => {}
        }

        let mut last_err = None;
        // The first authoritative negative answer in search order, if any. A
        // positive answer returns immediately, so this only ever records the
        // earliest NODATA or NXDOMAIN a candidate produced. Honoring search
        // order keeps an appended candidate's NODATA from masking an NXDOMAIN
        // of the intended (bare) name.
        let mut first_negative: Option<CachedResult> = None;
        // Set when any candidate returned an indeterminate failure (SERVFAIL or
        // the like). We never learned whether that name exists, so a later
        // candidate's negative must not be cached: a flaky nameserver would
        // otherwise pin a live name as absent for the negative TTL.
        let mut saw_transient = false;
        let names = self.search_names(&name);
        let total = names.len();
        for (i, search_name) in names.into_iter().enumerate() {
            trace!(%search_name, ?kind, "resolving");
            let res = match self
                .send_query_following_cnames(search_name.clone(), kind.dns_type())
                .await
            {
                Ok(response) => query::parse_records(&response, kind).map_err(Error::from),
                Err(e) => Err(e),
            };
            match res {
                Ok((results, ttl)) if !results.is_empty() => {
                    debug!(%name, ?kind, ?results, ttl, "resolved");
                    self.cache
                        .insert(&name, kind, CachedResult::Positive(results.clone()), ttl);
                    return Ok(results);
                }
                // A successful but empty answer is NODATA: the name exists but
                // has no records of this kind.
                Ok(_) => {
                    if first_negative.is_none() {
                        first_negative = Some(CachedResult::NoData);
                    }
                }
                Err(e @ Error::NxDomain { .. }) => {
                    let remaining = total - i - 1;
                    trace!(%search_name, ?kind, remaining, reason = %e, "lookup failed");
                    if first_negative.is_none() {
                        first_negative = Some(CachedResult::NxDomain);
                    }
                    last_err = Some(e);
                }
                // An indeterminate failure: we never learned whether this name
                // exists, so try the next search candidate. Mark it so a later
                // candidate's negative is not cached, since a flaky nameserver
                // must not pin a name that a retry could still resolve.
                Err(
                    e @ (Error::ServerError { .. }
                    | Error::Timeout { .. }
                    | Error::NoResponse { .. }
                    | Error::Transport { .. }
                    | Error::InvalidResponse { .. }),
                ) => {
                    let remaining = total - i - 1;
                    trace!(%search_name, ?kind, remaining, reason = %e, "lookup failed");
                    saw_transient = true;
                    last_err = Some(e);
                }
                // A fatal error is not specific to this candidate: a query that
                // cannot be built or a missing TLS config would fail every
                // candidate identically, so there is nothing to gain by trying
                // the rest.
                Err(e) => {
                    debug!(%search_name, ?kind, reason = %e, "lookup failed");
                    return Err(e);
                }
            }
        }

        // No candidate held records. Report the first authoritative negative in
        // search order (NODATA is a successful empty result, NXDOMAIN an error),
        // and cache it briefly to blunt a thundering herd. Skip the cache when a
        // candidate failed indeterminately, since the negative may be wrong.
        match first_negative {
            Some(CachedResult::NoData) => {
                debug!(%name, ?kind, "resolved to no records (NODATA)");
                if !saw_transient {
                    self.cache
                        .insert(&name, kind, CachedResult::NoData, NEGATIVE_TTL_SECS);
                }
                Ok(Vec::new())
            }
            Some(CachedResult::NxDomain) => {
                debug!(%name, ?kind, "does not exist (NXDOMAIN)");
                if !saw_transient {
                    self.cache
                        .insert(&name, kind, CachedResult::NxDomain, NEGATIVE_TTL_SECS);
                }
                Err(e!(Error::NxDomain))
            }
            _ => {
                let err = last_err.unwrap_or_else(|| e!(Error::NoResponse));
                debug!(%name, ?kind, reason = %err, "resolve failed");
                Err(err)
            }
        }
    }

    /// Looks up the IPv4 (A) records for `host`.
    pub async fn lookup_ipv4(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv4Addr> + use<>, Error> {
        // RFC 6761: localhost always resolves to loopback.
        if is_localhost(&host) {
            return Ok(vec![Ipv4Addr::LOCALHOST].into_iter());
        }
        // A hosts-file entry overrides DNS, so check it ahead of the cache.
        if let Some(addrs) = self
            .search_names(&host)
            .iter()
            .find_map(|name| self.hosts.lookup_ipv4(name))
        {
            trace!(%host, ?addrs, "resolved from hosts file");
            return Ok(addrs.into_iter());
        }
        // Collect into a `Vec` so this path returns the same iterator type as the
        // localhost and hosts-file short-circuits above.
        let addrs: Vec<Ipv4Addr> = self
            .lookup_record(host, RecordKind::A)
            .await?
            .into_iter()
            .filter_map(|r| match r {
                Record::A(ip) => Some(ip),
                _ => None,
            })
            .collect();
        Ok(addrs.into_iter())
    }

    /// Looks up the IPv6 (AAAA) records for `host`.
    pub async fn lookup_ipv6(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv6Addr> + use<>, Error> {
        // RFC 6761: localhost always resolves to loopback.
        if is_localhost(&host) {
            return Ok(vec![Ipv6Addr::LOCALHOST].into_iter());
        }
        // A hosts-file entry overrides DNS, so check it ahead of the cache.
        if let Some(addrs) = self
            .search_names(&host)
            .iter()
            .find_map(|name| self.hosts.lookup_ipv6(name))
        {
            trace!(%host, ?addrs, "resolved from hosts file");
            return Ok(addrs.into_iter());
        }
        // Collect into a `Vec` so this path returns the same iterator type as the
        // localhost and hosts-file short-circuits above.
        let addrs: Vec<Ipv6Addr> = self
            .lookup_record(host, RecordKind::Aaaa)
            .await?
            .into_iter()
            .filter_map(|r| match r {
                Record::Aaaa(ip) => Some(ip),
                _ => None,
            })
            .collect();
        Ok(addrs.into_iter())
    }

    /// Looks up the TXT records for `host`.
    pub async fn lookup_txt(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = TxtRecordData> + use<>, Error> {
        let records: Vec<TxtRecordData> = self
            .lookup_record(host, RecordKind::Txt)
            .await?
            .into_iter()
            .filter_map(|r| match r {
                Record::Txt(txt) => Some(txt),
                _ => None,
            })
            .collect();
        Ok(records.into_iter())
    }

    /// Looks up the MX (mail exchange) records for `host`.
    pub async fn lookup_mx(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = MxRecordData> + use<>, Error> {
        let records: Vec<MxRecordData> = self
            .lookup_record(host, RecordKind::Mx)
            .await?
            .into_iter()
            .filter_map(|r| match r {
                Record::Mx(data) => Some(data),
                _ => None,
            })
            .collect();
        Ok(records.into_iter())
    }

    /// Looks up the SVCB (service binding) records for `host`.
    pub async fn lookup_svcb(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = SvcbRecordData> + use<>, Error> {
        let records: Vec<SvcbRecordData> = self
            .lookup_record(host, RecordKind::Svcb)
            .await?
            .into_iter()
            .filter_map(|r| match r {
                Record::Svcb(data) => Some(data),
                _ => None,
            })
            .collect();
        Ok(records.into_iter())
    }

    /// Looks up the HTTPS service binding records for `host`.
    ///
    /// Returns [`HttpsRecord`]s, which layer HTTPS-specific helpers (the
    /// AliasMode/ServiceMode distinction, the effective target name, and the
    /// default `http/1.1` ALPN) over the raw service binding.
    pub async fn lookup_https(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = HttpsRecord> + use<>, Error> {
        let records: Vec<HttpsRecord> = self
            .lookup_record(host, RecordKind::Https)
            .await?
            .into_iter()
            .filter_map(|r| match r {
                Record::Https(data) => Some(data),
                _ => None,
            })
            .collect();
        Ok(records.into_iter())
    }

    /// Looks up the NS (name server) records for `host`, returning the name of
    /// each authoritative name server.
    pub async fn lookup_ns(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = String> + use<>, Error> {
        let records: Vec<String> = self
            .lookup_record(host, RecordKind::Ns)
            .await?
            .into_iter()
            .filter_map(|r| match r {
                Record::Ns(name) => Some(name),
                _ => None,
            })
            .collect();
        Ok(records.into_iter())
    }

    /// Looks up the SRV (service location) records for `host`.
    pub async fn lookup_srv(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = SrvRecordData> + use<>, Error> {
        let records: Vec<SrvRecordData> = self
            .lookup_record(host, RecordKind::Srv)
            .await?
            .into_iter()
            .filter_map(|r| match r {
                Record::Srv(data) => Some(data),
                _ => None,
            })
            .collect();
        Ok(records.into_iter())
    }

    /// Clears the positive DNS cache.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Returns the configured nameservers and their transports.
    pub fn nameservers(&self) -> Vec<(std::net::SocketAddr, DnsProtocol)> {
        self.nameservers
            .iter()
            .map(|ns| (ns.addr, ns.protocol))
            .collect()
    }

    /// Overrides the search domains and `ndots` used for search-list expansion.
    ///
    /// Test-only hook for the ported search-list scenarios in [`crate::tests`],
    /// which drive the public API but cannot reach these fields, since the
    /// builder only populates them from the system configuration.
    #[cfg(test)]
    pub(crate) fn set_search(&mut self, search_domains: Vec<String>, ndots: usize) {
        self.search_domains = search_domains;
        self.ndots = ndots;
    }

    /// Rebuilds the resolver after a network change, carrying the cache across.
    ///
    /// Re-reads the system DNS configuration and rebinds sockets lazily. Carries
    /// the cache across so a network change does not start DNS cold, which would
    /// strand reconnects while the new nameservers settle (#4037).
    pub fn reset(&self) -> Self {
        Self::build_inner(self.builder.clone(), self.cache.clone())
    }
}

impl Default for SimpleDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{CachedResult, Hosts, SimpleDnsResolver};
    use crate::{DnsProtocol, FallbackMode, Nameserver, Record, RecordKind};

    /// A resolver with no nameservers and no fallback, for unit tests that do
    /// not query the network. Skips reading the host's DNS configuration so the
    /// tests stay hermetic.
    fn empty_resolver() -> SimpleDnsResolver {
        SimpleDnsResolver::builder()
            .without_system_defaults()
            .disable_fallback()
            .build()
    }

    const GOOGLE_DNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    const CLOUDFLARE_DNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
    #[cfg(with_crypto_provider)]
    const GOOGLE_DNS_TLS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 853);
    #[cfg(with_crypto_provider)]
    const CLOUDFLARE_DNS_HTTPS: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);

    /// Builds a resolver that queries a single nameserver over `proto`.
    fn with_proto(addr: SocketAddr, proto: DnsProtocol) -> SimpleDnsResolver {
        #[cfg_attr(not(with_crypto_provider), allow(unused_mut))]
        let mut builder = SimpleDnsResolver::builder()
            .without_system_defaults()
            .disable_fallback()
            .nameserver(addr, proto);
        #[cfg(with_crypto_provider)]
        if proto == DnsProtocol::Tls {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder = builder.tls_client_config(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            );
        }
        builder.build()
    }

    /// A resolver that reads the host system's DNS configuration.
    fn system_resolver() -> SimpleDnsResolver {
        SimpleDnsResolver::new()
    }

    async fn assert_resolves_ipv4(resolver: &SimpleDnsResolver, host: &str) {
        let addrs: Vec<_> = resolver
            .lookup_ipv4(host.to_string())
            .await
            .unwrap()
            .collect();
        assert!(!addrs.is_empty(), "{host} should have IPv4 addresses");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv4_udp() {
        assert_resolves_ipv4(&with_proto(GOOGLE_DNS, DnsProtocol::Udp), "google.com").await;
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv6_udp() {
        let resolver = with_proto(GOOGLE_DNS, DnsProtocol::Udp);
        let addrs: Vec<_> = resolver
            .lookup_ipv6("google.com".to_string())
            .await
            .unwrap()
            .collect();
        assert!(!addrs.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv4_tcp() {
        assert_resolves_ipv4(&with_proto(CLOUDFLARE_DNS, DnsProtocol::Tcp), "google.com").await;
    }

    #[cfg(with_crypto_provider)]
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv4_tls() {
        assert_resolves_ipv4(&with_proto(GOOGLE_DNS_TLS, DnsProtocol::Tls), "google.com").await;
    }

    #[cfg(with_crypto_provider)]
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv4_https() {
        assert_resolves_ipv4(
            &with_proto(CLOUDFLARE_DNS_HTTPS, DnsProtocol::Https),
            "google.com",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_txt_udp() {
        let resolver = with_proto(GOOGLE_DNS, DnsProtocol::Udp);
        let records: Vec<_> = resolver
            .lookup_txt("google.com".to_string())
            .await
            .unwrap()
            .collect();
        assert!(!records.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_system_defaults() {
        assert_resolves_ipv4(&system_resolver(), "google.com").await;
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_multiple_sites() {
        let resolver = system_resolver();
        for host in ["google.com", "cloudflare.com", "example.com"] {
            assert_resolves_ipv4(&resolver, host).await;
        }
    }

    /// Run with `cargo test -p iroh-relay resolve_success_and_nxdomain -- --ignored --nocapture`
    /// and `RUST_LOG=iroh_relay::dns=trace` to see the log output.
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_success_and_nxdomain() {
        let _ = tracing_subscriber::fmt::try_init();
        let resolver = with_proto(GOOGLE_DNS, DnsProtocol::Udp);

        tracing::info!("--- resolving example.com (first, expect network query) ---");
        let addrs: Vec<_> = resolver
            .lookup_ipv4("example.com".to_string())
            .await
            .unwrap()
            .collect();
        assert!(!addrs.is_empty());

        tracing::info!("--- resolving example.com (second, expect cache hit) ---");
        let addrs2: Vec<_> = resolver
            .lookup_ipv4("example.com".to_string())
            .await
            .unwrap()
            .collect();
        assert_eq!(addrs, addrs2);

        tracing::info!("--- resolving nonexistent domain (expect NXDOMAIN) ---");
        let err = resolver
            .lookup_ipv4("this-domain-does-not-exist.example.invalid".to_string())
            .await
            .map(|i| i.collect::<Vec<_>>());
        assert!(err.is_err(), "expected NXDOMAIN, got {err:?}");
    }

    /// End to end validation of a known DNSSEC-signed name against a public
    /// resolver. `cloudflare.com` is signed, so the chain from the root anchors
    /// down must validate and the lookup must succeed.
    #[cfg(feature = "dnssec")]
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn validate_dnssec_signed_name() {
        let resolver = SimpleDnsResolver::builder()
            .without_system_defaults()
            .disable_fallback()
            .nameserver(CLOUDFLARE_DNS, DnsProtocol::Udp)
            .validate_dnssec()
            .build();
        assert_resolves_ipv4(&resolver, "cloudflare.com").await;
    }

    /// End to end authentication of a NODATA denial (finding D3). `cloudflare.com`
    /// is signed and publishes no SRV record at its apex, so an SRV query returns
    /// an authenticated NODATA. The resolver must prove the denial and return a
    /// normal empty or NXDOMAIN result, never `DnssecBogus`. A regression that
    /// failed closed on a valid NSEC or NSEC3 would surface here as Bogus.
    #[cfg(feature = "dnssec")]
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn validate_dnssec_authenticated_nodata() {
        let resolver = SimpleDnsResolver::builder()
            .without_system_defaults()
            .disable_fallback()
            .nameserver(CLOUDFLARE_DNS, DnsProtocol::Udp)
            .validate_dnssec()
            .build();
        let result = resolver
            .lookup_record("cloudflare.com".to_string(), RecordKind::Srv)
            .await;
        assert!(
            !matches!(result, Err(crate::Error::DnssecBogus { .. })),
            "an authenticated NODATA must not be Bogus, got {result:?}"
        );
    }

    mod search_names {
        use super::*;

        fn resolver_with_search(domains: &[&str]) -> SimpleDnsResolver {
            let mut r = empty_resolver();
            r.search_domains = domains.iter().map(|s| s.to_string()).collect();
            r
        }

        #[test]
        fn no_search_domains() {
            let r = empty_resolver();
            assert_eq!(r.search_names("myhost"), vec!["myhost"]);
        }

        #[test]
        fn invalid_search_expansion_is_dropped() {
            // A search domain with an over-long (>63 byte) label makes the
            // expansion an invalid DNS name. It must be skipped, not carried into
            // the candidate list where it would abort the lookup, and the bare
            // name must still be tried.
            let long_label = "a".repeat(64);
            let r = resolver_with_search(&[long_label.as_str(), "example.com"]);
            assert_eq!(
                r.search_names("myhost"),
                vec!["myhost.example.com", "myhost"]
            );
        }

        #[test]
        fn fqdn_bypasses_search() {
            let r = resolver_with_search(&["example.com"]);
            assert_eq!(
                r.search_names("myhost.example.com."),
                vec!["myhost.example.com."]
            );
        }

        #[test]
        fn short_name_tries_search_first() {
            let r = resolver_with_search(&["example.com", "test.local"]);
            // "myhost" has 0 dots (< ndots=1), so search domains come first.
            assert_eq!(
                r.search_names("myhost"),
                vec!["myhost.example.com", "myhost.test.local", "myhost"]
            );
        }

        #[test]
        fn dotted_name_tries_bare_first() {
            let r = resolver_with_search(&["example.com"]);
            // "foo.bar" has 1 dot (>= ndots=1), so bare name comes first.
            assert_eq!(
                r.search_names("foo.bar"),
                vec!["foo.bar", "foo.bar.example.com"]
            );
        }

        #[test]
        fn multi_dot_name_tries_bare_first() {
            let r = resolver_with_search(&["example.com"]);
            assert_eq!(r.search_names("a.b.c"), vec!["a.b.c", "a.b.c.example.com"]);
        }

        #[test]
        fn high_ndots_k8s_style() {
            let mut r = empty_resolver();
            r.search_domains = vec!["ns.svc.cluster.local".into(), "svc.cluster.local".into()];
            r.ndots = 5;
            // 4 dots < ndots=5, so search domains come first (Kubernetes behavior).
            assert_eq!(
                r.search_names("my-svc.my-ns.svc.cluster.local"),
                vec![
                    "my-svc.my-ns.svc.cluster.local.ns.svc.cluster.local",
                    "my-svc.my-ns.svc.cluster.local.svc.cluster.local",
                    "my-svc.my-ns.svc.cluster.local",
                ]
            );
        }

        #[test]
        fn ndots_two_short_name_tries_search_first() {
            let mut r = resolver_with_search(&["example.com", "test.local"]);
            r.ndots = 2;
            // "foo.bar" has 2 labels, not more than ndots=2, so search first.
            assert_eq!(
                r.search_names("foo.bar"),
                vec!["foo.bar.example.com", "foo.bar.test.local", "foo.bar"]
            );
        }

        #[test]
        fn ndots_two_long_name_tries_bare_first() {
            let mut r = resolver_with_search(&["example.com"]);
            r.ndots = 2;
            // "a.b.c" has 3 labels, more than ndots=2, so the bare name comes first.
            assert_eq!(r.search_names("a.b.c"), vec!["a.b.c", "a.b.c.example.com"]);
        }

        #[test]
        fn duplicate_search_expansion_is_suppressed() {
            // A repeated search domain would regenerate the same candidate; the
            // deduplication keeps each name once while preserving order.
            let r = resolver_with_search(&["example.com", "example.com"]);
            assert_eq!(r.search_names("foo"), vec!["foo.example.com", "foo"]);
        }
    }

    /// Spawns a mock UDP nameserver that answers one query with `rcode`,
    /// echoing the question and adding `answer` as an A record when given.
    async fn spawn_mock_ns(
        rcode: simple_dns::RCODE,
        answer: Option<Ipv4Addr>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        use simple_dns::{
            CLASS, Packet, PacketFlag, ResourceRecord,
            rdata::{A, RData},
        };

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let query = Packet::parse(&buf[..len]).unwrap();
            let question = query.questions[0].clone();
            let mut reply = Packet::new_reply(query.id());
            reply.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
            *reply.rcode_mut() = rcode;
            if let Some(ip) = answer {
                reply.answers.push(ResourceRecord::new(
                    question.qname.clone(),
                    CLASS::IN,
                    300,
                    RData::A(A {
                        address: u32::from(ip),
                    }),
                ));
            }
            reply.questions.push(question);
            socket
                .send_to(&reply.build_bytes_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        (addr, handle)
    }

    /// A SERVFAIL or REFUSED response from the fastest nameserver must not be
    /// the final answer: the resolver races on to a nameserver that can answer.
    #[tokio::test]
    async fn servfail_winner_falls_through_to_next_nameserver() {
        let (bad, bad_handle) = spawn_mock_ns(simple_dns::RCODE::ServerFailure, None).await;
        let (good, good_handle) =
            spawn_mock_ns(simple_dns::RCODE::NoError, Some(Ipv4Addr::new(10, 1, 2, 3))).await;

        // `bad` is listed first, so it is the fastest by default ordering and
        // wins the race with a SERVFAIL; the lookup must fall through to `good`.
        let resolver = SimpleDnsResolver::builder()
            .without_system_defaults()
            .disable_fallback()
            .nameservers([(bad, DnsProtocol::Udp), (good, DnsProtocol::Udp)])
            .build();

        let addrs: Vec<_> = resolver
            .lookup_ipv4("test.example".to_string())
            .await
            .unwrap()
            .collect();
        assert_eq!(addrs, [IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))]);

        bad_handle.await.unwrap();
        good_handle.await.unwrap();
    }

    /// A dummy nameserver address that is never actually queried, used to check
    /// how the builder lays out the primary and fallback tiers.
    const DUMMY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53);

    /// In the default `Deferred` mode the fallback nameservers sit behind the
    /// primary tier rather than racing with it.
    #[test]
    fn deferred_keeps_fallback_in_second_tier() {
        let r = SimpleDnsResolver::builder()
            .without_system_defaults()
            .nameserver(DUMMY, DnsProtocol::Udp)
            .fallback_nameservers([Nameserver::new(DUMMY, DnsProtocol::Udp)])
            .build();
        assert_eq!(r.primary_count, 1);
        assert_eq!(r.nameservers.len(), 2);
    }

    /// `always_use_fallback` merges the fallback nameservers into the primary
    /// tier so they race from the start.
    #[test]
    fn always_use_fallback_merges_tiers() {
        let r = SimpleDnsResolver::builder()
            .without_system_defaults()
            .nameserver(DUMMY, DnsProtocol::Udp)
            .fallback_nameservers([Nameserver::new(DUMMY, DnsProtocol::Udp)])
            .always_use_fallback()
            .build();
        assert_eq!(r.primary_count, 2);
        assert_eq!(r.nameservers.len(), 2);
    }

    /// `disable_fallback` drops the fallback tier entirely.
    #[test]
    fn disable_fallback_drops_second_tier() {
        let r = SimpleDnsResolver::builder()
            .without_system_defaults()
            .nameserver(DUMMY, DnsProtocol::Udp)
            .disable_fallback()
            .build();
        assert_eq!(r.primary_count, 1);
        assert_eq!(r.nameservers.len(), 1);
    }

    /// With no system configuration, `IfSystemUnavailable` includes the fallback
    /// nameservers, and merges them into the primary tier rather than deferring.
    #[test]
    fn if_system_unavailable_includes_fallback_when_system_empty() {
        let r = SimpleDnsResolver::builder()
            .without_system_defaults()
            .fallback_mode(FallbackMode::IfSystemUnavailable)
            .fallback_nameservers([Nameserver::new(DUMMY, DnsProtocol::Udp)])
            .build();
        assert_eq!(r.nameservers.len(), 1);
        assert_eq!(r.primary_count, 1);
    }

    /// When every primary nameserver fails, the lookup escalates to the fallback
    /// tier, which resolves the name.
    #[tokio::test]
    async fn escalates_to_fallback_when_primary_fails() {
        let (bad, bad_handle) = spawn_mock_ns(simple_dns::RCODE::ServerFailure, None).await;
        let (good, good_handle) =
            spawn_mock_ns(simple_dns::RCODE::NoError, Some(Ipv4Addr::new(10, 4, 5, 6))).await;

        // The primary tier is only `bad`, which SERVFAILs; the fallback tier is
        // `good`, reached only after the primary tier is exhausted.
        let resolver = SimpleDnsResolver::builder()
            .without_system_defaults()
            .nameserver(bad, DnsProtocol::Udp)
            .fallback_nameservers([Nameserver::new(good, DnsProtocol::Udp)])
            .build();

        let addrs: Vec<_> = resolver
            .lookup_ipv4("test.example".to_string())
            .await
            .unwrap()
            .collect();
        assert_eq!(addrs, [IpAddr::V4(Ipv4Addr::new(10, 4, 5, 6))]);

        bad_handle.await.unwrap();
        good_handle.await.unwrap();
    }

    /// A hosts-file entry must override DNS and resolve without any network
    /// query, the way the old hickory-backed resolver honored `/etc/hosts`.
    #[tokio::test]
    async fn hosts_file_overrides_dns() {
        let mut resolver = empty_resolver();
        resolver.hosts = Hosts::from_content("10.0.1.10 myrelay.test\n::1 myrelay.test\n");

        let v4: Vec<_> = resolver
            .lookup_ipv4("myrelay.test".to_string())
            .await
            .unwrap()
            .collect();
        assert_eq!(v4, [Ipv4Addr::new(10, 0, 1, 10)]);

        // A trailing dot (FQDN form) still matches the hosts entry.
        let v6: Vec<_> = resolver
            .lookup_ipv6("myrelay.test.".to_string())
            .await
            .unwrap()
            .collect();
        assert_eq!(v6, [Ipv6Addr::LOCALHOST]);
    }

    /// A major network change rebuilds the resolver via [`SimpleDnsResolver::reset`];
    /// the DNS cache must carry across so reconnects keep resolving while the new
    /// nameservers settle (issue #4037).
    #[test]
    fn cache_survives_reset() {
        let r = empty_resolver();
        r.cache.insert(
            "example.com",
            RecordKind::A,
            CachedResult::Positive(vec![Record::A(Ipv4Addr::LOCALHOST)]),
            300,
        );

        let reset = r.reset();

        let cached = reset.cache.get("example.com", RecordKind::A);
        let survived = matches!(
            cached,
            Some(CachedResult::Positive(ref records))
                if matches!(records.as_slice(), [Record::A(addr)] if *addr == Ipv4Addr::LOCALHOST)
        );
        assert!(survived, "cache entry should survive reset, got {cached:?}");
    }
}
