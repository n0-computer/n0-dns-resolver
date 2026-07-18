//! TTL-based DNS cache with least-recently-used eviction.

use std::{
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use lru::LruCache;

use crate::{Record, RecordKind};

/// Maximum number of entries in the DNS cache.
const MAX_CACHE_ENTRIES: usize = 512;

/// Maximum TTL for cache entries (1 day).
///
/// Prevents malicious or misconfigured servers from making entries
/// effectively permanent by returning very large TTL values.
const MAX_TTL_SECS: u32 = 86400;

/// How long a negative result (NODATA or NXDOMAIN) is cached.
///
/// Kept short so a thundering herd of concurrent lookups for the same absent
/// name collapses to one network query, while a name that becomes resolvable
/// (for example an endpoint that just published its records) is still picked up
/// promptly. A longer, SOA-derived negative TTL (RFC 2308) would need parsing
/// the authority section, which we do not do.
pub(super) const NEGATIVE_TTL_SECS: u32 = 30;

/// A cached lookup outcome: records, or an authenticated absence.
#[derive(Debug, Clone)]
pub(super) enum CachedResult {
    /// Records of the queried kind were found.
    Positive(Vec<Record>),
    /// The name exists but has no records of the queried kind (NODATA).
    NoData,
    /// The name does not exist (NXDOMAIN).
    NxDomain,
}

/// Normalizes a host to its cache-key form: lowercased, with any single trailing
/// dot removed.
///
/// DNS names are case-insensitive, and a fully-qualified name with a trailing dot
/// denotes the same node as the bare name. Normalizing here keeps
/// `Example.COM.` and `example.com` in one entry, matching the hosts-file
/// normalization in `Hosts::normalize`.
fn normalize(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// Hashes `(host, kind)` into a u64 key for allocation-free cache lookups.
///
/// A hash collision between different (host, kind) pairs could return records
/// for the wrong entry. The kind is part of the key, so a collision can only be
/// between two distinct host+kind pairs; [`DnsCache::get`] rechecks both against
/// the stored entry and treats a mismatch as a miss. With 64-bit hashes and a
/// 512-entry cache, the birthday-bound probability is ~1.4e-14 per lookup,
/// negligible in practice.
///
/// `host` is expected to already be [`normalize`]d so that names differing only
/// in case or a trailing dot hash to the same key.
///
/// A pre-hashed `u64` key is used rather than a `Hash`-deriving key struct on
/// purpose: the latter would allocate a `String` for the key on every `get`,
/// whereas hashing the borrowed `&str` here keeps lookups allocation-free.
fn cache_key(host: &str, kind: RecordKind) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    host.hash(&mut hasher);
    kind.hash(&mut hasher);
    hasher.finish()
}

/// A cache entry with TTL expiry tracking.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The host and record kind this entry is for. Verified on lookup so a
    /// `u64` key collision returns a miss rather than another entry's records.
    host: String,
    kind: RecordKind,
    result: CachedResult,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// Thread-safe DNS cache with LRU eviction and TTL-based expiry.
///
/// Uses pre-hashed u64 keys to avoid allocating a `String` on every lookup.
/// The only remaining per-hit allocation is the `records.clone()` on cache hit,
/// necessary because the result must outlive the lock guard.
///
/// Cloning shares the same underlying cache, so a resolver rebuilt on a network
/// change (see [`DnsResolver::reset`]) can carry its cache across rather
/// than starting cold while DNS is still in flux.
///
/// [`DnsResolver::reset`]: super::DnsResolver::reset
#[derive(Debug, Clone)]
pub(super) struct DnsCache {
    inner: Arc<Mutex<LruCache<u64, CacheEntry>>>,
}

impl DnsCache {
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(MAX_CACHE_ENTRIES).expect("non-zero"),
            ))),
        }
    }

    /// Looks up a cached result, returning `None` if it is absent or expired.
    pub(super) fn get(&self, host: &str, kind: RecordKind) -> Option<CachedResult> {
        let host = normalize(host);
        let key = cache_key(&host, kind);
        let mut inner = self.inner.lock().expect("poisoned");
        let entry = inner.get(&key)?;
        // Reject `u64` key collisions: only serve an exact host+kind match.
        if entry.host != host || entry.kind != kind {
            return None;
        }
        if entry.is_expired() {
            inner.pop(&key);
            return None;
        }
        Some(entry.result.clone())
    }

    /// Inserts a result into the cache under the given TTL.
    ///
    /// A TTL of 0 means do not cache. Positive results carry the response's TTL;
    /// negative results (NODATA, NXDOMAIN) are cached under [`NEGATIVE_TTL_SECS`]
    /// so a burst of concurrent lookups for the same absent name collapses to
    /// one network query.
    pub(super) fn insert(&self, host: &str, kind: RecordKind, result: CachedResult, ttl: u32) {
        if ttl == 0 {
            return;
        }
        let host = normalize(host);
        let entry = CacheEntry {
            host: host.clone(),
            kind,
            result,
            inserted_at: Instant::now(),
            ttl: Duration::from_secs(ttl.min(MAX_TTL_SECS) as u64),
        };
        self.inner
            .lock()
            .expect("poisoned")
            .put(cache_key(&host, kind), entry);
    }

    /// Clears all cache entries.
    pub(super) fn clear(&self) {
        self.inner.lock().expect("poisoned").clear();
    }

    /// Returns the stored TTL for `host`/`kind`, for tests that assert clamping.
    #[cfg(test)]
    fn stored_ttl(&self, host: &str, kind: RecordKind) -> Option<Duration> {
        let host = normalize(host);
        let mut inner = self.inner.lock().expect("poisoned");
        inner.get(&cache_key(&host, kind)).map(|entry| entry.ttl)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    fn positive() -> CachedResult {
        CachedResult::Positive(vec![Record::A(ADDR)])
    }

    /// `Record` is not `PartialEq` (part of the public API), so assert a single-A
    /// positive hit by unwrapping the one record and checking its address.
    fn assert_single_a(result: Option<CachedResult>, expected: Ipv4Addr) {
        match result {
            Some(CachedResult::Positive(records)) => match records.as_slice() {
                [Record::A(ip)] => assert_eq!(*ip, expected),
                other => panic!("expected one A record for {expected}, got {other:?}"),
            },
            other => panic!("expected a positive result for {expected}, got {other:?}"),
        }
    }

    #[test]
    fn ttl_zero_is_not_cached() {
        let cache = DnsCache::new();
        cache.insert("example.com", RecordKind::A, positive(), 0);
        assert!(cache.get("example.com", RecordKind::A).is_none());
    }

    #[test]
    fn hit_within_ttl() {
        let cache = DnsCache::new();
        cache.insert("example.com", RecordKind::A, positive(), 300);
        assert_single_a(cache.get("example.com", RecordKind::A), ADDR);
    }

    #[test]
    fn ttl_over_max_is_clamped() {
        let cache = DnsCache::new();
        cache.insert(
            "example.com",
            RecordKind::A,
            positive(),
            MAX_TTL_SECS + 1000,
        );
        assert_eq!(
            cache.stored_ttl("example.com", RecordKind::A),
            Some(Duration::from_secs(u64::from(MAX_TTL_SECS)))
        );
    }

    #[test]
    fn lookup_is_case_and_trailing_dot_insensitive() {
        let cache = DnsCache::new();
        cache.insert("example.com", RecordKind::A, positive(), 300);
        assert_single_a(cache.get("Example.COM.", RecordKind::A), ADDR);
    }

    #[test]
    fn negative_results_are_cached() {
        let cache = DnsCache::new();
        cache.insert(
            "nx.example",
            RecordKind::A,
            CachedResult::NxDomain,
            NEGATIVE_TTL_SECS,
        );
        assert!(matches!(
            cache.get("nx.example", RecordKind::A),
            Some(CachedResult::NxDomain)
        ));
        cache.insert(
            "nodata.example",
            RecordKind::Aaaa,
            CachedResult::NoData,
            NEGATIVE_TTL_SECS,
        );
        assert!(matches!(
            cache.get("nodata.example", RecordKind::Aaaa),
            Some(CachedResult::NoData)
        ));
    }
}
