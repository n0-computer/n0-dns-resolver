//! Resolver-side DNSSEC validation: fetch the chain and walk it (feature `dnssec`).
//!
//! [`SimpleDnsResolver::validate_answer`] is the entry point the lookup path
//! calls when [`crate::Builder::validate_dnssec`] is set. It extracts the answer
//! RRset and its RRSIG, then walks the chain of trust from the embedded root
//! anchors down to the signing zone, fetching each zone's DNSKEY RRset and the
//! delegating DS along the way.
//!
//! Validation is fail-closed. An answer with no RRSIG, a zone with no fetchable
//! DNSKEY or DS RRset, or a chain that does not validate all map to
//! [`crate::Error::DnssecBogus`]. Three cases lean on the denial-of-existence
//! proofs. A wildcard-expanded answer validates only when the authority section
//! proves no closer match exists. A delegation with no DS is accepted as
//! Insecure (unsigned) when the authority section proves the DS is truly absent,
//! rather than being rejected. A NODATA answer (no record of the queried type
//! and no CNAME) is authenticated against the signing zone with [`prove_nodata`]:
//! the SOA owner in the authority section names the zone, and the denial must be
//! proven or the answer is Bogus. Only the final answer RRset is validated; CNAME
//! hops are followed but not individually checked. Authenticating an NXDOMAIN
//! answer is not yet wired, because [`super::query::check_response`] turns it into
//! [`crate::Error::NxDomain`] before validation runs.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use lru::LruCache;
use n0_error::{AnyError, e, stack_error};
use simple_dns::{
    Name, Packet, TYPE,
    rdata::{DNSKEY, RData, RRSIG},
};
use tracing::{debug, warn};

use super::SimpleDnsResolver;
use crate::{
    Error,
    dnssec::{
        ChainError, DelegatedZone, DenialError, ROOT_TRUST_ANCHORS, ResourceRecord, SignedRrset,
        build_dnssec_query, descend_zone, prove_no_ds, prove_nodata, prove_wildcard, trust_root,
        verify_rrset_with_keys,
    },
};

/// The deepest signing zone the chain walk will fetch keys for.
///
/// [`SimpleDnsResolver::trusted_keys_for_zone`] walks every ancestor zone cut of
/// the signing zone, issuing DS and DNSKEY queries at each. A [`Name`] may hold
/// up to roughly 127 labels, which would be around 250 outbound queries for a
/// single lookup. Real signing zones are only a few labels deep, so a zone with
/// more ancestor cuts than this fails closed rather than fetching unboundedly.
const MAX_ZONE_DEPTH: usize = 16;

/// Maximum number of zones whose trust result is cached at once.
const MAX_TRUSTED_ZONE_ENTRIES: usize = 64;

/// How long a cached zone-trust result stays valid.
///
/// Short so a DNSKEY rollover or a DS change is picked up within a minute, while
/// still sparing repeated validations of the same signing zone (and shared
/// ancestors like the root and `com`) a fresh chain fetch each time.
const TRUSTED_ZONE_TTL: Duration = Duration::from_secs(60);

/// A reason answer validation could not complete or did not pass.
///
/// Every variant means the answer is Bogus under the fail-closed policy and maps
/// to [`Error::DnssecBogus`].
#[stack_error(derive, add_meta, std_sources)]
enum ValidateError {
    /// The answer carried no RRSIG covering the queried type.
    #[error("answer carried no RRSIG for the queried type")]
    MissingSignature {},
    /// The RRSIG signer name is neither the answer's owner name nor an ancestor
    /// of it, so the signing zone is not authoritative for the answer.
    #[error("RRSIG signer {signer} is not authoritative for {owner}")]
    SignerNotAuthoritative { signer: String, owner: String },
    /// The answer was synthesized from a wildcard, but the authority section did
    /// not prove that no closer non-wildcard match exists.
    #[error("wildcard-expanded answer for {owner} has no closer-match proof")]
    WildcardUnproven { owner: String, source: DenialError },
    /// No DNSKEY RRset with its signature could be fetched for a zone.
    #[error("no signed DNSKEY RRset for zone {zone}")]
    MissingDnskey { zone: String },
    /// Fetching the DNSKEY or DS records failed at the query layer.
    #[error("failed to fetch DNSSEC records")]
    Fetch { source: AnyError },
    /// The assembled chain of trust did not validate.
    #[error("chain of trust did not validate")]
    Chain { source: ChainError },
    /// A NODATA response carried no SOA record, so the signing zone is unknown
    /// and the denial cannot be authenticated.
    #[error("NODATA response has no SOA to name the signing zone")]
    MissingSoa {},
    /// The queried name in a NODATA response did not parse as a domain name.
    #[error("NODATA response is for an invalid name {name}")]
    InvalidQname { name: String },
    /// The SOA that named the signing zone is not the queried name's own zone or
    /// an ancestor of it, so it cannot authoritatively deny records for the name.
    #[error("NODATA SOA zone {zone} is not authoritative for {name}")]
    NonAuthoritativeSoa { zone: String, name: String },
    /// The authority section did not prove the queried type is absent (NODATA).
    #[error("NODATA denial for {name} is not proven")]
    DenialUnproven { name: String, source: DenialError },
    /// The signing zone is nested deeper than [`MAX_ZONE_DEPTH`] allows, so the
    /// chain walk would issue an unbounded number of queries.
    #[error("signing zone {zone} is too deep ({depth} labels) to validate")]
    ZoneTooDeep { zone: String, depth: usize },
}

/// The result of building a zone's trusted DNSKEY set.
#[derive(Debug, Clone)]
enum ZoneTrust {
    /// The zone is signed; these DNSKEYs are trusted for it.
    Secure(Vec<DNSKEY<'static>>),
    /// An ancestor delegation proved no DS, so the zone and everything below the
    /// cut is unsigned. The caller accepts the answer as-is (Insecure).
    Insecure,
}

/// A cache of validated per-zone trust results, keyed by zone name.
///
/// Only validated conclusions are stored: a Secure zone's trusted DNSKEY set or
/// a proven-insecure delegation. Entries expire after [`TRUSTED_ZONE_TTL`], so a
/// key rollover is picked up promptly. Cloning shares the underlying map, so a
/// resolver rebuilt on a network change keeps one cache across its clones.
#[derive(Debug, Clone)]
pub(super) struct DnssecCache {
    inner: Arc<Mutex<LruCache<String, CachedTrust>>>,
}

/// A cached zone-trust result together with its expiry deadline.
#[derive(Debug, Clone)]
struct CachedTrust {
    trust: ZoneTrust,
    expires_at: Instant,
}

impl DnssecCache {
    /// Creates an empty cache.
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(MAX_TRUSTED_ZONE_ENTRIES).expect("non-zero"),
            ))),
        }
    }

    /// Returns the cached trust for `zone`, or `None` when it is absent or has
    /// expired.
    fn get(&self, zone: &str) -> Option<ZoneTrust> {
        let mut inner = self.inner.lock().expect("poisoned");
        let entry = inner.get(zone)?;
        if Instant::now() >= entry.expires_at {
            inner.pop(zone);
            return None;
        }
        Some(entry.trust.clone())
    }

    /// Stores a validated trust result for `zone`.
    fn insert(&self, zone: &str, trust: ZoneTrust) {
        let entry = CachedTrust {
            trust,
            expires_at: Instant::now() + TRUSTED_ZONE_TTL,
        };
        self.inner
            .lock()
            .expect("poisoned")
            .put(zone.to_string(), entry);
    }
}

impl SimpleDnsResolver {
    /// Validates a DNS response for `qtype` against the DNSSEC chain of trust.
    ///
    /// Returns `Ok(())` when the answer's RRset validates from the embedded root
    /// anchors down. Any failure is fail-closed and surfaces as
    /// [`Error::DnssecBogus`].
    pub(super) async fn validate_answer(
        &self,
        host: &str,
        qtype: TYPE,
        response: &[u8],
    ) -> Result<(), Error> {
        match self.validate_inner(host, qtype, response).await {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!(%err, "DNSSEC validation rejected an answer");
                Err(e!(Error::DnssecBogus, AnyError::from_stack(err)))
            }
        }
    }

    /// Assembles and walks the chain of trust for the answer to `host`.
    async fn validate_inner(
        &self,
        host: &str,
        qtype: TYPE,
        response: &[u8],
    ) -> Result<(), ValidateError> {
        // Bind validation to the queried name: only an RRset owned by `host`
        // counts. Without this a response could carry a validly signed RRset for
        // an unrelated name that the attacker controls, pass the chain walk on
        // that RRset, and slip forged records for `host` through alongside it.
        let mut target = parse_signed_rrset(response, host, qtype)
            .ok_or_else(|| e!(ValidateError::MissingSignature))?;

        // The signer names are attacker-controlled, so each must be checked
        // against the answer before it is trusted to name the signing zone. Only
        // the answer's own zone or an ancestor may sign it (RFC 4035 5.3.1);
        // otherwise the holder of any signed zone could sign records for any name
        // and the chain to the root would still validate. Drop every RRSIG whose
        // signer is not authoritative and require at least one to remain. All
        // RRSIGs over a single RRset name the same zone, so the survivors share a
        // signer.
        let owner = target
            .records
            .first()
            .ok_or_else(|| e!(ValidateError::MissingSignature))?
            .name
            .clone();
        let rejected_signer = target
            .rrsigs
            .iter()
            .find(|sig| !signer_is_authoritative(&sig.signer_name, &owner))
            .map(|sig| sig.signer_name.to_string());
        target
            .rrsigs
            .retain(|sig| signer_is_authoritative(&sig.signer_name, &owner));

        // Each surviving signer names a candidate signing zone. Honest RRSIGs
        // over one RRset all name the RRset's real apex, but an on-path attacker
        // can inject an extra RRSIG signed by, say, the answer owner itself, which
        // points the chain walk at a zone cut that does not exist. Committing to a
        // single signer (even the most specific one) would then reject a
        // legitimate answer. Instead try every distinct candidate and accept if
        // any one yields a valid chain and signature; only fail if all of them do.
        // The candidates are ordered most specific first so the RRset's real apex,
        // the common case, is tried before an injected ancestor signer.
        let candidates = candidate_signers(&target.rrsigs);
        let mut last_err = None;
        for signing_rrsig in &candidates {
            match self
                .validate_with_signer(&target, &owner, signing_rrsig, response)
                .await
            {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Some(err),
            }
        }
        // No candidate validated. Surface the last chain failure, or the
        // authority rejection when there was no authoritative signer to try.
        Err(last_err.unwrap_or_else(|| {
            e!(ValidateError::SignerNotAuthoritative {
                signer: rejected_signer.unwrap_or_default(),
                owner: owner.to_string(),
            })
        }))
    }

    /// Validates the answer RRset against one candidate signing zone.
    ///
    /// Builds the trusted DNSKEY set for the zone named by `signing_rrsig`, then
    /// verifies the answer RRset under it. When the RRSIG is a wildcard expansion,
    /// the authority section must also prove no closer match exists. Returns
    /// `Ok(())` when this candidate proves the answer (or its zone is proven
    /// insecure); any failure is returned so the caller can try another candidate.
    async fn validate_with_signer(
        &self,
        target: &SignedRrset<'static>,
        owner: &Name<'static>,
        signing_rrsig: &RRSIG<'static>,
        response: &[u8],
    ) -> Result<(), ValidateError> {
        // A wildcard-expanded answer (RRSIG labels below the owner's label count)
        // is a valid signature over `*.zone`. Proving it applies to this name
        // needs an authority-section NSEC or NSEC3 showing no closer match exists
        // (RFC 4035 section 5.3.4); that proof runs after the chain validates the
        // signing zone's keys.
        let wildcard_labels =
            is_wildcard_expansion(signing_rrsig.labels, owner).then_some(signing_rrsig.labels);

        // The RRSIG signer names the zone that signed the answer. Build its
        // trusted DNSKEY set by walking the chain from the root down.
        let signing_zone = signing_rrsig.signer_name.to_string();
        debug!(zone = %signing_zone, "validating answer against DNSSEC chain");

        let trusted = match self.trusted_keys_for_zone(&signing_zone).await? {
            // A proven-absent DS above the signing zone makes it unsigned, so the
            // answer is Insecure and accepted as-is (RFC 4035 section 4.3).
            ZoneTrust::Insecure => return Ok(()),
            ZoneTrust::Secure(keys) => keys,
        };

        // The signing zone's keys are now trusted. Validate the answer RRset.
        verify_rrset_with_keys(target, &trusted)
            .map_err(|source| e!(ValidateError::Chain, source))?;

        // Finally, a wildcard-expanded answer needs its closer-match proof from
        // the same response's authority section, validated against the signing
        // zone keys we just trusted.
        if let Some(labels) = wildcard_labels {
            let authority = authority_records(response);
            prove_wildcard(owner, labels, &authority, &trusted).map_err(|source| {
                e!(ValidateError::WildcardUnproven {
                    owner: owner.to_string(),
                    source,
                })
            })?;
        }
        Ok(())
    }

    /// Authenticates a NODATA denial for `host`/`qtype`, fail-closed.
    ///
    /// A response with no record of the queried type and no CNAME to follow is a
    /// NODATA answer. Under validation it must be authenticated, or an on-path
    /// attacker could suppress a signed record by returning a forged empty answer.
    /// Returns `Ok(())` when the authority section proves the type is absent under
    /// the signing zone, or when that zone is proven insecure (unsigned). Any
    /// other outcome is fail-closed and surfaces as [`Error::DnssecBogus`].
    pub(super) async fn validate_nodata(
        &self,
        host: &str,
        qtype: TYPE,
        response: &[u8],
    ) -> Result<(), Error> {
        match self.validate_nodata_inner(host, qtype, response).await {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!(%err, "DNSSEC validation rejected a NODATA answer");
                Err(e!(Error::DnssecBogus, AnyError::from_stack(err)))
            }
        }
    }

    /// Proves the NODATA denial for `host`/`qtype` from the authority section.
    async fn validate_nodata_inner(
        &self,
        host: &str,
        qtype: TYPE,
        response: &[u8],
    ) -> Result<(), ValidateError> {
        let authority = authority_records(response);
        // The SOA in the authority section names the zone that answered the
        // denial, and its keys sign the accompanying NSEC or NSEC3 records. With
        // no SOA the signing zone is unknown, so the denial cannot be
        // authenticated and stays fail-closed.
        let zone = soa_zone(&authority).ok_or_else(|| e!(ValidateError::MissingSoa))?;
        let qname = Name::new(host)
            .map_err(|_| {
                e!(ValidateError::InvalidQname {
                    name: host.to_string(),
                })
            })?
            .into_owned();

        // The SOA owner is attacker-controlled, so it must be checked before it
        // is trusted to name the signing zone. Only the queried name's own zone
        // or an ancestor may authoritatively deny records for it; otherwise the
        // holder of any signed zone could sign an NSEC for this name and forge a
        // NODATA to suppress a real record. The authoritative relation is the same
        // suffix check the positive path uses on RRSIG signers.
        let authoritative = Name::new(&zone)
            .map(|zone_name| signer_is_authoritative(&zone_name, &qname))
            .unwrap_or(false);
        if !authoritative {
            return Err(e!(ValidateError::NonAuthoritativeSoa {
                zone: zone.clone(),
                name: host.to_string(),
            }));
        }

        let keys = match self.trusted_keys_for_zone(&zone).await? {
            ZoneTrust::Insecure => return Ok(()),
            ZoneTrust::Secure(keys) => keys,
        };

        prove_nodata(&qname, u16::from(qtype), &authority, &keys).map_err(|source| {
            e!(ValidateError::DenialUnproven {
                name: host.to_string(),
                source,
            })
        })
    }

    /// Builds the trusted DNSKEY set for `zone` by walking the chain of trust
    /// from the embedded root anchors down to it.
    ///
    /// Anchors the root against [`ROOT_TRUST_ANCHORS`], then discovers the real
    /// secure zone cuts between the root and `zone` and descends each one that
    /// publishes a signed DS RRset. Not every label boundary is a delegation: a
    /// zone can hold names several labels deep, and a delegation may skip labels,
    /// so the DS is queried at each ancestor and only the signed ones are
    /// descended.
    ///
    /// Returns [`ZoneTrust::Insecure`] when an ancestor delegation is proven to
    /// have no DS, which makes `zone` unsigned (RFC 4035 section 4.3, RFC 5155
    /// section 8.6). Without such a proof an ancestor with no DS is treated as a
    /// non-cut and skipped, which keeps the walk fail-closed: a stripped DS on a
    /// genuinely signed delegation yields no valid absence proof, so the zone's
    /// keys never enter the trusted set and the answer's RRSIG matches none.
    async fn trusted_keys_for_zone(&self, zone: &str) -> Result<ZoneTrust, ValidateError> {
        // Bound the walk before any fetch. Each ancestor zone cut costs uncached
        // DS and DNSKEY queries, so a deep name could drive hundreds of outbound
        // queries per lookup. Real signing zones are shallow, so a zone with more
        // ancestor cuts than the cap fails closed (Bogus) rather than fetching
        // unboundedly.
        let ancestors = zone_ancestors(zone);
        if ancestors.len() > MAX_ZONE_DEPTH {
            return Err(e!(ValidateError::ZoneTooDeep {
                zone: zone.to_string(),
                depth: ancestors.len(),
            }));
        }

        // A validated trust result for this zone may already be cached from an
        // earlier lookup, sparing the whole chain fetch.
        if let Some(trust) = self.dnssec_cache.get(zone) {
            return Ok(trust);
        }

        let root_dnskeys = self
            .fetch_signed_rrset(".", TYPE::DNSKEY)
            .await?
            .ok_or_else(|| {
                e!(ValidateError::MissingDnskey {
                    zone: ".".to_string(),
                })
            })?;
        // Anchor the root and carry the trusted DNSKEY set down each zone cut.
        let mut trusted = trust_root(&root_dnskeys, ROOT_TRUST_ANCHORS)
            .map_err(|source| e!(ValidateError::Chain, source))?;

        for ancestor in ancestors {
            let ds_response = self.fetch_raw(&ancestor, TYPE::DS).await?;
            if let Some(delegation) = parse_signed_rrset(&ds_response, &ancestor, TYPE::DS) {
                let dnskeys = self
                    .fetch_signed_rrset(&ancestor, TYPE::DNSKEY)
                    .await?
                    .ok_or_else(|| {
                        e!(ValidateError::MissingDnskey {
                            zone: ancestor.clone(),
                        })
                    })?;
                let delegated = DelegatedZone {
                    delegation,
                    dnskeys,
                };
                trusted = descend_zone(&trusted, &delegated)
                    .map_err(|source| e!(ValidateError::Chain, source))?;
            } else if let Ok(child) = Name::new(&ancestor) {
                let authority = authority_records(&ds_response);
                if prove_no_ds(&child, &authority, &trusted).is_ok() {
                    debug!(zone = %ancestor, "insecure delegation proven; zone is unsigned");
                    self.dnssec_cache.insert(zone, ZoneTrust::Insecure);
                    return Ok(ZoneTrust::Insecure);
                }
                debug!(zone = %ancestor, "no signed DS, treating as a non-cut and skipping");
            }
        }
        let trust = ZoneTrust::Secure(trusted);
        self.dnssec_cache.insert(zone, trust.clone());
        Ok(trust)
    }

    /// Queries `name` for `qtype` with the DO bit set and returns the RRset of
    /// `qtype` together with its RRSIG, or `None` when the answer has neither.
    ///
    /// Returns [`ValidateError::Fetch`] only for a query-layer failure; an answer
    /// that simply lacks the signed RRset yields `Ok(None)` so the caller can
    /// raise the zone-specific missing-record error.
    async fn fetch_signed_rrset(
        &self,
        name: &str,
        qtype: TYPE,
    ) -> Result<Option<SignedRrset<'static>>, ValidateError> {
        let response = self.fetch_raw(name, qtype).await?;
        Ok(parse_signed_rrset(&response, name, qtype))
    }

    /// Queries `name` for `qtype` with the DO bit set and returns the raw
    /// response bytes.
    ///
    /// The caller inspects both the answer and the authority section, so the full
    /// response is returned rather than a parsed RRset. Returns
    /// [`ValidateError::Fetch`] for a query-layer failure.
    async fn fetch_raw(&self, name: &str, qtype: TYPE) -> Result<Vec<u8>, ValidateError> {
        let (_id, query) = build_dnssec_query(name, qtype)
            .map_err(|err| e!(ValidateError::Fetch, AnyError::from_stack(err)))?;
        self.send_query(&query)
            .await
            .map_err(|err| e!(ValidateError::Fetch, AnyError::from_stack(err)))
    }
}

/// Parses a response and returns its authority section records, owned.
///
/// Denial-of-existence records (NSEC, NSEC3, and their RRSIGs) live in the
/// authority section, which `simple_dns` exposes as `name_servers`. A response
/// that does not parse yields an empty section, which the proofs treat as no
/// proof (fail-closed).
fn authority_records(response: &[u8]) -> Vec<ResourceRecord<'static>> {
    Packet::parse(response)
        .map(|packet| {
            packet
                .name_servers
                .iter()
                .map(|rr| rr.clone().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Returns the owner name of the SOA record in an authority section, if any.
///
/// A NODATA response places the answering zone's SOA in the authority section;
/// its owner names the zone whose keys sign the accompanying NSEC or NSEC3
/// records. Returns `None` when no SOA is present, which the caller treats as an
/// unauthenticated denial (fail-closed).
fn soa_zone(authority: &[ResourceRecord<'_>]) -> Option<String> {
    authority.iter().find_map(|rr| match &rr.rdata {
        RData::SOA(_) => Some(rr.name.to_string()),
        _ => None,
    })
}

/// Returns one RRSIG per distinct signer zone, most specific (longest) first.
///
/// All authoritative RRSIGs over one RRset name the same zone in an honest
/// response, but an on-path attacker can inject an RRSIG signed by a different
/// authoritative zone: an ancestor, or the answer owner itself. Each distinct
/// signer names a candidate signing zone the chain walk can try, so the caller
/// accepts the answer if any candidate yields a valid chain. Ordering the
/// deepest signer first tries the RRset's real apex, the common case, before any
/// injected one, and deduping bounds the number of chain walks by the number of
/// distinct signer zones.
fn candidate_signers(rrsigs: &[RRSIG<'static>]) -> Vec<RRSIG<'static>> {
    let mut ordered: Vec<&RRSIG<'static>> = rrsigs.iter().collect();
    ordered.sort_by_key(|sig| std::cmp::Reverse(sig.signer_name.as_bytes().count()));
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for sig in ordered {
        let name = sig.signer_name.to_string().to_ascii_lowercase();
        if !seen.contains(&name) {
            seen.push(name);
            out.push(sig.clone());
        }
    }
    out
}

/// Returns whether `signer` may sign records owned by `owner`.
///
/// A zone signs only the names at or below its apex, so the signer must equal
/// `owner` or be an ancestor of it: its labels must be a suffix of `owner`'s,
/// compared case-insensitively. This rejects an RRSIG whose signer is an
/// unrelated (but validly signed) zone, which would otherwise chain to the root
/// and validate.
fn signer_is_authoritative(signer: &Name<'_>, owner: &Name<'_>) -> bool {
    let signer_labels: Vec<Vec<u8>> = signer.as_bytes().map(<[u8]>::to_ascii_lowercase).collect();
    let owner_labels: Vec<Vec<u8>> = owner.as_bytes().map(<[u8]>::to_ascii_lowercase).collect();
    signer_labels.len() <= owner_labels.len()
        && owner_labels[owner_labels.len() - signer_labels.len()..] == signer_labels[..]
}

/// Returns whether an answer was synthesized from a wildcard.
///
/// The RRSIG `labels` field counts the labels the signer covered, excluding the
/// root and any leading `*`. When it is smaller than the owner's label count the
/// record was expanded from a `*.zone` wildcard rather than published for the
/// exact name (RFC 4035 section 5.3.2).
fn is_wildcard_expansion(rrsig_labels: u8, owner: &Name<'_>) -> bool {
    (rrsig_labels as usize) < owner.as_bytes().count()
}

/// Splits a zone name into its ancestor zones, from the top-level domain down to
/// the zone itself, excluding the root.
///
/// For example `"www.example.com"` yields `["com", "example.com",
/// "www.example.com"]` and `"com"` yields `["com"]`. The root (an empty name)
/// yields an empty list, since it is anchored separately.
fn zone_ancestors(zone: &str) -> Vec<String> {
    let zone = zone.strip_suffix('.').unwrap_or(zone);
    if zone.is_empty() {
        return Vec::new();
    }
    let labels: Vec<&str> = zone.split('.').collect();
    (0..labels.len())
        .rev()
        .map(|i| labels[i..].join("."))
        .collect()
}

/// Extracts the `qtype` RRset owned by `expected_owner` and every RRSIG over it.
///
/// Gathers every RRSIG in the answer section owned by `expected_owner` that
/// covers `qtype`, and every answer record of `qtype` under that same owner. An
/// RRset can carry several RRSIGs during a key rollover or from separate KSK and
/// ZSK, so all of them are collected; the chain walk succeeds if any one
/// validates. Requiring the owner ties the returned RRset to the name that was
/// queried, so a signed RRset for a different name in the same response cannot
/// stand in for it. Returns `None` when the response does not parse, the
/// expected name is invalid, or no matching RRSIG or records are present, all of
/// which the caller treats as a missing signature.
fn parse_signed_rrset(
    response: &[u8],
    expected_owner: &str,
    qtype: TYPE,
) -> Option<SignedRrset<'static>> {
    let packet = Packet::parse(response).ok()?;
    let covered = u16::from(qtype);
    let owner = Name::new(expected_owner).ok()?;

    let rrsigs: Vec<_> = packet
        .answers
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::RRSIG(sig) if rr.name == owner && sig.type_covered == covered => {
                Some(sig.clone().into_owned())
            }
            _ => None,
        })
        .collect();
    if rrsigs.is_empty() {
        return None;
    }

    let records: Vec<ResourceRecord<'static>> = packet
        .answers
        .iter()
        .filter(|rr| u16::from(rr.rdata.type_code()) == covered && rr.name == owner)
        .map(|rr| rr.clone().into_owned())
        .collect();
    if records.is_empty() {
        return None;
    }
    Some(SignedRrset { records, rrsigs })
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use simple_dns::{
        CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, ResourceRecord,
        rdata::{A, RData, RRSIG, SOA},
    };

    use super::*;

    /// Builds a NODATA reply for `name`/A: NoError, the question echoed, no answer
    /// of the queried type, and `soa_owner` placed as a SOA in the authority
    /// section when given.
    fn nodata_reply(name: &str, soa_owner: Option<&str>) -> Vec<u8> {
        let mut packet = Packet::new_reply(1);
        packet.set_flags(PacketFlag::RESPONSE);
        packet.questions.push(Question::new(
            Name::new_unchecked(name),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        if let Some(owner) = soa_owner {
            packet.name_servers.push(ResourceRecord::new(
                Name::new_unchecked(owner),
                CLASS::IN,
                3600,
                RData::SOA(SOA {
                    mname: Name::new_unchecked("ns.example.com"),
                    rname: Name::new_unchecked("hostmaster.example.com"),
                    serial: 1,
                    refresh: 3600,
                    retry: 600,
                    expire: 604_800,
                    minimum: 300,
                }),
            ));
        }
        packet.build_bytes_vec().unwrap()
    }

    #[test]
    fn soa_zone_extracts_the_apex_owner() {
        let response = nodata_reply("host.example.com", Some("example.com"));
        let authority = authority_records(&response);
        assert_eq!(soa_zone(&authority).as_deref(), Some("example.com"));
    }

    #[test]
    fn soa_zone_none_without_soa() {
        let response = nodata_reply("host.example.com", None);
        let authority = authority_records(&response);
        assert!(soa_zone(&authority).is_none());
    }

    /// A NODATA answer with no SOA cannot name a signing zone, so the denial is
    /// unauthenticated and must fail closed rather than being accepted as "no such
    /// record" (finding D3). This resolves before any network fetch.
    #[tokio::test]
    async fn validate_nodata_fails_closed_without_soa() {
        let resolver = SimpleDnsResolver::builder()
            .without_system_defaults()
            .disable_fallback()
            .validate_dnssec()
            .build();
        let response = nodata_reply("host.example.com", None);
        let result = resolver
            .validate_nodata("host.example.com", TYPE::A, &response)
            .await;
        assert!(
            matches!(result, Err(Error::DnssecBogus { .. })),
            "unauthenticated NODATA must be Bogus, got {result:?}"
        );
    }

    /// A NODATA answer with a SOA but no reachable chain (and so no validated
    /// NSEC or NSEC3) also fails closed: the denial is never proven, so the empty
    /// answer must not be returned as authoritative (finding D3).
    #[tokio::test]
    async fn validate_nodata_fails_closed_without_proof() {
        let resolver = SimpleDnsResolver::builder()
            .without_system_defaults()
            .disable_fallback()
            .validate_dnssec()
            .build();
        // No nameservers, so the chain fetch cannot complete and no NSEC or NSEC3
        // is validated. The denial stays unproven.
        let response = nodata_reply("host.example.com", Some("example.com"));
        let result = resolver
            .validate_nodata("host.example.com", TYPE::A, &response)
            .await;
        assert!(
            matches!(result, Err(Error::DnssecBogus { .. })),
            "NODATA with no denial proof must be Bogus, got {result:?}"
        );
    }

    /// The SOA names an unrelated zone the attacker controls. Even though that
    /// zone may be signed, it is not authoritative for the queried name, so the
    /// denial must be rejected before any chain fetch. Without this check the
    /// holder of any signed zone could sign an NSEC for another name and forge a
    /// NODATA, suppressing that name's records.
    #[tokio::test]
    async fn validate_nodata_rejects_non_authoritative_soa() {
        let resolver = SimpleDnsResolver::builder()
            .without_system_defaults()
            .disable_fallback()
            .validate_dnssec()
            .build();
        let response = nodata_reply("host.example.com", Some("attacker.com"));
        // Assert the specific reason: the SOA zone is rejected as non-authoritative
        // before any chain fetch. Checking the inner error (not just the wrapped
        // Bogus) isolates this from the fetch failure a nameserver-less resolver
        // would otherwise hit.
        let result = resolver
            .validate_nodata_inner("host.example.com", TYPE::A, &response)
            .await;
        assert!(
            matches!(result, Err(ValidateError::NonAuthoritativeSoa { .. })),
            "a non-authoritative SOA zone must be rejected, got {result:?}"
        );
    }

    #[test]
    fn candidate_signers_orders_deepest_first_and_dedups() {
        let rrsig = |signer: &str, labels: u8| RRSIG {
            type_covered: u16::from(TYPE::A),
            algorithm: 13,
            labels,
            original_ttl: 300,
            signature_expiration: 1_800_000_000,
            signature_inception: 1_700_000_000,
            key_tag: 1,
            signer_name: Name::new_unchecked(signer).into_owned(),
            signature: Cow::Owned(vec![0u8; 64]),
        };
        // An injected owner-signed RRSIG (host.example.com) plus the real apex
        // (example.com) and a shallower ancestor (com): every distinct signer is a
        // candidate, ordered deepest first so the real apex is tried before an
        // injected ancestor, regardless of input order.
        let rrsigs = vec![
            rrsig("com", 3),
            rrsig("example.com", 3),
            rrsig("host.example.com", 3),
        ];
        let names: Vec<String> = candidate_signers(&rrsigs)
            .iter()
            .map(|sig| sig.signer_name.to_string())
            .collect();
        assert_eq!(names, ["host.example.com", "example.com", "com"]);

        // Duplicate signer names collapse to one candidate, so the number of chain
        // walks stays bounded by the distinct signer zones.
        let rrsigs = vec![rrsig("example.com", 3), rrsig("example.com", 2)];
        let names: Vec<String> = candidate_signers(&rrsigs)
            .iter()
            .map(|sig| sig.signer_name.to_string())
            .collect();
        assert_eq!(names, ["example.com"]);

        assert!(candidate_signers(&[]).is_empty());
    }

    #[test]
    fn signer_must_be_owner_or_ancestor() {
        let owner = Name::new_unchecked("host.example.com");
        // The owning zone and its ancestors may sign.
        assert!(signer_is_authoritative(
            &Name::new_unchecked("example.com"),
            &owner
        ));
        assert!(signer_is_authoritative(
            &Name::new_unchecked("host.example.com"),
            &owner
        ));
        assert!(signer_is_authoritative(&Name::new_unchecked("com"), &owner));
        // Case does not matter.
        assert!(signer_is_authoritative(
            &Name::new_unchecked("Example.COM"),
            &owner
        ));
        // An unrelated but validly signed zone must not sign for this name.
        assert!(!signer_is_authoritative(
            &Name::new_unchecked("attacker.com"),
            &owner
        ));
        assert!(!signer_is_authoritative(
            &Name::new_unchecked("example.org"),
            &owner
        ));
        // A name longer than the owner cannot be an ancestor.
        assert!(!signer_is_authoritative(
            &Name::new_unchecked("a.host.example.com"),
            &owner
        ));
    }

    #[test]
    fn wildcard_expansion_detected_by_label_count() {
        let owner = Name::new_unchecked("host.example.com");
        // Three owner labels signed by three RRSIG labels: an exact-name answer.
        assert!(!is_wildcard_expansion(3, &owner));
        // Two RRSIG labels: the record came from `*.example.com`.
        assert!(is_wildcard_expansion(2, &owner));
    }

    #[test]
    fn zone_ancestors_orders_parent_to_child() {
        assert_eq!(
            zone_ancestors("www.example.com"),
            vec!["com", "example.com", "www.example.com"]
        );
        assert_eq!(zone_ancestors("example.com."), vec!["com", "example.com"]);
        assert_eq!(zone_ancestors("com"), vec!["com"]);
        assert!(zone_ancestors("").is_empty());
        assert!(zone_ancestors(".").is_empty());
    }

    /// Builds a reply carrying one A record for `name` and an RRSIG covering it.
    fn reply_with_signed_a(name: &str) -> Vec<u8> {
        let mut packet = Packet::new_reply(1);
        packet.set_flags(PacketFlag::RESPONSE);
        packet.questions.push(Question::new(
            Name::new_unchecked(name),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            300,
            RData::A(A {
                address: u32::from_be_bytes([192, 0, 2, 7]),
            }),
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            300,
            RData::RRSIG(RRSIG {
                type_covered: u16::from(TYPE::A),
                algorithm: 13,
                labels: 2,
                original_ttl: 300,
                signature_expiration: 1_800_000_000,
                signature_inception: 1_700_000_000,
                key_tag: 12345,
                signer_name: Name::new_unchecked("example.com"),
                signature: Cow::Owned(vec![0xAB; 64]),
            }),
        ));
        packet.build_bytes_vec().unwrap()
    }

    #[test]
    fn parse_signed_rrset_extracts_records_and_signature() {
        let response = reply_with_signed_a("host.example.com");
        let signed = parse_signed_rrset(&response, "host.example.com", TYPE::A)
            .expect("signed RRset present");
        assert_eq!(signed.records.len(), 1);
        assert_eq!(signed.rrsigs.len(), 1);
        assert_eq!(signed.rrsigs[0].signer_name.to_string(), "example.com");
        assert_eq!(signed.rrsigs[0].key_tag, 12345);
    }

    #[test]
    fn parse_signed_rrset_collects_every_rrsig() {
        // Two RRSIGs cover the same A RRset, as a zone with a separate KSK and
        // ZSK, or one mid rollover, would publish. Both must be collected so the
        // chain walk can try each.
        let mut packet = Packet::new_reply(1);
        packet.set_flags(PacketFlag::RESPONSE);
        let name = "host.example.com";
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            300,
            RData::A(A {
                address: u32::from_be_bytes([192, 0, 2, 7]),
            }),
        ));
        for key_tag in [11111u16, 22222u16] {
            packet.answers.push(ResourceRecord::new(
                Name::new_unchecked(name),
                CLASS::IN,
                300,
                RData::RRSIG(RRSIG {
                    type_covered: u16::from(TYPE::A),
                    algorithm: 13,
                    labels: 3,
                    original_ttl: 300,
                    signature_expiration: 1_800_000_000,
                    signature_inception: 1_700_000_000,
                    key_tag,
                    signer_name: Name::new_unchecked("example.com"),
                    signature: Cow::Owned(vec![0xAB; 64]),
                }),
            ));
        }
        let response = packet.build_bytes_vec().unwrap();
        let signed = parse_signed_rrset(&response, name, TYPE::A).expect("signed RRset present");
        assert_eq!(signed.records.len(), 1);
        let tags: Vec<u16> = signed.rrsigs.iter().map(|sig| sig.key_tag).collect();
        assert_eq!(tags, vec![11111, 22222]);
    }

    #[test]
    fn parse_signed_rrset_none_without_rrsig() {
        // A plain A response with no RRSIG must not be treated as signed.
        let mut packet = Packet::new_reply(1);
        packet.set_flags(PacketFlag::RESPONSE);
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("host.example.com"),
            CLASS::IN,
            300,
            RData::A(A {
                address: u32::from_be_bytes([192, 0, 2, 7]),
            }),
        ));
        let response = packet.build_bytes_vec().unwrap();
        assert!(parse_signed_rrset(&response, "host.example.com", TYPE::A).is_none());
    }

    #[test]
    fn parse_signed_rrset_none_for_other_type() {
        // The RRSIG covers A, so asking for AAAA finds no signature.
        let response = reply_with_signed_a("host.example.com");
        assert!(parse_signed_rrset(&response, "host.example.com", TYPE::AAAA).is_none());
    }

    #[test]
    fn parse_signed_rrset_none_for_other_owner() {
        // A signed RRset for a different name must not satisfy a query for `host`:
        // the response carries a valid signature over host.attacker.com, but the
        // queried name is host.example.com.
        let response = reply_with_signed_a("host.attacker.com");
        assert!(parse_signed_rrset(&response, "host.example.com", TYPE::A).is_none());
    }

    /// A signing zone nested deeper than [`MAX_ZONE_DEPTH`] must fail closed
    /// before any fetch, rather than walking an unbounded chain of zone cuts
    /// (finding H4). The check runs ahead of the root DNSKEY fetch, so a resolver
    /// with no nameservers still reaches it.
    #[tokio::test]
    async fn trusted_keys_for_zone_rejects_a_too_deep_zone() {
        let resolver = SimpleDnsResolver::builder()
            .without_system_defaults()
            .disable_fallback()
            .validate_dnssec()
            .build();
        let deep = vec!["a"; MAX_ZONE_DEPTH + 1].join(".");
        let result = resolver.trusted_keys_for_zone(&deep).await;
        assert!(
            matches!(result, Err(ValidateError::ZoneTooDeep { .. })),
            "a too-deep zone must be rejected, got {result:?}"
        );
    }

    /// The zone-trust cache stores and returns a validated result and reports a
    /// miss for an unknown zone (finding H4).
    #[test]
    fn dnssec_cache_round_trips_a_trust_result() {
        let cache = DnssecCache::new();
        assert!(cache.get("example.com").is_none());
        cache.insert("example.com", ZoneTrust::Insecure);
        assert!(matches!(
            cache.get("example.com"),
            Some(ZoneTrust::Insecure)
        ));
        // A different zone name is a miss.
        assert!(cache.get("example.net").is_none());
    }
}
