//! Basic DNSSEC validation: RRSIG signatures plus DS and key-tag helpers.
//!
//! This module is a standalone toolkit, not an automatic layer over the
//! resolver. It answers one question correctly: given an RRset, an [`RRSIG`]
//! over it, and the [`DNSKEY`] the RRSIG names, is the signature valid
//! ([`verify_rrsig`])? It also validates the DS delegation link (a [`DNSKEY`]
//! against a parent [`DS`] digest, [`verify_ds`]) and computes DNSKEY key tags
//! ([`key_tag`]). [`build_dnssec_query`] is the query-side counterpart: it
//! builds a query that requests DNSSEC records by setting the EDNS DO bit.
//!
//! # Scope
//!
//! [`verify_rrsig`] and [`verify_ds`] validate a single signature or delegation
//! link. [`verify_chain`] walks a full sequence of those links from the embedded
//! IANA root trust anchors ([`ROOT_TRUST_ANCHORS`]) down to a target RRset, and
//! is fail-closed: it treats a missing DS, an absent record, or a broken
//! signature as a validation failure rather than as proof that a name is
//! unsigned.
//!
//! Authenticated denial of existence is covered by a separate set of proofs
//! ([`prove_nodata`], [`prove_nxdomain`], [`prove_no_ds`], [`prove_wildcard`]).
//! Each takes the denial records from a response's authority section together
//! with the trusted DNSKEY set of the zone that owns them, validates every
//! record's signature, and evaluates the NSEC or NSEC3 range and bit-map logic.
//! A proof succeeds only when the denial is authenticated; an unvalidated or
//! absent record is fail-closed. [`verify_chain`] itself still proves signatures
//! rather than their absence, so on its own it rejects an unsigned delegation or
//! a negative answer.
//!
//! The supported signature algorithms are RSA/SHA-256 (8, RFC 5702), RSA/SHA-512
//! (10, RFC 5702), ECDSA P-256 SHA-256 (13, RFC 6605), ECDSA P-384 SHA-384 (14,
//! RFC 6605), and Ed25519 (15, RFC 8080). The deprecated RSA/SHA-1 and DSA
//! algorithms are deliberately absent. Supported DS digest types are SHA-1 (1),
//! SHA-256 (2), and SHA-384 (4).
//!
//! The canonical forms follow RFC 4034 section 6, and the signature input
//! follows RFC 4035 section 5.3.
//!
//! The record types come from [`simple_dns`], which this crate re-exports under
//! the `dnssec` feature so callers can name them without a second dependency.

use std::{
    borrow::Cow,
    cmp::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use n0_error::{AnyError, e, stack_error};
use ring::{digest, signature};
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, TYPE,
    rdata::{DNSKEY, DS, NSEC, NsecTypeBitMap, OPT, RData, RRSIG},
};

/// EDNS(0) advertised UDP payload size for DNSSEC queries.
///
/// Matches the resolver's plain-query default (RFC 6891, DNS flag day 2020).
/// DNSSEC responses are larger, so advertising a generous size avoids needless
/// truncation and TCP fallback.
const EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

/// The Zone Key flag in the DNSKEY flags field (RFC 4034 section 2.1.1).
///
/// A key without this flag set is not a zone key and must not be used to
/// validate an RRset.
const DNSKEY_ZONE_FLAG: u16 = 0x0100;

/// The REVOKE flag in the DNSKEY flags field (RFC 5011 section 2.1).
///
/// A key with this flag set has been revoked by its zone and must not be used to
/// validate an RRset.
const DNSKEY_REVOKE_FLAG: u16 = 0x0080;

/// The protocol value every DNSKEY must carry (RFC 4034 section 2.1.2).
const DNSKEY_PROTOCOL: u8 = 3;

/// The largest number of signature checks one RRset may force during validation.
///
/// A key tag is a checksum, so many DNSKEYs can share one tag and many RRSIGs can
/// name it, which multiplies into a quadratic pile of expensive signature checks
/// an attacker can pack into a single response (the KeyTrap denial of service,
/// CVE-2023-50387). Legitimate RRsets need only a handful of checks, so the walk
/// stops after this many and fails closed. The bound sits well above any honest
/// RRset (a few keys signed by a few RRSIGs).
const MAX_SIGNATURE_CHECKS: usize = 16;

/// SHA-256 digest of the root KSK-2017, key tag 20326 (IANA anchor `Klajeyz`).
const ROOT_KSK_2017_DIGEST: [u8; 32] = [
    0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
    0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
];

/// SHA-256 digest of the root KSK-2024, key tag 38696 (IANA anchor `Kmyv6jo`).
const ROOT_KSK_2024_DIGEST: [u8; 32] = [
    0x68, 0x3D, 0x2D, 0x0A, 0xCB, 0x8C, 0x9B, 0x71, 0x2A, 0x19, 0x48, 0xB2, 0x7F, 0x74, 0x12, 0x19,
    0x29, 0x8D, 0x0A, 0x45, 0x0D, 0x61, 0x2C, 0x48, 0x3A, 0xF4, 0x44, 0xA4, 0xC0, 0xFB, 0x2B, 0x16,
];

/// The IANA root zone trust anchors, as DS records over the root KSK.
///
/// These are the currently valid entries from the IANA root anchors file at
/// <https://data.iana.org/root-anchors/root-anchors.xml>: KSK-2017 (key tag
/// 20326) and KSK-2024 (key tag 38696), both RSA/SHA-256 (algorithm 8) with a
/// SHA-256 digest (digest type 2). A validating chain is trusted only if its root
/// DNSKEY RRset matches one of these anchors, so operators must update this list
/// on a root KSK rollover. For a private root or a pending rollover, pass a
/// custom anchor set to [`verify_chain_with_anchors`] instead.
pub const ROOT_TRUST_ANCHORS: &[DS<'static>] = &[
    DS {
        key_tag: 20326,
        algorithm: 8,
        digest_type: 2,
        digest: Cow::Borrowed(&ROOT_KSK_2017_DIGEST),
    },
    DS {
        key_tag: 38696,
        algorithm: 8,
        digest_type: 2,
        digest: Cow::Borrowed(&ROOT_KSK_2024_DIGEST),
    },
];

/// A trust anchor for the root DNSKEY RRset.
///
/// A chain is trusted only when a key in its root DNSKEY RRset is anchored by one
/// of these. The two forms match the two ways an operator holds a root anchor. A
/// [`TrustAnchor::Ds`] carries a DS-style digest over a root key, exactly as the
/// IANA root-anchors file publishes it (and as [`ROOT_TRUST_ANCHORS`] holds the
/// current KSKs). A [`TrustAnchor::Dnskey`] pins a root key directly by its
/// algorithm and public-key bytes, which is convenient when the operator holds
/// the key material itself rather than a digest of it, for example when pinning a
/// pending KSK during a rollover or a private root's key.
///
/// Pass a slice of these to [`verify_chain_with_trust_anchors`]. The DS-only
/// [`verify_chain_with_anchors`] remains available for callers that hold anchors
/// as plain DS records.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TrustAnchor {
    /// A DS-style anchor: a root key is anchored when its DS digest matches.
    Ds(DS<'static>),
    /// A DNSKEY-style anchor: a root key is anchored when its algorithm and
    /// public-key bytes match this key.
    Dnskey(DNSKEY<'static>),
}

/// An error returned while validating DNSSEC records.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, std_sources)]
#[non_exhaustive]
pub enum DnssecError {
    /// The RRSIG uses a signature algorithm this module does not support.
    #[error("unsupported DNSSEC algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: u8 },
    /// The DS uses a digest type this module does not support.
    #[error("unsupported DS digest type: {digest_type}")]
    UnsupportedDigestType { digest_type: u8 },
    /// The RRset contains a record type whose canonical form is not implemented.
    #[error("unsupported record type in RRset: {type_code}")]
    UnsupportedRecordType { type_code: u16 },
    /// The RRset was empty, so there was nothing to validate.
    #[error("empty RRset")]
    EmptyRrset {},
    /// The RRset records do not share one owner name, class, and type matching
    /// the RRSIG.
    #[error("inconsistent RRset")]
    InconsistentRrset {},
    /// The DNSKEY is structurally unusable: wrong protocol, not a zone key, an
    /// algorithm that does not match the RRSIG, or a malformed public key.
    #[error("invalid or unusable DNSKEY")]
    InvalidKey {},
    /// The DNSKEY key tag does not match the one the RRSIG or DS refers to.
    #[error("key tag mismatch")]
    KeyTagMismatch {},
    /// The RRSIG label count exceeds the owner name's label count.
    #[error("RRSIG label count exceeds owner labels")]
    WildcardLabels {},
    /// The signature validity period has not yet started.
    #[error("signature not yet valid")]
    SignatureNotYetValid {},
    /// The signature validity period has passed.
    #[error("signature expired")]
    SignatureExpired {},
    /// The cryptographic signature check failed.
    #[error("signature verification failed")]
    BadSignature {},
    /// The DS digest does not match the digest of the DNSKEY.
    #[error("DS digest mismatch")]
    DigestMismatch {},
    /// The query name could not be encoded into a packet.
    #[error("failed to build DNSSEC query")]
    BuildQuery { source: AnyError },
}

/// Builds a DNS query for `host` and `qtype` that requests DNSSEC records.
///
/// The query carries an EDNS(0) OPT record with the DO (DNSSEC OK) bit set, so a
/// validating or DNSSEC-aware nameserver includes RRSIG records (and, for
/// denial of existence, NSEC or NSEC3 records) in its response. The returned
/// `id` is the transaction ID a caller uses to match the response.
///
/// # Errors
///
/// Returns [`DnssecError::BuildQuery`] if `host` is not a valid DNS name or the
/// packet cannot be serialized.
///
/// # Examples
///
/// ```
/// use n0_dns_resolver::{build_dnssec_query, simple_dns::TYPE};
///
/// let (id, bytes) = build_dnssec_query("example.com", TYPE::A).unwrap();
/// assert!(!bytes.is_empty());
/// let _ = id;
/// ```
pub fn build_dnssec_query(host: &str, qtype: TYPE) -> Result<(u16, Vec<u8>), DnssecError> {
    let id: u16 = rand::random();
    let mut packet = Packet::new_query(id);
    packet.set_flags(PacketFlag::RECURSION_DESIRED);

    let name =
        Name::new(host).map_err(|err| e!(DnssecError::BuildQuery, AnyError::from_std(err)))?;
    packet.questions.push(Question::new(
        name,
        QTYPE::TYPE(qtype),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    *packet.opt_mut() = Some(OPT {
        udp_packet_size: EDNS_UDP_PAYLOAD_SIZE,
        version: 0,
        opt_codes: vec![],
    });

    let mut bytes = packet
        .build_bytes_vec()
        .map_err(|err| e!(DnssecError::BuildQuery, AnyError::from_std(err)))?;

    // `simple_dns` does not model the DO bit, so set it directly. The DO bit is
    // the high bit of the OPT record's TTL flags field (RFC 6891 section 6.1.3).
    // Our OPT record is the last record and carries no options, so its RDLEN is
    // the final two bytes and the flags high byte is four bytes from the end.
    if let Some(flags_hi) = bytes.len().checked_sub(4).and_then(|i| bytes.get_mut(i)) {
        *flags_hi |= 0x80;
    }

    Ok((id, bytes))
}

/// Computes the key tag of `dnskey` (RFC 4034 appendix B).
///
/// The key tag is a 16-bit checksum over the DNSKEY RDATA. It is not a unique
/// identifier: two distinct keys can share a tag, which is why validation still
/// checks the algorithm and, ultimately, the signature. RRSIG and DS records
/// carry the key tag of the DNSKEY they refer to.
///
/// # Examples
///
/// ```
/// # use n0_dns_resolver::{key_tag, simple_dns::rdata::DNSKEY};
/// # use std::borrow::Cow;
/// let dnskey = DNSKEY {
///     flags: 256,
///     protocol: 3,
///     algorithm: 13,
///     public_key: Cow::Owned(vec![0u8; 64]),
/// };
/// let _tag = key_tag(&dnskey);
/// ```
#[must_use]
pub fn key_tag(dnskey: &DNSKEY<'_>) -> u16 {
    let rdata = dnskey_rdata(dnskey);
    let mut acc: u32 = 0;
    for (i, byte) in rdata.iter().enumerate() {
        acc += if i & 1 == 0 {
            u32::from(*byte) << 8
        } else {
            u32::from(*byte)
        };
    }
    acc += (acc >> 16) & 0xFFFF;
    (acc & 0xFFFF) as u16
}

/// Validates a DNSKEY against a parent DS record (RFC 4035 section 5.2).
///
/// A DS record in the parent zone commits to a child zone's DNSKEY by its key
/// tag, algorithm, and a digest over the DNSKEY. This recomputes that digest
/// over `owner` (the DNSKEY's owner name) and the DNSKEY RDATA and compares it
/// to the DS. It supports digest types 1 (SHA-1), 2 (SHA-256), and 4 (SHA-384).
///
/// A successful result proves the DS and DNSKEY agree; it does not by itself
/// establish trust, which requires the DS to be reached from an already-trusted
/// parent.
///
/// # Errors
///
/// - [`DnssecError::KeyTagMismatch`] if the DS key tag does not match the
///   DNSKEY.
/// - [`DnssecError::InvalidKey`] if the DS algorithm does not match the DNSKEY.
/// - [`DnssecError::UnsupportedDigestType`] for an unsupported digest type.
/// - [`DnssecError::DigestMismatch`] if the computed digest differs from the DS.
pub fn verify_ds(owner: &Name<'_>, dnskey: &DNSKEY<'_>, ds: &DS<'_>) -> Result<(), DnssecError> {
    if ds.key_tag != key_tag(dnskey) {
        return Err(e!(DnssecError::KeyTagMismatch));
    }
    if ds.algorithm != dnskey.algorithm {
        return Err(e!(DnssecError::InvalidKey));
    }
    let algorithm = match ds.digest_type {
        1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        2 => &digest::SHA256,
        4 => &digest::SHA384,
        digest_type => return Err(e!(DnssecError::UnsupportedDigestType { digest_type })),
    };

    let mut data = encode_name(owner.as_bytes(), true);
    data.extend_from_slice(&dnskey_rdata(dnskey));
    let computed = digest::digest(algorithm, &data);

    if computed.as_ref() == ds.digest.as_ref() {
        Ok(())
    } else {
        Err(e!(DnssecError::DigestMismatch))
    }
}

/// Verifies an RRSIG over an RRset using the DNSKEY it names.
///
/// The `rrset` must be the set of records the RRSIG covers: every record
/// sharing one owner name, class, and the RRSIG's covered type. This checks the
/// preconditions RFC 4035 section 5.3.1 requires (the DNSKEY is a zone key with
/// protocol 3, its algorithm and key tag match the RRSIG, and the current time
/// falls within the signature's validity period), reconstructs the signed data
/// in canonical form (RFC 4034 section 6), and verifies the signature.
///
/// Wildcard-expanded names are handled: when the RRSIG covers fewer labels than
/// the owner name has, the name is reconstructed as `*` plus the trailing
/// labels (RFC 4035 section 5.3.2).
///
/// A successful result proves the RRset was signed by the given DNSKEY. It does
/// not establish that the DNSKEY itself is trusted; that requires validating the
/// DNSKEY up the delegation chain (see [`verify_ds`]).
///
/// # Errors
///
/// Returns a [`DnssecError`] describing which check failed: an empty or
/// inconsistent RRset, an unusable key, a key tag mismatch, a signature outside
/// its validity period, an unsupported algorithm or record type, or a failed
/// signature check ([`DnssecError::BadSignature`]).
pub fn verify_rrsig(
    rrsig: &RRSIG<'_>,
    rrset: &[ResourceRecord<'_>],
    dnskey: &DNSKEY<'_>,
) -> Result<(), DnssecError> {
    if dnskey.protocol != DNSKEY_PROTOCOL || dnskey.flags & DNSKEY_ZONE_FLAG == 0 {
        return Err(e!(DnssecError::InvalidKey));
    }
    // A revoked key (RFC 5011 section 2.1) has been retired by its zone and must
    // not validate anything, even though it is still a well-formed zone key.
    if dnskey.flags & DNSKEY_REVOKE_FLAG != 0 {
        return Err(e!(DnssecError::InvalidKey));
    }
    if dnskey.algorithm != rrsig.algorithm {
        return Err(e!(DnssecError::InvalidKey));
    }
    if key_tag(dnskey) != rrsig.key_tag {
        return Err(e!(DnssecError::KeyTagMismatch));
    }

    // RFC 4034 section 3.1.5 requires the inception and expiration to be compared
    // to the current time with RFC 1982 serial-number arithmetic, not a plain
    // integer compare, so the window stays correct across the 2106 wrap of the
    // 32-bit seconds counter.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as u32;
    if !serial_le(rrsig.signature_inception, now) {
        return Err(e!(DnssecError::SignatureNotYetValid));
    }
    if !serial_le(now, rrsig.signature_expiration) {
        return Err(e!(DnssecError::SignatureExpired));
    }

    let signed = signed_data(rrsig, rrset)?;
    verify_signature(rrsig, dnskey, &signed)
}

/// Returns whether `a` is less than or equal to `b` in RFC 1982 serial-number
/// arithmetic over 32 bits.
///
/// Serial arithmetic treats the value space as a circle, so `a <= b` holds when
/// `b` is at most a half-space ahead of `a` (`b - a < 2^31`, computed with
/// wrapping subtraction). This keeps RRSIG inception and expiration comparisons
/// correct as the 32-bit Unix-seconds counter wraps in 2106 (RFC 4034 section
/// 3.1.5).
fn serial_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < 0x8000_0000
}

/// A parsed DNS resource record, re-exported from [`simple_dns`] for use with
/// [`verify_rrsig`].
pub type ResourceRecord<'a> = simple_dns::ResourceRecord<'a>;

/// An RRset together with the [`RRSIG`] records that sign it.
///
/// The `records` share one owner name, class, and type, and `rrsigs` holds every
/// signature covering them. An RRset routinely carries more than one RRSIG: a
/// DNSKEY RRset signed by both a KSK and a ZSK, or any RRset mid key rollover
/// where the old and new key both sign. This is the unit [`verify_chain`]
/// validates at each level, and it succeeds if any one RRSIG validates under a
/// trusted key.
#[derive(Debug, Clone)]
pub struct SignedRrset<'a> {
    /// The records the signatures cover.
    pub records: Vec<ResourceRecord<'a>>,
    /// The signatures over `records`. Validation succeeds if any one of them
    /// verifies under a trusted key.
    pub rrsigs: Vec<RRSIG<'a>>,
}

/// A zone below the root in a [`ChainOfTrust`].
///
/// It pairs the DS RRset that delegates to the zone (published in and signed by
/// the parent) with the zone's own DNSKEY RRset (self-signed by the zone key
/// the DS commits to).
#[derive(Debug, Clone)]
pub struct DelegatedZone<'a> {
    /// The DS RRset in the parent zone, and the parent's signature over it.
    pub delegation: SignedRrset<'a>,
    /// This zone's DNSKEY RRset, and its self-signature.
    pub dnskeys: SignedRrset<'a>,
}

/// A chain of trust from the root zone down to a target RRset.
///
/// [`verify_chain`] walks it from `root_dnskeys` (anchored against the embedded
/// [`ROOT_TRUST_ANCHORS`]) through each entry of `zones` (parent to child) to
/// `target`, requiring every link to validate. Build one per name to validate:
/// `zones` lists every zone cut from just below the root down to the target's
/// signing zone, and `target` is the answer RRset with its RRSIG.
#[derive(Debug, Clone)]
pub struct ChainOfTrust<'a> {
    /// The root zone DNSKEY RRset and its self-signature.
    pub root_dnskeys: SignedRrset<'a>,
    /// Each delegated zone from just below the root to the signing zone, ordered
    /// parent to child. Empty when the target is signed directly by the root.
    pub zones: Vec<DelegatedZone<'a>>,
    /// The target RRset and the signature over it.
    pub target: SignedRrset<'a>,
}

/// An error returned while walking a DNSSEC chain of trust.
///
/// Every variant means the chain is Bogus: validation failed and the answer must
/// be rejected. The walk is fail-closed, so a missing DS, an absent record, or an
/// unmatched key produces one of these errors rather than an "insecure" result.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, std_sources)]
#[non_exhaustive]
pub enum ChainError {
    /// A DNSKEY, DS, or target RRset in the chain was empty.
    #[error("empty RRset in chain")]
    EmptyRrset {},
    /// A DNSKEY RRset contained no DNSKEY records.
    #[error("no DNSKEY records in RRset")]
    NoDnskeys {},
    /// A delegation RRset contained no DS records.
    #[error("no DS records in delegation")]
    NoDelegation {},
    /// The root DNSKEY RRset matched none of the trust anchors.
    #[error("root DNSKEY does not match any trust anchor")]
    UntrustedRoot {},
    /// A zone's DNSKEY RRset contained no key committed to by the parent DS.
    #[error("no DNSKEY matches the delegating DS")]
    NoMatchingDnskey {},
    /// No key in the trusted set matched the RRSIG's key tag and algorithm.
    #[error("no trusted key matches the signature")]
    NoSigningKey {},
    /// A signature or delegation link failed cryptographic validation.
    #[error("chain link failed validation")]
    Link { source: DnssecError },
}

/// Validates a chain of trust from the embedded root anchors down to a target.
///
/// This is [`verify_chain_with_anchors`] using the built-in [`ROOT_TRUST_ANCHORS`].
/// It is the fail-closed core of an offline DNSSEC validator: it returns `Ok`
/// (Secure) only if every link validates from an embedded root anchor to the
/// target signature. A missing DS, a broken signature, or an absent record is a
/// [`ChainError`] (Bogus), never treated as "insecure".
///
/// It proves signatures, not their absence: without NSEC or NSEC3 support a
/// legitimately unsigned delegation or a negative answer cannot be proven and is
/// rejected, which is the intended fail-closed behavior.
///
/// # Errors
///
/// Returns a [`ChainError`] identifying the first link that failed: an untrusted
/// root, a DS that no DNSKEY matches, an RRset with no signing key, or a failed
/// signature or delegation check.
pub fn verify_chain(chain: &ChainOfTrust<'_>) -> Result<(), ChainError> {
    verify_chain_with_anchors(chain, ROOT_TRUST_ANCHORS)
}

/// Validates a chain of trust against a caller-supplied set of trust anchors.
///
/// Behaves like [`verify_chain`] but anchors the root DNSKEY RRset against
/// `anchors` (DS records over the root KSK) rather than the built-in set. Use
/// this to pin a pending root KSK during a rollover, to validate against a
/// private root, or to test a chain whose root is not the IANA root.
///
/// # Errors
///
/// Returns the same [`ChainError`] variants as [`verify_chain`]; in particular
/// [`ChainError::UntrustedRoot`] when the root DNSKEY RRset matches no anchor.
pub fn verify_chain_with_anchors(
    chain: &ChainOfTrust<'_>,
    anchors: &[DS<'_>],
) -> Result<(), ChainError> {
    let trusted = trust_root(&chain.root_dnskeys, anchors)?;
    walk_from_trusted_root(chain, trusted)
}

/// Validates a chain of trust against a set of [`TrustAnchor`]s.
///
/// Behaves like [`verify_chain_with_anchors`] but accepts anchors in either DS or
/// DNSKEY form (see [`TrustAnchor`]). A root key is anchored when a
/// [`TrustAnchor::Ds`] digest matches it or a [`TrustAnchor::Dnskey`] matches its
/// algorithm and public-key bytes. Use this to pin a root key directly, for a
/// pending KSK rollover or a private root.
///
/// # Errors
///
/// Returns the same [`ChainError`] variants as [`verify_chain`]; in particular
/// [`ChainError::UntrustedRoot`] when no root key matches an anchor.
pub fn verify_chain_with_trust_anchors(
    chain: &ChainOfTrust<'_>,
    anchors: &[TrustAnchor],
) -> Result<(), ChainError> {
    let trusted = trust_root_with_anchors(&chain.root_dnskeys, anchors)?;
    walk_from_trusted_root(chain, trusted)
}

/// Walks a chain from an already-anchored root DNSKEY set down to the target.
///
/// Carries the trusted DNSKEY set down one zone cut at a time. After a level
/// validates, the whole child DNSKEY RRset is trusted and signs the next level
/// (the next DS, or the target). The target RRset is signed by the deepest zone's
/// now-trusted DNSKEY set.
fn walk_from_trusted_root(
    chain: &ChainOfTrust<'_>,
    mut trusted: Vec<DNSKEY<'static>>,
) -> Result<(), ChainError> {
    for zone in &chain.zones {
        trusted = descend_zone(&trusted, zone)?;
    }
    verify_rrset_with_keys(&chain.target, &trusted)
}

/// Anchors the root DNSKEY RRset and returns its trusted keys.
///
/// The RRset must contain a key whose DS matches one of `anchors` and must be
/// self-signed by such a key (RFC 4035 section 5). On success the whole root
/// DNSKEY set is returned as owned records, which the caller carries down as the
/// trusted set for the next zone cut.
///
/// # Errors
///
/// Returns [`ChainError::UntrustedRoot`] when no root key matches an anchor, or a
/// [`ChainError::Link`] when the self-signature does not verify.
pub(crate) fn trust_root(
    root_dnskeys: &SignedRrset<'_>,
    anchors: &[DS<'_>],
) -> Result<Vec<DNSKEY<'static>>, ChainError> {
    trust_root_inner(root_dnskeys, |owner, key| {
        anchors
            .iter()
            .any(|anchor| verify_ds(owner, key, anchor).is_ok())
    })
}

/// Anchors the root DNSKEY RRset against [`TrustAnchor`]s and returns its keys.
///
/// Behaves like [`trust_root`] but accepts DS-form and DNSKEY-form anchors. A
/// root key is anchored when a [`TrustAnchor::Ds`] digest matches it or a
/// [`TrustAnchor::Dnskey`] matches its algorithm and public-key bytes.
///
/// # Errors
///
/// Returns [`ChainError::UntrustedRoot`] when no root key matches an anchor, or a
/// [`ChainError::Link`] when the self-signature does not verify.
pub(crate) fn trust_root_with_anchors(
    root_dnskeys: &SignedRrset<'_>,
    anchors: &[TrustAnchor],
) -> Result<Vec<DNSKEY<'static>>, ChainError> {
    trust_root_inner(root_dnskeys, |owner, key| {
        anchors
            .iter()
            .any(|anchor| key_matches_anchor(owner, key, anchor))
    })
}

/// Anchors the root DNSKEY RRset given a predicate that recognizes anchored keys.
///
/// The root RRset must contain a key `is_anchored` accepts and must be
/// self-signed by such a key (RFC 4035 section 5). On success the whole root
/// DNSKEY set is returned as owned records, which the caller carries down as the
/// trusted set for the next zone cut. Sharing this core keeps the DS-form and
/// [`TrustAnchor`]-form entry points identical apart from how a key is matched.
fn trust_root_inner(
    root_dnskeys: &SignedRrset<'_>,
    is_anchored: impl Fn(&Name<'_>, &DNSKEY<'_>) -> bool,
) -> Result<Vec<DNSKEY<'static>>, ChainError> {
    let root_keys = dnskeys_of(&root_dnskeys.records)?;
    let root_owner = owner_of(&root_dnskeys.records)?;
    let anchored: Vec<&DNSKEY<'_>> = root_keys
        .iter()
        .copied()
        .filter(|key| is_anchored(root_owner, key))
        .collect();
    if anchored.is_empty() {
        return Err(e!(ChainError::UntrustedRoot));
    }
    verify_signed_rrset(root_dnskeys, &anchored)?;
    Ok(root_keys
        .into_iter()
        .map(|key| key.clone().into_owned())
        .collect())
}

/// Returns whether `key`, owned by `owner`, is anchored by `anchor`.
///
/// A [`TrustAnchor::Ds`] anchors the key when its DS digest matches (the same
/// check [`verify_ds`] performs). A [`TrustAnchor::Dnskey`] anchors the key when
/// its algorithm and public-key bytes are identical. The DNSKEY match ignores the
/// flags field: a later self-signature check still requires the key to be a
/// usable zone key, so pinning by algorithm and public key is enough to identify
/// it.
fn key_matches_anchor(owner: &Name<'_>, key: &DNSKEY<'_>, anchor: &TrustAnchor) -> bool {
    match anchor {
        TrustAnchor::Ds(ds) => verify_ds(owner, key, ds).is_ok(),
        TrustAnchor::Dnskey(anchor_key) => {
            anchor_key.algorithm == key.algorithm
                && anchor_key.public_key.as_ref() == key.public_key.as_ref()
        }
    }
}

/// Descends one zone cut and returns the child zone's trusted keys.
///
/// The delegation DS RRset must be signed by `parent_keys`, the child DNSKEY
/// RRset must contain a key the delegating DS commits to, and that RRset must be
/// self-signed by such a key (RFC 4035 section 5). On success the whole child
/// DNSKEY set is returned as owned records for the next descent.
///
/// # Errors
///
/// Returns [`ChainError::NoMatchingDnskey`] when no child key matches the
/// delegating DS, [`ChainError::NoDelegation`] when the RRset carries no DS, or a
/// [`ChainError::Link`] when a signature does not verify.
pub(crate) fn descend_zone(
    parent_keys: &[DNSKEY<'_>],
    zone: &DelegatedZone<'_>,
) -> Result<Vec<DNSKEY<'static>>, ChainError> {
    let parent_refs: Vec<&DNSKEY<'_>> = parent_keys.iter().collect();
    // The DS RRset is published in, and signed by, the trusted parent zone.
    verify_signed_rrset(&zone.delegation, &parent_refs)?;
    let delegating_ds = ds_records_of(&zone.delegation.records)?;

    let child_keys = dnskeys_of(&zone.dnskeys.records)?;
    let child_owner = owner_of(&zone.dnskeys.records)?;
    let matched: Vec<&DNSKEY<'_>> = child_keys
        .iter()
        .copied()
        .filter(|key| {
            delegating_ds
                .iter()
                .any(|ds| verify_ds(child_owner, key, ds).is_ok())
        })
        .collect();
    if matched.is_empty() {
        return Err(e!(ChainError::NoMatchingDnskey));
    }
    verify_signed_rrset(&zone.dnskeys, &matched)?;
    Ok(child_keys
        .into_iter()
        .map(|key| key.clone().into_owned())
        .collect())
}

/// Verifies a [`SignedRrset`] against an owned set of trusted keys.
///
/// A convenience wrapper over the internal signature check for callers that hold
/// the trusted keys as owned records (the resolver's incremental walk and the
/// denial-of-existence proofs).
///
/// # Errors
///
/// Returns [`ChainError::NoSigningKey`] or [`ChainError::Link`] like
/// [`verify_chain`].
pub(crate) fn verify_rrset_with_keys(
    signed: &SignedRrset<'_>,
    keys: &[DNSKEY<'_>],
) -> Result<(), ChainError> {
    let refs: Vec<&DNSKEY<'_>> = keys.iter().collect();
    verify_signed_rrset(signed, &refs)
}

/// Verifies a [`SignedRrset`] using whichever trusted key one of its RRSIGs names.
///
/// Tries every RRSIG in the set against every key in `keys` whose key tag and
/// algorithm match it, and succeeds on the first pair that validates. Trying
/// every matching key matters because a key tag is a checksum, not an identifier:
/// two keys can share a tag, so a tag match alone does not pick the right key
/// (RFC 4034 appendix B). Returns [`ChainError::NoSigningKey`] when no RRSIG has
/// a matching key at all, and [`ChainError::Link`] when a matching key was tried
/// but every signature check failed.
fn verify_signed_rrset(signed: &SignedRrset<'_>, keys: &[&DNSKEY<'_>]) -> Result<(), ChainError> {
    let mut matched_any = false;
    let mut last_err = None;
    let mut checks = 0usize;
    'search: for rrsig in &signed.rrsigs {
        for key in keys {
            if key.algorithm == rrsig.algorithm && key_tag(key) == rrsig.key_tag {
                matched_any = true;
                match verify_rrsig(rrsig, &signed.records, key) {
                    Ok(()) => return Ok(()),
                    Err(err) => last_err = Some(err),
                }
                // Stop after a generous number of checks so a response cannot
                // force unbounded work (see [`MAX_SIGNATURE_CHECKS`]).
                checks += 1;
                if checks >= MAX_SIGNATURE_CHECKS {
                    break 'search;
                }
            }
        }
    }
    match last_err {
        Some(err) if matched_any => Err(e!(ChainError::Link, err)),
        _ => Err(e!(ChainError::NoSigningKey)),
    }
}

/// Collects references to the DNSKEY records in an RRset.
///
/// Returns [`ChainError::NoDnskeys`] when the RRset holds no DNSKEY record.
fn dnskeys_of<'a, 'b>(
    records: &'b [ResourceRecord<'a>],
) -> Result<Vec<&'b DNSKEY<'a>>, ChainError> {
    let keys: Vec<&DNSKEY<'_>> = records
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::DNSKEY(dnskey) => Some(dnskey),
            _ => None,
        })
        .collect();
    if keys.is_empty() {
        Err(e!(ChainError::NoDnskeys))
    } else {
        Ok(keys)
    }
}

/// Collects references to the DS records in an RRset.
///
/// Returns [`ChainError::NoDelegation`] when the RRset holds no DS record.
fn ds_records_of<'a, 'b>(records: &'b [ResourceRecord<'a>]) -> Result<Vec<&'b DS<'a>>, ChainError> {
    let ds: Vec<&DS<'_>> = records
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::DS(ds) => Some(ds),
            _ => None,
        })
        .collect();
    if ds.is_empty() {
        Err(e!(ChainError::NoDelegation))
    } else {
        Ok(ds)
    }
}

/// Returns the owner name shared by an RRset, taken from its first record.
///
/// Returns [`ChainError::EmptyRrset`] when the RRset is empty.
fn owner_of<'a, 'b>(records: &'b [ResourceRecord<'a>]) -> Result<&'b Name<'a>, ChainError> {
    records
        .first()
        .map(|rr| &rr.name)
        .ok_or_else(|| e!(ChainError::EmptyRrset))
}

/// Reconstructs the signed data for an RRSIG in canonical form.
///
/// The layout is the RRSIG RDATA up to but not including the signature field,
/// followed by each covered record in canonical form, with the records sorted
/// by their canonical encoding (RFC 4034 sections 6.2 and 6.3).
fn signed_data(rrsig: &RRSIG<'_>, rrset: &[ResourceRecord<'_>]) -> Result<Vec<u8>, DnssecError> {
    let first = rrset.first().ok_or_else(|| e!(DnssecError::EmptyRrset))?;
    let owner = &first.name;
    for rr in rrset {
        if rr.name != *owner
            || rr.class != first.class
            || u16::from(rr.rdata.type_code()) != rrsig.type_covered
        {
            return Err(e!(DnssecError::InconsistentRrset));
        }
    }

    let owner_wire = canonical_owner(owner, rrsig.labels)?;

    // RRSIG RDATA without the trailing signature field. RFC 4035 section 5.3.2
    // requires the signer name here to be in canonical form, which per RFC 4034
    // section 6.1 (and the RRSIG entry in the section 6.2 downcase list) means
    // lowercased. A signer whose on-wire name carries uppercase letters signed
    // over the lowercased form, so we must lowercase it to match.
    let mut signed = Vec::new();
    signed.extend_from_slice(&rrsig.type_covered.to_be_bytes());
    signed.push(rrsig.algorithm);
    signed.push(rrsig.labels);
    signed.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
    signed.extend_from_slice(&rrsig.signature_expiration.to_be_bytes());
    signed.extend_from_slice(&rrsig.signature_inception.to_be_bytes());
    signed.extend_from_slice(&rrsig.key_tag.to_be_bytes());
    signed.extend_from_slice(&encode_name(rrsig.signer_name.as_bytes(), true));

    // RFC 4034 section 6.3 orders the records within the RRset by their
    // canonical RDATA alone, treated as a left-justified octet sequence. Sort on
    // just the RDATA, not the full record encoding: the RDLEN field is not part
    // of the ordering key, and including it would misorder an RRset whose members
    // have different RDATA lengths (a DNSKEY or DS set, for example), producing
    // the wrong signed data and a spurious verification failure.
    let mut rdatas = Vec::with_capacity(rrset.len());
    for rr in rrset {
        rdatas.push(canonical_rdata(&rr.rdata)?);
    }
    rdatas.sort_unstable();
    // RFC 4034 section 6.3: if two RRs in the set are identical, only one is
    // included in the signed data. Owner, type, class, and TTL are identical
    // across the RRset (checked above), so equal canonical RDATA means a
    // duplicate RR. A signer removes duplicates before signing, so a response
    // that repeats a record would otherwise produce different signed data and a
    // spurious verification failure.
    rdatas.dedup();

    // Each record contributes owner | type | class | RRSIG original TTL | RDLEN |
    // RDATA in canonical form. Owner, type, class, and TTL are identical across
    // the RRset (checked above), so only the RDATA varies between records.
    for rdata in rdatas {
        signed.extend_from_slice(&owner_wire);
        signed.extend_from_slice(&rrsig.type_covered.to_be_bytes());
        signed.extend_from_slice(&(first.class as u16).to_be_bytes());
        signed.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        signed.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        signed.extend_from_slice(&rdata);
    }

    Ok(signed)
}

/// Encodes the owner name used for the signature, expanding wildcards.
///
/// When `rrsig_labels` equals the owner's label count the owner is used as is.
/// When it is smaller, the record matched a wildcard, and the name is
/// reconstructed as `*` plus the trailing `rrsig_labels` labels (RFC 4035
/// section 5.3.2). A larger count is invalid.
fn canonical_owner(owner: &Name<'_>, rrsig_labels: u8) -> Result<Vec<u8>, DnssecError> {
    let labels: Vec<&[u8]> = owner.as_bytes().collect();
    let count = labels.len();
    let wanted = rrsig_labels as usize;
    if wanted == count {
        Ok(encode_name(labels.into_iter(), true))
    } else if wanted < count {
        let mut expanded: Vec<&[u8]> = Vec::with_capacity(wanted + 1);
        expanded.push(b"*");
        expanded.extend_from_slice(&labels[count - wanted..]);
        Ok(encode_name(expanded.into_iter(), true))
    } else {
        Err(e!(DnssecError::WildcardLabels))
    }
}

/// Encodes a sequence of labels into canonical wire form.
///
/// Emits each label length-prefixed, followed by the root terminator. When
/// `downcase` is set, uppercase ASCII letters are lowercased, which is the
/// canonical form for owner names (RFC 4034 section 6.1). The RRSIG signer name
/// is encoded without downcasing to reproduce the exact signed bytes.
fn encode_name<'a>(labels: impl Iterator<Item = &'a [u8]>, downcase: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for label in labels {
        out.push(label.len() as u8);
        if downcase {
            out.extend(label.iter().map(u8::to_ascii_lowercase));
        } else {
            out.extend_from_slice(label);
        }
    }
    out.push(0);
    out
}

/// Serializes the RDATA of a supported record type into canonical wire form.
///
/// The supported types (A, AAAA, DNSKEY, DS, NSEC, NSEC3) carry no embedded
/// domain names that DNS compresses, so their canonical RDATA is their plain wire
/// RDATA. NSEC3 arrives as an unparsed [`RData::NULL`] because [`simple_dns`] does
/// not model it, so its raw RDATA is used directly. Other types return
/// [`DnssecError::UnsupportedRecordType`].
fn canonical_rdata(rdata: &RData<'_>) -> Result<Vec<u8>, DnssecError> {
    match rdata {
        RData::A(a) => Ok(a.address.to_be_bytes().to_vec()),
        RData::AAAA(aaaa) => Ok(aaaa.address.to_be_bytes().to_vec()),
        RData::DNSKEY(dnskey) => Ok(dnskey_rdata(dnskey)),
        RData::DS(ds) => Ok(ds_rdata(ds)),
        RData::NSEC(nsec) => Ok(nsec_rdata(nsec)),
        // NSEC3 (type 50) is not modeled by `simple_dns`; it parses as an
        // unknown record whose raw RDATA is already the canonical form.
        RData::NULL(NSEC3_TYPE_CODE, null) => Ok(null.get_data().to_vec()),
        other => Err(e!(DnssecError::UnsupportedRecordType {
            type_code: u16::from(other.type_code()),
        })),
    }
}

/// Serializes NSEC RDATA into wire form (next owner name and the type bit maps).
///
/// The next owner name is emitted uncompressed and without downcasing, so the
/// bytes reproduce what the zone signed (RFC 6840 section 5.1 no longer downcases
/// names embedded in RDATA). The type bit map windows are emitted in ascending
/// window order (RFC 4034 section 4.1.2).
fn nsec_rdata(nsec: &NSEC<'_>) -> Vec<u8> {
    let mut out = encode_name(nsec.next_name.as_bytes(), false);
    let mut windows: Vec<&NsecTypeBitMap<'_>> = nsec.type_bit_maps.iter().collect();
    windows.sort_by_key(|window| window.window_block);
    for window in windows {
        out.push(window.window_block);
        out.push(window.bitmap.len() as u8);
        out.extend_from_slice(&window.bitmap);
    }
    out
}

/// Serializes DNSKEY RDATA into wire form (flags, protocol, algorithm, key).
fn dnskey_rdata(dnskey: &DNSKEY<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + dnskey.public_key.len());
    out.extend_from_slice(&dnskey.flags.to_be_bytes());
    out.push(dnskey.protocol);
    out.push(dnskey.algorithm);
    out.extend_from_slice(&dnskey.public_key);
    out
}

/// Serializes DS RDATA into wire form (key tag, algorithm, digest type, digest).
fn ds_rdata(ds: &DS<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ds.digest.len());
    out.extend_from_slice(&ds.key_tag.to_be_bytes());
    out.push(ds.algorithm);
    out.push(ds.digest_type);
    out.extend_from_slice(&ds.digest);
    out
}

/// Verifies the signature over `signed` using the RRSIG's algorithm and the key.
///
/// Dispatches on the RRSIG algorithm number:
///
/// - 8 is RSA/SHA-256 (RFC 5702).
/// - 10 is RSA/SHA-512 (RFC 5702).
/// - 13 is ECDSA P-256 SHA-256 (RFC 6605).
/// - 14 is ECDSA P-384 SHA-384 (RFC 6605).
/// - 15 is Ed25519 (RFC 8080).
///
/// Any other algorithm is unsupported. The deprecated RSA/SHA-1 (5 and 7) and
/// DSA (3 and 6) algorithms are deliberately absent.
fn verify_signature(
    rrsig: &RRSIG<'_>,
    dnskey: &DNSKEY<'_>,
    signed: &[u8],
) -> Result<(), DnssecError> {
    match rrsig.algorithm {
        13 => {
            // RFC 6605: the DNSKEY holds the raw 64-byte curve point x || y.
            // `ring` expects the uncompressed SEC1 point 0x04 || x || y, and the
            // DNSSEC signature is the fixed-width r || s that FIXED verifies.
            if dnskey.public_key.len() != 64 {
                return Err(e!(DnssecError::InvalidKey));
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&dnskey.public_key);
            let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point);
            key.verify(signed, &rrsig.signature)
                .map_err(|_| e!(DnssecError::BadSignature))
        }
        14 => {
            // RFC 6605: the P-384 DNSKEY holds the raw 96-byte curve point
            // x || y. As for P-256, prepend the 0x04 uncompressed-point tag and
            // verify the fixed-width r || s signature.
            if dnskey.public_key.len() != 96 {
                return Err(e!(DnssecError::InvalidKey));
            }
            let mut point = Vec::with_capacity(97);
            point.push(0x04);
            point.extend_from_slice(&dnskey.public_key);
            let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, point);
            key.verify(signed, &rrsig.signature)
                .map_err(|_| e!(DnssecError::BadSignature))
        }
        15 => {
            // RFC 8080: the DNSKEY holds the raw 32-byte Ed25519 public key, and
            // the RRSIG holds the 64-byte Ed25519 signature.
            if dnskey.public_key.len() != 32 {
                return Err(e!(DnssecError::InvalidKey));
            }
            let key = signature::UnparsedPublicKey::new(&signature::ED25519, &dnskey.public_key);
            key.verify(signed, &rrsig.signature)
                .map_err(|_| e!(DnssecError::BadSignature))
        }
        8 | 10 => {
            // RFC 5702: both share the RFC 3110 key encoding and differ only in
            // the hash. Algorithm 8 is SHA-256, algorithm 10 is SHA-512.
            let params = if rrsig.algorithm == 8 {
                &signature::RSA_PKCS1_2048_8192_SHA256
            } else {
                &signature::RSA_PKCS1_2048_8192_SHA512
            };
            let (exponent, modulus) = split_rsa_public_key(&dnskey.public_key)?;
            let components = signature::RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            };
            components
                .verify(params, signed, &rrsig.signature)
                .map_err(|_| e!(DnssecError::BadSignature))
        }
        algorithm => Err(e!(DnssecError::UnsupportedAlgorithm { algorithm })),
    }
}

/// Splits an RSA DNSKEY public key into its exponent and modulus (RFC 3110).
///
/// The wire form is a length-prefixed exponent followed by the modulus. A
/// leading zero byte signals a two-byte exponent length; otherwise the first
/// byte is the length directly.
fn split_rsa_public_key(public_key: &[u8]) -> Result<(&[u8], &[u8]), DnssecError> {
    let (exp_len, rest) = match public_key.split_first() {
        Some((0, rest)) => {
            let (len_bytes, rest) = rest
                .split_at_checked(2)
                .ok_or_else(|| e!(DnssecError::InvalidKey))?;
            (
                usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]])),
                rest,
            )
        }
        Some((&len, rest)) => (usize::from(len), rest),
        None => return Err(e!(DnssecError::InvalidKey)),
    };
    if exp_len == 0 {
        return Err(e!(DnssecError::InvalidKey));
    }
    rest.split_at_checked(exp_len)
        .filter(|(_, modulus)| !modulus.is_empty())
        .ok_or_else(|| e!(DnssecError::InvalidKey))
}

// ============================================================================
// Authenticated denial of existence (NSEC and NSEC3)
// ============================================================================
//
// The proofs below take the denial records from a response's authority section
// together with the trusted DNSKEY set of the zone that owns them, validate each
// record's signature, and evaluate the RFC 4034, RFC 4035, and RFC 5155 denial
// logic. The caller establishes the trusted keys through the chain of trust; the
// proofs never treat an unvalidated or absent record as proof, so every failure
// is fail-closed (Bogus). NSEC3 arrives as an unparsed record because
// `simple_dns` does not model it, so its RDATA is parsed here per RFC 5155.

/// The NSEC record type code (RFC 4034 section 4).
const NSEC_TYPE_CODE: u16 = 47;
/// The NSEC3 record type code (RFC 5155 section 3).
const NSEC3_TYPE_CODE: u16 = 50;
/// The NS record type code (RFC 1035).
const NS_TYPE_CODE: u16 = 2;
/// The SOA record type code (RFC 1035).
const SOA_TYPE_CODE: u16 = 6;
/// The CNAME record type code (RFC 1035).
const CNAME_TYPE_CODE: u16 = 5;
/// The DS record type code (RFC 4034 section 5).
const DS_TYPE_CODE: u16 = 43;

/// The NSEC3 Opt-Out flag (RFC 5155 section 3.1.2.1).
///
/// When set on an NSEC3 that covers a name, an unsigned (insecure) delegation may
/// exist in the covered range without its own matching NSEC3.
const NSEC3_FLAG_OPT_OUT: u8 = 0x01;

/// The only defined NSEC3 hash algorithm, SHA-1 (RFC 5155 section 5).
const NSEC3_HASH_SHA1: u8 = 1;

/// The largest NSEC3 iteration count a proof will honor (RFC 9276).
///
/// RFC 9276 recommends treating a high iteration count as insecure rather than
/// doing the work. A record above this cap cannot contribute to a proof and is
/// skipped, so a response cannot force unbounded SHA-1 hashing. The cap matches
/// the value hickory-dns and the `domain` crate use for the insecure threshold.
const MAX_NSEC3_ITERATIONS: u16 = 100;

/// The largest number of NSEC or NSEC3 records one denial proof will validate.
///
/// [`MAX_SIGNATURE_CHECKS`] bounds the signature checks per record, but
/// [`validated_nsecs`] and [`validated_nsec3s`] run that check for every record
/// in the authority section, so without a second bound the total scales with the
/// section length (up to roughly a thousand records over TCP). An attacker who
/// queries a genuinely signed zone could pad the authority section with NSEC3
/// records carrying tag- and algorithm-matching but bogus RRSIGs and force
/// thousands of failed RSA or ECDSA verifications per response. Capping the
/// number of denial records each collector will verify keeps the work bounded.
/// A legitimate denial uses only a handful of records (fewer than five even for
/// the NSEC3 closest-encloser proof), so this generous cap never affects a real
/// proof; surplus records are ignored, which stays fail-closed.
const MAX_DENIAL_RECORDS: usize = 16;

/// A reason a denial-of-existence proof did not hold.
///
/// Every variant means the denial is not proven, so the caller stays fail-closed
/// (Bogus). The proofs return success only when the denial is authenticated.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, std_sources)]
#[non_exhaustive]
pub enum DenialError {
    /// No validated NSEC or NSEC3 record establishes the denial.
    #[error("no NSEC or NSEC3 record proves the denial")]
    NoProof {},
    /// A matching record shows the queried type is present, so it is not absent.
    #[error("the queried type is present, so its absence is not proven")]
    TypePresent {},
    /// No validated record covers the queried name in the canonical ordering.
    #[error("no NSEC or NSEC3 covers the queried name")]
    NotCovered {},
    /// A DS record is present at the delegation, so it is signed, not insecure.
    #[error("the delegation carries a DS, so it is secure not insecure")]
    SecureDelegation {},
}

/// A parsed NSEC3 record (RFC 5155 section 3).
///
/// `simple_dns` does not model NSEC3, so it surfaces as an unknown record whose
/// RDATA this type parses. The `next_hashed_owner` and the owner name's first
/// label are unpadded lowercase base32hex hashes over the canonical owner name.
#[derive(Debug, Clone)]
struct Nsec3 {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>,
    next_hashed_owner: Vec<u8>,
    /// The type bit map windows, each `(window_block, bitmap)` (RFC 4034 4.1.2).
    type_bit_maps: Vec<(u8, Vec<u8>)>,
}

impl Nsec3 {
    /// Parses NSEC3 RDATA (RFC 5155 section 3.2), returning `None` if truncated.
    fn parse(rdata: &[u8]) -> Option<Self> {
        let hash_algorithm = *rdata.first()?;
        let flags = *rdata.get(1)?;
        let iterations = u16::from_be_bytes([*rdata.get(2)?, *rdata.get(3)?]);
        let salt_len = *rdata.get(4)? as usize;
        let salt_end = 5 + salt_len;
        let salt = rdata.get(5..salt_end)?.to_vec();
        let hash_len = *rdata.get(salt_end)? as usize;
        let hash_start = salt_end + 1;
        let hash_end = hash_start + hash_len;
        let next_hashed_owner = rdata.get(hash_start..hash_end)?.to_vec();

        let mut type_bit_maps = Vec::new();
        let mut rest = rdata.get(hash_end..)?;
        while !rest.is_empty() {
            let window = *rest.first()?;
            let len = *rest.get(1)? as usize;
            let bitmap = rest.get(2..2 + len)?.to_vec();
            type_bit_maps.push((window, bitmap));
            rest = rest.get(2 + len..)?;
        }

        Some(Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            type_bit_maps,
        })
    }
}

/// Proves that `qname` exists but has no records of type `qtype` (NODATA).
///
/// A validated NSEC that matches `qname` with the `qtype` bit clear, or the NSEC3
/// equivalent, proves the type is absent (RFC 4035 section 5.4, RFC 5155 section
/// 8.5). A matching record that also carries a CNAME bit is rejected for any
/// query other than CNAME, since a CNAME would answer through aliasing.
///
/// # Errors
///
/// Returns [`DenialError::TypePresent`] when a matching record shows `qtype` (or
/// a CNAME) is present, and [`DenialError::NoProof`] when no validated record
/// matches `qname`.
pub fn prove_nodata(
    qname: &Name<'_>,
    qtype: u16,
    authority: &[ResourceRecord<'_>],
    keys: &[DNSKEY<'_>],
) -> Result<(), DenialError> {
    for (owner, nsec) in validated_nsecs(authority, keys) {
        if canonical_name_cmp(&owner, qname) == Ordering::Equal {
            return nodata_from_bits(|type_code| nsec_type_present(&nsec, type_code), qtype);
        }
    }
    for (owner, nsec3) in validated_nsec3s(authority, keys) {
        if nsec3_owner_matches(&owner, qname, &nsec3) {
            return nodata_from_bits(|type_code| nsec3_type_present(&nsec3, type_code), qtype);
        }
    }
    Err(e!(DenialError::NoProof))
}

/// Applies the NODATA type-bit rules given a way to test a type's presence.
fn nodata_from_bits(present: impl Fn(u16) -> bool, qtype: u16) -> Result<(), DenialError> {
    if present(qtype) {
        return Err(e!(DenialError::TypePresent));
    }
    // A CNAME at the name answers any type through aliasing, so NODATA for a
    // non-CNAME type is only valid when no CNAME is present (RFC 4035 5.4).
    if qtype != CNAME_TYPE_CODE && present(CNAME_TYPE_CODE) {
        return Err(e!(DenialError::TypePresent));
    }
    Ok(())
}

/// Proves that `qname` does not exist at all (NXDOMAIN).
///
/// For NSEC this requires a validated NSEC covering `qname` and a validated NSEC
/// covering the wildcard at the closest encloser (RFC 4035 section 5.4). For
/// NSEC3 this runs the closest-encloser proof: a match for the closest encloser,
/// a record covering the next closer name, and a record covering the wildcard
/// (RFC 5155 section 8.4).
///
/// # Errors
///
/// Returns [`DenialError::NotCovered`] when no record covers `qname`, and
/// [`DenialError::NoProof`] when the wildcard or closest-encloser part is
/// missing.
pub fn prove_nxdomain(
    qname: &Name<'_>,
    authority: &[ResourceRecord<'_>],
    keys: &[DNSKEY<'_>],
) -> Result<(), DenialError> {
    let nsecs = validated_nsecs(authority, keys);
    if !nsecs.is_empty() {
        let Some((owner, nsec)) = nsecs
            .iter()
            .find(|(owner, nsec)| nsec_covers(owner, &nsec.next_name, qname))
        else {
            return Err(e!(DenialError::NotCovered));
        };
        // The closest encloser is the deepest ancestor of `qname` that the
        // covering NSEC proves to exist. Its wildcard must also be covered, or a
        // wildcard could have synthesized the name.
        let closest = closest_encloser(qname, owner, &nsec.next_name);
        let wildcard = prepend_wildcard(&closest);
        if nsecs
            .iter()
            .any(|(owner, nsec)| nsec_covers(owner, &nsec.next_name, &wildcard))
        {
            return Ok(());
        }
        return Err(e!(DenialError::NoProof));
    }

    prove_nxdomain_nsec3(qname, &validated_nsec3s(authority, keys))
}

/// Runs the NSEC3 closest-encloser proof for NXDOMAIN (RFC 5155 section 8.4).
fn prove_nxdomain_nsec3(
    qname: &Name<'_>,
    nsec3s: &[(Name<'static>, Nsec3)],
) -> Result<(), DenialError> {
    let Some((_, first)) = nsec3s.first() else {
        return Err(e!(DenialError::NoProof));
    };
    let salt = first.salt.clone();
    let iterations = first.iterations;
    let hash = |name: &Name<'_>| base32hex_encode(&nsec3_hash(name, &salt, iterations));

    let labels = qname.as_bytes().count();
    // Try each ancestor of `qname` as the closest encloser, deepest first.
    for encloser_labels in (0..labels).rev() {
        let encloser = suffix_name(qname, encloser_labels);
        let encloser_hash = hash(&encloser);
        let matched = nsec3s
            .iter()
            .any(|(owner, _)| nsec3_owner_hash(owner).as_deref() == Some(encloser_hash.as_str()));
        if !matched {
            continue;
        }
        let next_closer = suffix_name(qname, encloser_labels + 1);
        if !nsec3s_cover(nsec3s, &hash(&next_closer)) {
            continue;
        }
        let wildcard = prepend_wildcard(&encloser);
        if nsec3s_cover(nsec3s, &hash(&wildcard)) {
            return Ok(());
        }
    }
    Err(e!(DenialError::NoProof))
}

/// Proves that the delegation at `child` is insecure: it has an NS record but no
/// DS, so the child zone is unsigned (RFC 4035 section 5.2, RFC 5155 section 8.6).
///
/// For NSEC a matching record with the NS bit set, the DS bit clear, and the SOA
/// bit clear proves the delegation is unsigned. For NSEC3 the same match works,
/// and an Opt-Out record covering the name also proves it (RFC 5155 section 6).
///
/// # Errors
///
/// Returns [`DenialError::SecureDelegation`] when a matching record carries a DS,
/// and [`DenialError::NoProof`] when nothing proves the delegation is insecure.
pub fn prove_no_ds(
    child: &Name<'_>,
    authority: &[ResourceRecord<'_>],
    keys: &[DNSKEY<'_>],
) -> Result<(), DenialError> {
    for (owner, nsec) in validated_nsecs(authority, keys) {
        if canonical_name_cmp(&owner, child) == Ordering::Equal {
            if nsec_type_present(&nsec, DS_TYPE_CODE) {
                return Err(e!(DenialError::SecureDelegation));
            }
            if nsec_type_present(&nsec, NS_TYPE_CODE) && !nsec_type_present(&nsec, SOA_TYPE_CODE) {
                return Ok(());
            }
        }
    }

    let nsec3s = validated_nsec3s(authority, keys);
    for (owner, nsec3) in &nsec3s {
        if nsec3_owner_matches(owner, child, nsec3) {
            if nsec3_type_present(nsec3, DS_TYPE_CODE) {
                return Err(e!(DenialError::SecureDelegation));
            }
            if nsec3_type_present(nsec3, NS_TYPE_CODE) && !nsec3_type_present(nsec3, SOA_TYPE_CODE)
            {
                return Ok(());
            }
        }
    }
    // Opt-Out: a covering NSEC3 with the flag set spans unsigned delegations.
    let child_hash =
        |nsec3: &Nsec3| base32hex_encode(&nsec3_hash(child, &nsec3.salt, nsec3.iterations));
    for (owner, nsec3) in &nsec3s {
        if nsec3.flags & NSEC3_FLAG_OPT_OUT == 0 {
            continue;
        }
        if let Some(owner_hash) = nsec3_owner_hash(owner) {
            let next_hash = base32hex_encode(&nsec3.next_hashed_owner);
            if nsec3_covers(&owner_hash, &next_hash, &child_hash(nsec3)) {
                return Ok(());
            }
        }
    }
    Err(e!(DenialError::NoProof))
}

/// Proves a wildcard-expanded answer for `qname` has no closer match.
///
/// The answer was synthesized from `*.<encloser>` where the encloser is the last
/// `wildcard_labels` labels of `qname`. The proof shows the next closer name
/// (`qname` truncated to `wildcard_labels + 1` labels) does not exist, so no name
/// between the encloser and `qname` could have answered instead (RFC 4035 section
/// 5.3.4, RFC 5155 section 8.8).
///
/// # Errors
///
/// Returns [`DenialError::NoProof`] when no validated record covers the next
/// closer name.
pub fn prove_wildcard(
    qname: &Name<'_>,
    wildcard_labels: u8,
    authority: &[ResourceRecord<'_>],
    keys: &[DNSKEY<'_>],
) -> Result<(), DenialError> {
    let qlabels = qname.as_bytes().count();
    let next_closer_len = (wildcard_labels as usize).saturating_add(1);
    if next_closer_len > qlabels {
        return Err(e!(DenialError::NoProof));
    }
    let next_closer = suffix_name(qname, next_closer_len);

    for (owner, nsec) in validated_nsecs(authority, keys) {
        if nsec_covers(&owner, &nsec.next_name, &next_closer) {
            return Ok(());
        }
    }
    for (owner, nsec3) in validated_nsec3s(authority, keys) {
        if let Some(owner_hash) = nsec3_owner_hash(&owner) {
            let next_hash = base32hex_encode(&nsec3.next_hashed_owner);
            let target = base32hex_encode(&nsec3_hash(&next_closer, &nsec3.salt, nsec3.iterations));
            if nsec3_covers(&owner_hash, &next_hash, &target) {
                return Ok(());
            }
        }
    }
    Err(e!(DenialError::NoProof))
}

/// Collects the validated NSEC records from an authority section.
///
/// Each NSEC is kept only if one of the RRSIGs over it, in the same section,
/// verifies under `keys`. That ties the record to the zone whose keys are
/// trusted, so a record from an unrelated zone cannot slip in. At most
/// [`MAX_DENIAL_RECORDS`] records are verified, bounding the signature work a
/// padded authority section can force.
fn validated_nsecs<'a>(
    authority: &'a [ResourceRecord<'a>],
    keys: &[DNSKEY<'_>],
) -> Vec<(Name<'static>, NSEC<'static>)> {
    let mut out = Vec::new();
    let mut considered = 0usize;
    for rr in authority {
        let RData::NSEC(nsec) = &rr.rdata else {
            continue;
        };
        // Cap the records whose signature is checked (see [`MAX_DENIAL_RECORDS`]).
        considered += 1;
        if considered > MAX_DENIAL_RECORDS {
            break;
        }
        let records = [rr.clone()];
        if authority_rrset_signed(&records, &rr.name, NSEC_TYPE_CODE, authority, keys) {
            out.push((rr.name.clone().into_owned(), nsec.clone().into_owned()));
        }
    }
    out
}

/// Collects the validated NSEC3 records from an authority section.
///
/// Records whose hash algorithm is not SHA-1 or whose iteration count exceeds
/// [`MAX_NSEC3_ITERATIONS`] are dropped, as are records that set a reserved flag
/// bit (RFC 5155 section 3.1.2 defines only Opt-Out). All survivors must share
/// the hash algorithm, iterations, and salt of the first validated record (RFC
/// 5155 section 8.2), so a mixed set cannot smuggle in a record hashed under
/// different parameters. Each survivor must also carry a valid signature under
/// `keys`.
fn validated_nsec3s<'a>(
    authority: &'a [ResourceRecord<'a>],
    keys: &[DNSKEY<'_>],
) -> Vec<(Name<'static>, Nsec3)> {
    let mut out = Vec::new();
    // The parameters of the first validated record, which every later record must
    // match. Set only after a signature check so an unsigned record cannot fix the
    // reference parameters and evict the real ones.
    let mut params: Option<(u8, u16, Vec<u8>)> = None;
    let mut considered = 0usize;
    for rr in authority {
        let RData::NULL(NSEC3_TYPE_CODE, null) = &rr.rdata else {
            continue;
        };
        let Some(nsec3) = Nsec3::parse(null.get_data()) else {
            continue;
        };
        if nsec3.hash_algorithm != NSEC3_HASH_SHA1 || nsec3.iterations > MAX_NSEC3_ITERATIONS {
            continue;
        }
        if nsec3.flags & !NSEC3_FLAG_OPT_OUT != 0 {
            continue;
        }
        if let Some((algorithm, iterations, salt)) = &params {
            if nsec3.hash_algorithm != *algorithm
                || nsec3.iterations != *iterations
                || nsec3.salt != *salt
            {
                continue;
            }
        }
        // Cap the records whose signature is checked (see [`MAX_DENIAL_RECORDS`]).
        considered += 1;
        if considered > MAX_DENIAL_RECORDS {
            break;
        }
        let records = [rr.clone()];
        if authority_rrset_signed(&records, &rr.name, NSEC3_TYPE_CODE, authority, keys) {
            if params.is_none() {
                params = Some((nsec3.hash_algorithm, nsec3.iterations, nsec3.salt.clone()));
            }
            out.push((rr.name.clone().into_owned(), nsec3));
        }
    }
    out
}

/// Returns whether one of the RRSIGs over `records` in `authority` verifies.
///
/// Matches every RRSIG that covers `type_covered` and shares `owner` against each
/// key whose tag and algorithm fit, capping the number of signature checks at
/// [`MAX_SIGNATURE_CHECKS`] to bound the work a response can force.
fn authority_rrset_signed(
    records: &[ResourceRecord<'_>],
    owner: &Name<'_>,
    type_covered: u16,
    authority: &[ResourceRecord<'_>],
    keys: &[DNSKEY<'_>],
) -> bool {
    let mut checks = 0usize;
    for rr in authority {
        let RData::RRSIG(sig) = &rr.rdata else {
            continue;
        };
        if rr.name != *owner || sig.type_covered != type_covered {
            continue;
        }
        for key in keys {
            if key.algorithm == sig.algorithm && key_tag(key) == sig.key_tag {
                if verify_rrsig(sig, records, key).is_ok() {
                    return true;
                }
                checks += 1;
                if checks >= MAX_SIGNATURE_CHECKS {
                    return false;
                }
            }
        }
    }
    false
}

/// Returns whether any NSEC3 in `nsec3s` covers the hash `target`.
fn nsec3s_cover(nsec3s: &[(Name<'static>, Nsec3)], target: &str) -> bool {
    nsec3s.iter().any(|(owner, nsec3)| {
        nsec3_owner_hash(owner).is_some_and(|owner_hash| {
            let next_hash = base32hex_encode(&nsec3.next_hashed_owner);
            nsec3_covers(&owner_hash, &next_hash, target)
        })
    })
}

/// Returns whether an NSEC3 owner matches the hash of `name`.
fn nsec3_owner_matches(owner: &Name<'_>, name: &Name<'_>, nsec3: &Nsec3) -> bool {
    let target = base32hex_encode(&nsec3_hash(name, &nsec3.salt, nsec3.iterations));
    nsec3_owner_hash(owner).as_deref() == Some(target.as_str())
}

/// Returns the NSEC3 owner hash: the lowercase first label of the owner name.
fn nsec3_owner_hash(owner: &Name<'_>) -> Option<String> {
    owner
        .as_bytes()
        .next()
        .map(|label| String::from_utf8_lossy(&label.to_ascii_lowercase()).into_owned())
}

/// Compares two domain names in canonical DNS order (RFC 4034 section 6.1).
///
/// Names sort by their labels from the least significant (rightmost) first, each
/// label compared as a left-justified case-insensitive octet sequence. A name
/// with fewer labels sorts before a longer name that shares its suffix.
fn canonical_name_cmp(a: &Name<'_>, b: &Name<'_>) -> Ordering {
    let a_labels: Vec<Vec<u8>> = a.as_bytes().map(<[u8]>::to_ascii_lowercase).collect();
    let b_labels: Vec<Vec<u8>> = b.as_bytes().map(<[u8]>::to_ascii_lowercase).collect();
    for (label_a, label_b) in a_labels.iter().rev().zip(b_labels.iter().rev()) {
        match label_a.cmp(label_b) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    a_labels.len().cmp(&b_labels.len())
}

/// Returns whether the NSEC gap `(owner, next)` covers `target`.
///
/// `target` is covered when it sorts strictly after `owner` and strictly before
/// `next`. The last NSEC in a zone wraps: its `next` is the apex, which sorts
/// first, so a name after `owner` or before `next` is covered.
fn nsec_covers(owner: &Name<'_>, next: &Name<'_>, target: &Name<'_>) -> bool {
    if canonical_name_cmp(owner, next) == Ordering::Less {
        canonical_name_cmp(owner, target) == Ordering::Less
            && canonical_name_cmp(target, next) == Ordering::Less
    } else {
        canonical_name_cmp(owner, target) == Ordering::Less
            || canonical_name_cmp(target, next) == Ordering::Less
    }
}

/// Returns whether the NSEC3 hash gap `(owner_hash, next_hash)` covers `target`.
///
/// The hashes are order-preserving base32hex strings, so string comparison
/// matches the canonical hashed-owner order. The last NSEC3 wraps like NSEC.
fn nsec3_covers(owner_hash: &str, next_hash: &str, target: &str) -> bool {
    if owner_hash < next_hash {
        owner_hash < target && target < next_hash
    } else {
        owner_hash < target || target < next_hash
    }
}

/// Returns the closest encloser of `qname` implied by a covering NSEC.
///
/// The closest encloser is the deepest ancestor of `qname` shown to exist by the
/// covering NSEC. It is the longer of the ancestors that `qname` shares with the
/// NSEC's owner name and with its next name (RFC 4035 section 5.3.2).
fn closest_encloser(qname: &Name<'_>, owner: &Name<'_>, next: &Name<'_>) -> Name<'static> {
    let by_owner = common_suffix_len(qname, owner);
    let by_next = common_suffix_len(qname, next);
    suffix_name(qname, by_owner.max(by_next))
}

/// Returns the number of trailing labels `a` and `b` share (case-insensitive).
fn common_suffix_len(a: &Name<'_>, b: &Name<'_>) -> usize {
    let a_labels: Vec<Vec<u8>> = a.as_bytes().map(<[u8]>::to_ascii_lowercase).collect();
    let b_labels: Vec<Vec<u8>> = b.as_bytes().map(<[u8]>::to_ascii_lowercase).collect();
    a_labels
        .iter()
        .rev()
        .zip(b_labels.iter().rev())
        .take_while(|(label_a, label_b)| label_a == label_b)
        .count()
}

/// Returns the name formed by the last `keep` labels of `name`.
///
/// A `keep` of zero yields the root. Used to derive an ancestor (closest
/// encloser or next closer) of a queried name.
fn suffix_name(name: &Name<'_>, keep: usize) -> Name<'static> {
    let labels: Vec<String> = name
        .as_bytes()
        .map(|label| String::from_utf8_lossy(label).into_owned())
        .collect();
    let start = labels.len().saturating_sub(keep);
    Name::new_unchecked(&labels[start..].join(".")).into_owned()
}

/// Returns `name` with a leading `*` wildcard label.
fn prepend_wildcard(name: &Name<'_>) -> Name<'static> {
    let base = name.to_string();
    let wildcard = if base.is_empty() {
        "*".to_string()
    } else {
        format!("*.{base}")
    };
    Name::new_unchecked(&wildcard).into_owned()
}

/// Computes the NSEC3 hash of `name` (RFC 5155 section 5).
///
/// The hash is `iterations` extra rounds of SHA-1 over the previous digest and
/// the salt, starting from the canonical (lowercased) wire form of `name` and the
/// salt.
fn nsec3_hash(name: &Name<'_>, salt: &[u8], iterations: u16) -> Vec<u8> {
    let mut input = encode_name(name.as_bytes(), true);
    input.extend_from_slice(salt);
    let mut digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    for _ in 0..iterations {
        let mut next = digest.as_ref().to_vec();
        next.extend_from_slice(salt);
        digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &next);
    }
    digest.as_ref().to_vec()
}

/// Encodes bytes as unpadded lowercase base32hex (RFC 4648 section 7).
fn base32hex_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Returns whether the NSEC type bit map marks `type_code` as present.
fn nsec_type_present(nsec: &NSEC<'_>, type_code: u16) -> bool {
    type_bit_present(
        nsec.type_bit_maps
            .iter()
            .map(|window| (window.window_block, window.bitmap.as_ref())),
        type_code,
    )
}

/// Returns whether the NSEC3 type bit map marks `type_code` as present.
fn nsec3_type_present(nsec3: &Nsec3, type_code: u16) -> bool {
    type_bit_present(
        nsec3
            .type_bit_maps
            .iter()
            .map(|(window, bitmap)| (*window, bitmap.as_slice())),
        type_code,
    )
}

/// Returns whether a type bit map has the bit for `type_code` set.
///
/// The type is located by its high octet (the window block) and its low octet
/// (the bit offset within the window), most significant bit first (RFC 4034
/// section 4.1.2).
fn type_bit_present<'a>(windows: impl Iterator<Item = (u8, &'a [u8])>, type_code: u16) -> bool {
    let target_window = (type_code >> 8) as u8;
    let offset = (type_code & 0xff) as usize;
    let byte_index = offset / 8;
    let bit = 7 - (offset % 8);
    for (window, bitmap) in windows {
        if window == target_window {
            return bitmap
                .get(byte_index)
                .is_some_and(|byte| byte & (1 << bit) != 0);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ring::{
        rand::SystemRandom,
        signature::{
            ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
            Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256, RSA_PKCS1_SHA512, RsaKeyPair,
        },
    };
    use simple_dns::{
        CLASS, Name, ResourceRecord,
        rdata::{A, RData},
    };

    use super::*;

    /// The example.com DNSKEY from RFC 4034, whose key tag is 2642. Taken from
    /// the `simple-dns` DNSKEY sample, which is the same key referenced by the
    /// RFC 4034 RRSIG example (key tag 2642).
    fn rfc4034_dnskey() -> DNSKEY<'static> {
        let public_key: &[u8] = b"\x01\x03\xd2\x2a\x6c\xa7\x7f\x35\xb8\x93\x20\x6f\xd3\x5e\x4c\x50\x6d\x83\x78\x84\x37\x09\xb9\x7e\x04\x16\x47\xe1\xbf\xf4\x3d\x8d\x64\xc6\x49\xaf\x1e\x37\x19\x73\xc9\xe8\x91\xfc\xe3\xdf\x51\x9a\x8c\x84\x0a\x63\xee\x42\xa6\xd2\xeb\xdd\xbb\x97\x03\x5d\x21\x5a\xa4\xe4\x17\xb1\xfa\x45\xfa\x11\xa9\x74\x1e\xa2\x09\x8c\x1d\xfa\x5f\xb5\xfe\xb3\x32\xfd\x4b\xc8\x15\x20\x89\xae\xf3\x6b\xa6\x44\xcc\xe2\x41\x3b\x3b\x72\xbe\x18\xcb\xef\x8d\xa2\x53\xf4\xe9\x3d\x21\x03\x86\x6d\x92\x34\xa2\xe2\x8d\xf5\x29\xa6\x7d\x54\x68\xdb\xef\xe3";
        DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 5,
            public_key: Cow::Borrowed(public_key),
        }
    }

    #[test]
    fn key_tag_matches_rfc4034_vector() {
        assert_eq!(key_tag(&rfc4034_dnskey()), 2642);
    }

    #[test]
    fn verify_ds_accepts_matching_sha256_digest() {
        // SHA-256 digest over canonical "example.com" plus the DNSKEY RDATA,
        // computed independently with Python's hashlib.
        let digest: &[u8] = &[
            182, 35, 169, 57, 1, 184, 225, 27, 54, 77, 184, 132, 153, 167, 218, 237, 110, 212, 118,
            124, 88, 89, 73, 173, 64, 64, 234, 71, 224, 182, 189, 0,
        ];
        let ds = DS {
            key_tag: 2642,
            algorithm: 5,
            digest_type: 2,
            digest: Cow::Borrowed(digest),
        };
        let owner = Name::new_unchecked("example.com");
        assert!(verify_ds(&owner, &rfc4034_dnskey(), &ds).is_ok());
    }

    #[test]
    fn verify_ds_rejects_tampered_digest() {
        let mut digest = vec![
            182, 35, 169, 57, 1, 184, 225, 27, 54, 77, 184, 132, 153, 167, 218, 237, 110, 212, 118,
            124, 88, 89, 73, 173, 64, 64, 234, 71, 224, 182, 189, 0,
        ];
        digest[0] ^= 0xFF;
        let ds = DS {
            key_tag: 2642,
            algorithm: 5,
            digest_type: 2,
            digest: Cow::Owned(digest),
        };
        let owner = Name::new_unchecked("example.com");
        assert!(matches!(
            verify_ds(&owner, &rfc4034_dnskey(), &ds),
            Err(DnssecError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn verify_ds_accepts_sha1_and_sha384_digests() {
        // Independently computed (Python hashlib) digests over canonical
        // "example.com" plus the RFC 4034 DNSKEY RDATA, mirroring the SHA-256
        // test for digest types 1 (SHA-1) and 4 (SHA-384).
        let owner = Name::new_unchecked("example.com");

        let sha1: &[u8] = &[
            133, 176, 190, 195, 215, 137, 33, 162, 82, 229, 233, 184, 162, 161, 244, 166, 35, 99,
            104, 171,
        ];
        let ds1 = DS {
            key_tag: 2642,
            algorithm: 5,
            digest_type: 1,
            digest: Cow::Borrowed(sha1),
        };
        assert!(verify_ds(&owner, &rfc4034_dnskey(), &ds1).is_ok());

        let sha384: &[u8] = &[
            121, 192, 160, 149, 17, 201, 94, 3, 190, 25, 216, 248, 35, 127, 89, 189, 37, 72, 201,
            21, 135, 243, 180, 86, 242, 229, 2, 111, 217, 139, 236, 83, 10, 19, 218, 21, 70, 251,
            59, 156, 222, 217, 164, 150, 86, 53, 88, 103,
        ];
        let ds4 = DS {
            key_tag: 2642,
            algorithm: 5,
            digest_type: 4,
            digest: Cow::Borrowed(sha384),
        };
        assert!(verify_ds(&owner, &rfc4034_dnskey(), &ds4).is_ok());

        // A tampered SHA-384 digest is rejected.
        let mut tampered = sha384.to_vec();
        tampered[0] ^= 0xFF;
        let ds_bad = DS {
            key_tag: 2642,
            algorithm: 5,
            digest_type: 4,
            digest: Cow::Owned(tampered),
        };
        assert!(matches!(
            verify_ds(&owner, &rfc4034_dnskey(), &ds_bad),
            Err(DnssecError::DigestMismatch { .. })
        ));
    }

    /// Decodes a hex string into bytes for the static algorithm known-answer
    /// vectors.
    fn hex(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn verify_signature_ecdsa_p256_known_answer() {
        // RFC 6979 Appendix A.2.5: NIST P-256, SHA-256, message "sample". The
        // DNSKEY holds the raw 64-byte point x || y; the RRSIG holds the
        // fixed-width r || s. A published vector catches a point-format or r || s
        // regression that a self-consistent sign-then-verify would miss.
        let public_key = hex(concat!(
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        ));
        let signature = hex(concat!(
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        ));
        let dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 13,
            public_key: Cow::Owned(public_key),
        };
        let rrsig = kat_rrsig(13, signature);
        assert!(verify_signature(&rrsig, &dnskey, b"sample").is_ok());
        // A one-character change to the message breaks the check.
        assert!(matches!(
            verify_signature(&rrsig, &dnskey, b"Sample"),
            Err(DnssecError::BadSignature { .. })
        ));
    }

    #[test]
    fn verify_signature_ecdsa_p384_known_answer() {
        // RFC 6979 Appendix A.2.6: NIST P-384, SHA-384, message "sample". The
        // DNSKEY holds the raw 96-byte point x || y; the RRSIG holds r || s.
        let public_key = hex(concat!(
            "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64",
            "DEF8F0EA9055866064A254515480BC13",
            "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1",
            "288B231C3AE0D4FE7344FD2533264720",
        ));
        let signature = hex(concat!(
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C",
            "81A648152E44ACF96E36DD1E80FABE46",
            "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F",
            "A329C145786E679E7B82C71A38628AC8",
        ));
        let dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 14,
            public_key: Cow::Owned(public_key),
        };
        let rrsig = kat_rrsig(14, signature);
        assert!(verify_signature(&rrsig, &dnskey, b"sample").is_ok());
        assert!(matches!(
            verify_signature(&rrsig, &dnskey, b"Sample"),
            Err(DnssecError::BadSignature { .. })
        ));
    }

    #[test]
    fn verify_signature_ed25519_known_answer() {
        // RFC 8032 section 7.1 TEST 2: Ed25519, 1-byte message 0x72. The DNSKEY
        // holds the raw 32-byte public key and the RRSIG the 64-byte signature.
        let public_key = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let signature = hex(concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ));
        let dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 15,
            public_key: Cow::Owned(public_key),
        };
        let rrsig = kat_rrsig(15, signature);
        assert!(verify_signature(&rrsig, &dnskey, &hex("72")).is_ok());
        // A one-byte change to the message breaks the check.
        assert!(matches!(
            verify_signature(&rrsig, &dnskey, &hex("73")),
            Err(DnssecError::BadSignature { .. })
        ));
    }

    /// An RRSIG carrying just the algorithm and signature that
    /// [`verify_signature`] reads; the other fields are irrelevant to it.
    fn kat_rrsig(algorithm: u8, signature: Vec<u8>) -> RRSIG<'static> {
        RRSIG {
            type_covered: 1,
            algorithm,
            labels: 0,
            original_ttl: 0,
            signature_expiration: 0,
            signature_inception: 0,
            key_tag: 0,
            signer_name: Name::new_unchecked("."),
            signature: Cow::Owned(signature),
        }
    }

    #[test]
    fn signed_data_matches_independent_vector() {
        // Independently computed (Python) canonical signed data for a single A
        // record of www.example.com -> 192.0.2.1 under a fixed RRSIG.
        let expected: &[u8] = &[
            0, 1, 13, 3, 0, 0, 14, 16, 101, 83, 241, 0, 95, 94, 16, 0, 48, 57, 7, 101, 120, 97,
            109, 112, 108, 101, 3, 99, 111, 109, 0, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112,
            108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 192, 0, 2, 1,
        ];
        let rrsig = RRSIG {
            type_covered: 1,
            algorithm: 13,
            labels: 3,
            original_ttl: 3600,
            signature_expiration: 1_700_000_000,
            signature_inception: 1_600_000_000,
            key_tag: 12345,
            signer_name: Name::new_unchecked("example.com"),
            signature: Cow::Borrowed(&[]),
        };
        let rr = ResourceRecord::new(
            Name::new_unchecked("www.example.com"),
            CLASS::IN,
            300,
            RData::A(A {
                address: u32::from_be_bytes([192, 0, 2, 1]),
            }),
        );
        assert_eq!(signed_data(&rrsig, &[rr]).unwrap(), expected);
    }

    /// RFC 4034 section 6.3 orders the records in an RRset by their canonical
    /// RDATA, not by RDATA length. Two DS records whose RDATA sort in the
    /// opposite order to their lengths must come out in RDATA order.
    #[test]
    fn signed_data_orders_rrset_by_rdata_not_length() {
        let ds_record = |key_tag: u16, digest_type: u8, digest: Vec<u8>| {
            ResourceRecord::new(
                Name::new_unchecked("example.com"),
                CLASS::IN,
                300,
                RData::DS(DS {
                    key_tag,
                    algorithm: 5,
                    digest_type,
                    digest: Cow::Owned(digest),
                }),
            )
        };
        // Lower key tag but longer RDATA (SHA-256, 32-byte digest): sorts first
        // by RDATA (leading 0x00), last by length.
        let ds_low = ds_record(0x0000, 2, vec![0x00; 32]);
        // Higher key tag but shorter RDATA (SHA-1, 20-byte digest): sorts last by
        // RDATA (leading 0xFF), first by length.
        let ds_high = ds_record(0xFFFF, 1, vec![0xFF; 20]);

        let rrsig = RRSIG {
            type_covered: 43, // DS
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            signature_expiration: 1_700_000_000,
            signature_inception: 1_600_000_000,
            key_tag: 12345,
            signer_name: Name::new_unchecked("example.com"),
            signature: Cow::Borrowed(&[]),
        };

        // Pass the records in the opposite of canonical order so the sort must fix it.
        let out = signed_data(&rrsig, &[ds_high, ds_low]).unwrap();

        let mut low_rdata = vec![0x00, 0x00, 0x05, 0x02];
        low_rdata.extend_from_slice(&[0x00; 32]);
        let mut high_rdata = vec![0xFF, 0xFF, 0x05, 0x01];
        high_rdata.extend_from_slice(&[0xFF; 20]);
        let position = |needle: &[u8]| out.windows(needle.len()).position(|w| w == needle);
        let low = position(&low_rdata).expect("ds_low rdata present");
        let high = position(&high_rdata).expect("ds_high rdata present");
        assert!(
            low < high,
            "records must be ordered by canonical RDATA, not by RDATA length"
        );
    }

    /// Builds an A RRset and an RRSIG over it whose validity period covers now.
    fn a_rrset_and_rrsig(
        algorithm: u8,
        key_tag: u16,
    ) -> (Vec<ResourceRecord<'static>>, RRSIG<'static>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let rrset = vec![
            ResourceRecord::new(
                Name::new_unchecked("www.example.com"),
                CLASS::IN,
                3600,
                RData::A(A {
                    address: u32::from_be_bytes([192, 0, 2, 1]),
                }),
            ),
            ResourceRecord::new(
                Name::new_unchecked("www.example.com"),
                CLASS::IN,
                3600,
                RData::A(A {
                    address: u32::from_be_bytes([192, 0, 2, 2]),
                }),
            ),
        ];
        let rrsig = RRSIG {
            type_covered: 1,
            algorithm,
            labels: 3,
            original_ttl: 3600,
            signature_expiration: now + 3600,
            signature_inception: now - 3600,
            key_tag,
            signer_name: Name::new_unchecked("example.com"),
            signature: Cow::Owned(Vec::new()),
        };
        (rrset, rrsig)
    }

    #[test]
    fn verify_rrsig_signer_name_is_case_insensitive() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public_key = key_pair.public_key().as_ref()[1..].to_vec();
        let dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 13,
            public_key: Cow::Owned(public_key),
        };
        let tag = key_tag(&dnskey);

        let (rrset, mut rrsig) = a_rrset_and_rrsig(13, tag);
        // The signer signs over the canonical (lowercased) signer name.
        let signed = signed_data(&rrsig, &rrset).unwrap();
        let signature = key_pair.sign(&rng, &signed).unwrap();
        rrsig.signature = Cow::Owned(signature.as_ref().to_vec());
        // The record arrives with an uppercase signer name (RFC 4035 5.3.2 lets
        // the wire form differ from the canonical form). Validation must
        // canonicalize before verifying, so this still accepts.
        rrsig.signer_name = Name::new_unchecked("Example.COM");

        assert!(verify_rrsig(&rrsig, &rrset, &dnskey).is_ok());
    }

    #[test]
    fn verify_rrsig_ecdsa_p256_round_trip() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        // The public key is the uncompressed SEC1 point 0x04 || x || y; the
        // DNSKEY carries only the 64-byte x || y.
        let public_key = key_pair.public_key().as_ref()[1..].to_vec();
        let mut dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 13,
            public_key: Cow::Owned(public_key),
        };
        let tag = key_tag(&dnskey);

        let (rrset, mut rrsig) = a_rrset_and_rrsig(13, tag);
        let signed = signed_data(&rrsig, &rrset).unwrap();
        let signature = key_pair.sign(&rng, &signed).unwrap();
        rrsig.signature = Cow::Owned(signature.as_ref().to_vec());

        assert!(verify_rrsig(&rrsig, &rrset, &dnskey).is_ok());

        // A tampered signature is rejected.
        let mut bad = rrsig.clone();
        let mut sig_bytes = bad.signature.into_owned();
        sig_bytes[0] ^= 0xFF;
        bad.signature = Cow::Owned(sig_bytes);
        assert!(matches!(
            verify_rrsig(&bad, &rrset, &dnskey),
            Err(DnssecError::BadSignature { .. })
        ));

        // A tampered record is rejected.
        let mut tampered = rrset.clone();
        tampered[0] = ResourceRecord::new(
            Name::new_unchecked("www.example.com"),
            CLASS::IN,
            3600,
            RData::A(A {
                address: u32::from_be_bytes([203, 0, 113, 9]),
            }),
        );
        assert!(matches!(
            verify_rrsig(&rrsig, &tampered, &dnskey),
            Err(DnssecError::BadSignature { .. })
        ));

        // A key with the wrong tag is rejected before any crypto runs.
        dnskey.flags = 257;
        assert!(matches!(
            verify_rrsig(&rrsig, &rrset, &dnskey),
            Err(DnssecError::KeyTagMismatch { .. })
        ));
    }

    #[test]
    fn verify_rrsig_ecdsa_p384_round_trip() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        // The public key is the uncompressed SEC1 point 0x04 || x || y; the
        // DNSKEY carries only the 96-byte x || y (RFC 6605).
        let public_key = key_pair.public_key().as_ref()[1..].to_vec();
        assert_eq!(public_key.len(), 96);
        let dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 14,
            public_key: Cow::Owned(public_key),
        };
        let tag = key_tag(&dnskey);

        let (rrset, mut rrsig) = a_rrset_and_rrsig(14, tag);
        let signed = signed_data(&rrsig, &rrset).unwrap();
        let signature = key_pair.sign(&rng, &signed).unwrap();
        rrsig.signature = Cow::Owned(signature.as_ref().to_vec());

        assert!(verify_rrsig(&rrsig, &rrset, &dnskey).is_ok());

        let mut bad = rrsig.clone();
        let mut sig_bytes = bad.signature.into_owned();
        sig_bytes[0] ^= 0xFF;
        bad.signature = Cow::Owned(sig_bytes);
        assert!(matches!(
            verify_rrsig(&bad, &rrset, &dnskey),
            Err(DnssecError::BadSignature { .. })
        ));
    }

    #[test]
    fn verify_rrsig_ed25519_round_trip() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        // RFC 8080: the DNSKEY carries the raw 32-byte Ed25519 public key.
        let public_key = key_pair.public_key().as_ref().to_vec();
        assert_eq!(public_key.len(), 32);
        let dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 15,
            public_key: Cow::Owned(public_key),
        };
        let tag = key_tag(&dnskey);

        let (rrset, mut rrsig) = a_rrset_and_rrsig(15, tag);
        let signed = signed_data(&rrsig, &rrset).unwrap();
        let signature = key_pair.sign(&signed);
        rrsig.signature = Cow::Owned(signature.as_ref().to_vec());

        assert!(verify_rrsig(&rrsig, &rrset, &dnskey).is_ok());

        // A tampered signature is rejected.
        let mut bad = rrsig.clone();
        let mut sig_bytes = bad.signature.into_owned();
        sig_bytes[0] ^= 0xFF;
        bad.signature = Cow::Owned(sig_bytes);
        assert!(matches!(
            verify_rrsig(&bad, &rrset, &dnskey),
            Err(DnssecError::BadSignature { .. })
        ));

        // A tampered record is rejected.
        let mut tampered = rrset.clone();
        tampered[0] = ResourceRecord::new(
            Name::new_unchecked("www.example.com"),
            CLASS::IN,
            3600,
            RData::A(A {
                address: u32::from_be_bytes([203, 0, 113, 9]),
            }),
        );
        assert!(matches!(
            verify_rrsig(&rrsig, &tampered, &dnskey),
            Err(DnssecError::BadSignature { .. })
        ));
    }

    #[test]
    fn verify_rrsig_rsa_sha256_round_trip() {
        // A fixed 2048-bit RSA key (PKCS#8 DER) so the test stays offline and
        // deterministic. Signing with RSA PKCS#1 v1.5 is deterministic.
        let key_pair = RsaKeyPair::from_pkcs8(RSA_PKCS8_DER).unwrap();

        // DNSKEY RSA public key (RFC 3110): exponent length, exponent, modulus.
        let mut public_key = vec![RSA_EXPONENT.len() as u8];
        public_key.extend_from_slice(RSA_EXPONENT);
        public_key.extend_from_slice(RSA_MODULUS);
        let dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 8,
            public_key: Cow::Owned(public_key),
        };
        let tag = key_tag(&dnskey);

        let (rrset, mut rrsig) = a_rrset_and_rrsig(8, tag);
        let signed = signed_data(&rrsig, &rrset).unwrap();
        let mut signature = vec![0u8; key_pair.public().modulus_len()];
        let rng = SystemRandom::new();
        key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, &signed, &mut signature)
            .unwrap();
        rrsig.signature = Cow::Owned(signature);

        assert!(verify_rrsig(&rrsig, &rrset, &dnskey).is_ok());

        let mut bad = rrsig.clone();
        let mut sig_bytes = bad.signature.into_owned();
        sig_bytes[0] ^= 0xFF;
        bad.signature = Cow::Owned(sig_bytes);
        assert!(matches!(
            verify_rrsig(&bad, &rrset, &dnskey),
            Err(DnssecError::BadSignature { .. })
        ));
    }

    #[test]
    fn verify_rrsig_rsa_sha512_round_trip() {
        // Reuse the fixed RSA key; algorithm 10 shares the RFC 3110 encoding and
        // differs from algorithm 8 only in the hash (SHA-512).
        let key_pair = RsaKeyPair::from_pkcs8(RSA_PKCS8_DER).unwrap();

        let mut public_key = vec![RSA_EXPONENT.len() as u8];
        public_key.extend_from_slice(RSA_EXPONENT);
        public_key.extend_from_slice(RSA_MODULUS);
        let dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 10,
            public_key: Cow::Owned(public_key),
        };
        let tag = key_tag(&dnskey);

        let (rrset, mut rrsig) = a_rrset_and_rrsig(10, tag);
        let signed = signed_data(&rrsig, &rrset).unwrap();
        let mut signature = vec![0u8; key_pair.public().modulus_len()];
        let rng = SystemRandom::new();
        key_pair
            .sign(&RSA_PKCS1_SHA512, &rng, &signed, &mut signature)
            .unwrap();
        rrsig.signature = Cow::Owned(signature);

        assert!(verify_rrsig(&rrsig, &rrset, &dnskey).is_ok());

        let mut bad = rrsig.clone();
        let mut sig_bytes = bad.signature.into_owned();
        sig_bytes[0] ^= 0xFF;
        bad.signature = Cow::Owned(sig_bytes);
        assert!(matches!(
            verify_rrsig(&bad, &rrset, &dnskey),
            Err(DnssecError::BadSignature { .. })
        ));
    }

    #[test]
    fn verify_rrsig_rejects_unsupported_algorithm() {
        // Algorithm 5 (RSA/SHA-1) is intentionally not supported.
        let (rrset, rrsig) = a_rrset_and_rrsig(5, 0);
        let dnskey = DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 5,
            public_key: Cow::Owned(vec![3, 1, 0, 1, 0xAB, 0xCD]),
        };
        let rrsig = RRSIG {
            key_tag: key_tag(&dnskey),
            ..rrsig
        };
        assert!(matches!(
            verify_rrsig(&rrsig, &rrset, &dnskey),
            Err(DnssecError::UnsupportedAlgorithm { algorithm: 5, .. })
        ));
    }

    #[test]
    fn verify_rrsig_rejects_revoked_key() {
        // A key with the REVOKE bit set is a well-formed zone key but must not
        // validate anything (RFC 5011). The check precedes the key-tag compare,
        // so a revoked key is refused before any crypto runs.
        let (rrset, rrsig) = a_rrset_and_rrsig(13, 0);
        let dnskey = DNSKEY {
            flags: DNSKEY_ZONE_FLAG | DNSKEY_REVOKE_FLAG,
            protocol: 3,
            algorithm: 13,
            public_key: Cow::Owned(vec![0u8; 64]),
        };
        assert!(matches!(
            verify_rrsig(&rrsig, &rrset, &dnskey),
            Err(DnssecError::InvalidKey { .. })
        ));
    }

    #[test]
    fn serial_le_handles_the_32_bit_wrap() {
        assert!(serial_le(10, 20));
        assert!(!serial_le(20, 10));
        assert!(serial_le(100, 100));
        // A time just after the counter wraps is still "after" one just before.
        let before_wrap = u32::MAX - 10;
        let after_wrap = 5u32;
        assert!(serial_le(before_wrap, after_wrap));
        assert!(!serial_le(after_wrap, before_wrap));
    }

    #[test]
    fn signed_data_removes_duplicate_rrs() {
        // RFC 4034 section 6.3: a duplicate RR is dropped when building the signed
        // data, so a set that repeats a record hashes the same as one that does
        // not, and a signature over the deduplicated set still verifies.
        let a_record = |addr: [u8; 4]| {
            ResourceRecord::new(
                Name::new_unchecked("www.example.com"),
                CLASS::IN,
                3600,
                RData::A(A {
                    address: u32::from_be_bytes(addr),
                }),
            )
        };
        let rrsig = RRSIG {
            type_covered: 1,
            algorithm: 13,
            labels: 3,
            original_ttl: 3600,
            signature_expiration: 1_700_000_000,
            signature_inception: 1_600_000_000,
            key_tag: 12345,
            signer_name: Name::new_unchecked("example.com"),
            signature: Cow::Borrowed(&[]),
        };
        let once = signed_data(&rrsig, &[a_record([192, 0, 2, 1])]).unwrap();
        let twice = signed_data(
            &rrsig,
            &[a_record([192, 0, 2, 1]), a_record([192, 0, 2, 1])],
        )
        .unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn build_dnssec_query_sets_do_bit() {
        let (_, bytes) = build_dnssec_query("example.com", TYPE::A).unwrap();
        // The OPT record still parses and the DO bit is set in its TTL flags.
        let packet = Packet::parse(&bytes).unwrap();
        assert!(packet.opt().is_some(), "query must carry an OPT record");
        let flags_hi = bytes[bytes.len() - 4];
        assert_eq!(flags_hi & 0x80, 0x80, "DO bit must be set");
    }

    mod chain {
        use super::*;

        fn now() -> u32 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32
        }

        /// Counts the labels in `name`, treating the empty string as the root.
        fn label_count(name: &str) -> u8 {
            name.split('.').filter(|l| !l.is_empty()).count() as u8
        }

        /// A test zone whose single ECDSA P-256 key acts as both its KSK and ZSK.
        struct Zone {
            name: String,
            key_pair: EcdsaKeyPair,
            dnskey: DNSKEY<'static>,
            tag: u16,
        }

        impl Zone {
            fn new(name: &str, rng: &SystemRandom) -> Self {
                let pkcs8 =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng).unwrap();
                let key_pair =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), rng)
                        .unwrap();
                let public_key = key_pair.public_key().as_ref()[1..].to_vec();
                // Flags 257: zone key plus secure entry point (a KSK).
                let dnskey = DNSKEY {
                    flags: 257,
                    protocol: 3,
                    algorithm: 13,
                    public_key: Cow::Owned(public_key),
                };
                let tag = key_tag(&dnskey);
                Self {
                    name: name.to_string(),
                    key_pair,
                    dnskey,
                    tag,
                }
            }

            fn owner(&self) -> Name<'static> {
                Name::new_unchecked(&self.name).into_owned()
            }

            /// Signs `records` (owner `owner`, covered type `type_covered`).
            fn sign(
                &self,
                records: &[ResourceRecord<'static>],
                type_covered: u16,
                owner: &str,
                rng: &SystemRandom,
            ) -> RRSIG<'static> {
                let now = now();
                let mut rrsig = RRSIG {
                    type_covered,
                    algorithm: 13,
                    labels: label_count(owner),
                    original_ttl: 3600,
                    signature_expiration: now + 3600,
                    signature_inception: now - 3600,
                    key_tag: self.tag,
                    signer_name: self.owner(),
                    signature: Cow::Owned(Vec::new()),
                };
                let signed = signed_data(&rrsig, records).unwrap();
                let sig = self.key_pair.sign(rng, &signed).unwrap();
                rrsig.signature = Cow::Owned(sig.as_ref().to_vec());
                rrsig
            }

            /// The self-signed DNSKEY RRset for this zone.
            fn signed_dnskeys(&self, rng: &SystemRandom) -> SignedRrset<'static> {
                let records = vec![ResourceRecord::new(
                    self.owner(),
                    CLASS::IN,
                    3600,
                    RData::DNSKEY(self.dnskey.clone()),
                )];
                let rrsig = self.sign(&records, 48, &self.name, rng);
                SignedRrset {
                    records,
                    rrsigs: vec![rrsig],
                }
            }

            /// A SHA-256 DS record committing to this zone's key.
            fn ds(&self) -> DS<'static> {
                let owner = self.owner();
                let mut data = encode_name(owner.as_bytes(), true);
                data.extend_from_slice(&dnskey_rdata(&self.dnskey));
                let digest = digest::digest(&digest::SHA256, &data);
                DS {
                    key_tag: self.tag,
                    algorithm: self.dnskey.algorithm,
                    digest_type: 2,
                    digest: Cow::Owned(digest.as_ref().to_vec()),
                }
            }
        }

        /// Builds a signed root -> `example` -> `host.example` A chain, plus the
        /// trust anchor over the root key.
        fn good_chain(rng: &SystemRandom) -> (ChainOfTrust<'static>, Vec<DS<'static>>) {
            let root = Zone::new("", rng);
            let child = Zone::new("example", rng);

            let root_dnskeys = root.signed_dnskeys(rng);

            // DS(example) is published in the root and signed by the root key.
            let ds_records = vec![ResourceRecord::new(
                Name::new_unchecked("example").into_owned(),
                CLASS::IN,
                3600,
                RData::DS(child.ds()),
            )];
            let ds_rrsig = root.sign(&ds_records, 43, "example", rng);

            let child_dnskeys = child.signed_dnskeys(rng);

            let target_records = vec![ResourceRecord::new(
                Name::new_unchecked("host.example").into_owned(),
                CLASS::IN,
                3600,
                RData::A(A {
                    address: u32::from_be_bytes([192, 0, 2, 1]),
                }),
            )];
            let target_rrsig = child.sign(&target_records, 1, "host.example", rng);

            let chain = ChainOfTrust {
                root_dnskeys,
                zones: vec![DelegatedZone {
                    delegation: SignedRrset {
                        records: ds_records,
                        rrsigs: vec![ds_rrsig],
                    },
                    dnskeys: child_dnskeys,
                }],
                target: SignedRrset {
                    records: target_records,
                    rrsigs: vec![target_rrsig],
                },
            };
            (chain, vec![root.ds()])
        }

        #[test]
        fn accepts_a_good_chain() {
            let rng = SystemRandom::new();
            let (chain, anchors) = good_chain(&rng);
            assert!(verify_chain_with_anchors(&chain, &anchors).is_ok());
        }

        #[test]
        fn rejects_untrusted_root() {
            let rng = SystemRandom::new();
            let (chain, _) = good_chain(&rng);
            // A DS over an unrelated key does not anchor this root.
            let stranger = Zone::new("", &rng);
            assert!(matches!(
                verify_chain_with_anchors(&chain, &[stranger.ds()]),
                Err(ChainError::UntrustedRoot { .. })
            ));
        }

        #[test]
        fn rejects_wrong_ds_digest() {
            let rng = SystemRandom::new();
            let (mut chain, anchors) = good_chain(&rng);
            // Corrupt the DS digest that delegates to the child zone.
            let RData::DS(ds) = &mut chain.zones[0].delegation.records[0].rdata else {
                panic!("delegation record must be a DS");
            };
            let mut digest = ds.digest.to_vec();
            digest[0] ^= 0xFF;
            ds.digest = Cow::Owned(digest);
            // The DS RRSIG no longer matches, so the delegation link fails first.
            assert!(matches!(
                verify_chain_with_anchors(&chain, &anchors),
                Err(ChainError::Link { .. } | ChainError::NoMatchingDnskey { .. })
            ));
        }

        #[test]
        fn rejects_tampered_leaf_signature() {
            let rng = SystemRandom::new();
            let (mut chain, anchors) = good_chain(&rng);
            let mut sig = chain.target.rrsigs[0].signature.to_vec();
            sig[0] ^= 0xFF;
            chain.target.rrsigs[0].signature = Cow::Owned(sig);
            assert!(matches!(
                verify_chain_with_anchors(&chain, &anchors),
                Err(ChainError::Link { .. })
            ));
        }

        #[test]
        fn rejects_missing_child_dnskey() {
            let rng = SystemRandom::new();
            let (mut chain, anchors) = good_chain(&rng);
            // Drop the child's DNSKEY records: the delegating DS matches nothing.
            chain.zones[0].dnskeys.records.clear();
            assert!(matches!(
                verify_chain_with_anchors(&chain, &anchors),
                Err(ChainError::NoDnskeys { .. })
            ));
        }

        #[test]
        fn dnskey_rrset_validates_with_one_good_rrsig_among_bad() {
            let rng = SystemRandom::new();
            let (mut chain, anchors) = good_chain(&rng);

            // Prepend an RRSIG from an untrusted stranger key over the child's
            // DNSKEY RRset, as if an unrelated key had signed alongside the real
            // one. Its key tag matches no trusted DNSKEY, so validation must fall
            // through to the genuine self-signature and still succeed.
            let stranger = Zone::new("", &rng);
            let records = chain.zones[0].dnskeys.records.clone();
            let bogus = stranger.sign(&records, 48, "example", &rng);
            chain.zones[0].dnskeys.rrsigs.insert(0, bogus);
            assert!(verify_chain_with_anchors(&chain, &anchors).is_ok());

            // Dropping the genuine RRSIG leaves only the untrusted one, which no
            // trusted key matches, so the chain must now fail closed.
            chain.zones[0].dnskeys.rrsigs.remove(1);
            assert!(matches!(
                verify_chain_with_anchors(&chain, &anchors),
                Err(ChainError::NoSigningKey { .. })
            ));
        }

        #[test]
        fn validates_target_deep_below_zone_apex() {
            // A target several labels below the signing zone apex, where none of
            // the intermediate labels is a zone cut, so `zones` lists only the
            // signing zone. This mirrors the resolver skipping non-cut ancestors:
            // the chain must still validate.
            let rng = SystemRandom::new();
            let root = Zone::new("", &rng);
            let child = Zone::new("example", &rng);

            let root_dnskeys = root.signed_dnskeys(&rng);
            let ds_records = vec![ResourceRecord::new(
                Name::new_unchecked("example").into_owned(),
                CLASS::IN,
                3600,
                RData::DS(child.ds()),
            )];
            let ds_rrsig = root.sign(&ds_records, 43, "example", &rng);
            let child_dnskeys = child.signed_dnskeys(&rng);

            let target_records = vec![ResourceRecord::new(
                Name::new_unchecked("a.b.c.example").into_owned(),
                CLASS::IN,
                3600,
                RData::A(A {
                    address: u32::from_be_bytes([192, 0, 2, 9]),
                }),
            )];
            let target_rrsig = child.sign(&target_records, 1, "a.b.c.example", &rng);

            let chain = ChainOfTrust {
                root_dnskeys,
                zones: vec![DelegatedZone {
                    delegation: SignedRrset {
                        records: ds_records,
                        rrsigs: vec![ds_rrsig],
                    },
                    dnskeys: child_dnskeys,
                }],
                target: SignedRrset {
                    records: target_records,
                    rrsigs: vec![target_rrsig],
                },
            };
            assert!(verify_chain_with_anchors(&chain, &[root.ds()]).is_ok());
        }

        #[test]
        fn fails_when_signing_zone_is_not_reached() {
            // If the signing zone's DS were stripped, the resolver would skip it
            // as a non-cut and it would never enter `zones`. The target, still
            // signed by that zone's key, must then fail to validate against the
            // only remaining trusted set (the root), keeping the walk fail-closed.
            let rng = SystemRandom::new();
            let (mut chain, anchors) = good_chain(&rng);
            chain.zones.clear();
            assert!(matches!(
                verify_chain_with_anchors(&chain, &anchors),
                Err(ChainError::NoSigningKey { .. })
            ));
        }

        #[test]
        fn embedded_anchors_have_expected_tags() {
            let tags: Vec<u16> = ROOT_TRUST_ANCHORS.iter().map(|ds| ds.key_tag).collect();
            assert_eq!(tags, vec![20326, 38696]);
            for ds in ROOT_TRUST_ANCHORS {
                assert_eq!(ds.algorithm, 8);
                assert_eq!(ds.digest_type, 2);
                assert_eq!(ds.digest.len(), 32);
            }
        }

        /// Returns the DNSKEY published in a root DNSKEY RRset.
        fn root_key(chain: &ChainOfTrust<'static>) -> DNSKEY<'static> {
            match &chain.root_dnskeys.records[0].rdata {
                RData::DNSKEY(key) => key.clone(),
                _ => panic!("root DNSKEY RRset must carry a DNSKEY"),
            }
        }

        #[test]
        fn accepts_a_dnskey_form_anchor() {
            let rng = SystemRandom::new();
            let (chain, _) = good_chain(&rng);
            // Pin the root key directly instead of by its DS digest. The same chain
            // that a DS-form anchor accepts must validate under the matching
            // DNSKEY-form anchor.
            let anchors = vec![TrustAnchor::Dnskey(root_key(&chain))];
            assert!(verify_chain_with_trust_anchors(&chain, &anchors).is_ok());
        }

        #[test]
        fn rejects_a_wrong_dnskey_form_anchor() {
            let rng = SystemRandom::new();
            let (chain, _) = good_chain(&rng);
            // A DNSKEY-form anchor over an unrelated key does not anchor this root.
            let stranger = Zone::new("", &rng);
            let anchors = vec![TrustAnchor::Dnskey(stranger.dnskey.clone())];
            assert!(matches!(
                verify_chain_with_trust_anchors(&chain, &anchors),
                Err(ChainError::UntrustedRoot { .. })
            ));
        }

        #[test]
        fn ds_form_trust_anchor_still_works() {
            let rng = SystemRandom::new();
            let (chain, ds_anchors) = good_chain(&rng);
            // The DS-form anchor from `good_chain`, wrapped as a `TrustAnchor`,
            // validates the same chain through the new entry point.
            let anchors: Vec<TrustAnchor> = ds_anchors.into_iter().map(TrustAnchor::Ds).collect();
            assert!(verify_chain_with_trust_anchors(&chain, &anchors).is_ok());
        }
    }

    mod denial {
        use simple_dns::rdata::NSEC;

        use super::*;

        /// Type codes the denial tests set in NSEC and NSEC3 bit maps.
        const A: u16 = 1;
        const AAAA: u16 = 28;
        const NS: u16 = 2;
        const SOA: u16 = 6;
        const DS: u16 = 43;
        const RRSIG_BIT: u16 = 46;
        const NSEC_BIT: u16 = 47;

        fn now() -> u32 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32
        }

        fn label_count(name: &str) -> u8 {
            name.split('.').filter(|label| !label.is_empty()).count() as u8
        }

        /// A single-key ECDSA P-256 zone that can sign denial records.
        struct Signer {
            key_pair: EcdsaKeyPair,
            dnskey: DNSKEY<'static>,
        }

        impl Signer {
            fn new() -> Self {
                let rng = SystemRandom::new();
                let pkcs8 =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
                let key_pair = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    pkcs8.as_ref(),
                    &rng,
                )
                .unwrap();
                let public_key = key_pair.public_key().as_ref()[1..].to_vec();
                let dnskey = DNSKEY {
                    flags: 257,
                    protocol: 3,
                    algorithm: 13,
                    public_key: Cow::Owned(public_key),
                };
                Self { key_pair, dnskey }
            }

            fn keys(&self) -> Vec<DNSKEY<'static>> {
                vec![self.dnskey.clone()]
            }

            /// Signs `records` and returns the RRSIG resource record over them.
            fn sign(
                &self,
                records: &[ResourceRecord<'static>],
                type_covered: u16,
                owner: &str,
                signer: &str,
            ) -> ResourceRecord<'static> {
                let rng = SystemRandom::new();
                let now = now();
                let mut rrsig = RRSIG {
                    type_covered,
                    algorithm: 13,
                    labels: label_count(owner),
                    original_ttl: 3600,
                    signature_expiration: now + 3600,
                    signature_inception: now - 3600,
                    key_tag: key_tag(&self.dnskey),
                    signer_name: Name::new_unchecked(signer).into_owned(),
                    signature: Cow::Owned(Vec::new()),
                };
                let signed = signed_data(&rrsig, records).unwrap();
                let sig = self.key_pair.sign(&rng, &signed).unwrap();
                rrsig.signature = Cow::Owned(sig.as_ref().to_vec());
                ResourceRecord::new(
                    Name::new_unchecked(owner).into_owned(),
                    CLASS::IN,
                    3600,
                    RData::RRSIG(rrsig),
                )
            }
        }

        /// Builds a single-window (types below 256) type bit map.
        fn bitmap(types: &[u16]) -> Vec<u8> {
            let max = types.iter().copied().max().unwrap_or(0) as usize;
            let mut bytes = vec![0u8; max / 8 + 1];
            for &type_code in types {
                let offset = (type_code & 0xff) as usize;
                bytes[offset / 8] |= 1 << (7 - (offset % 8));
            }
            bytes
        }

        /// An NSEC resource record for `owner` pointing at `next` with `types`.
        fn nsec_rr(owner: &str, next: &str, types: &[u16]) -> ResourceRecord<'static> {
            let nsec = NSEC {
                next_name: Name::new_unchecked(next).into_owned(),
                type_bit_maps: vec![NsecTypeBitMap {
                    window_block: 0,
                    bitmap: Cow::Owned(bitmap(types)),
                }],
            };
            ResourceRecord::new(
                Name::new_unchecked(owner).into_owned(),
                CLASS::IN,
                3600,
                RData::NSEC(nsec),
            )
        }

        /// Raw NSEC3 RDATA with salt `aabbccdd` and 12 iterations (RFC 5155 B).
        fn nsec3_rdata(flags: u8, next_hash: &[u8], types: &[u16]) -> Vec<u8> {
            nsec3_rdata_params(&[0xaa, 0xbb, 0xcc, 0xdd], 12, flags, next_hash, types)
        }

        /// Raw NSEC3 RDATA with a custom salt and iteration count.
        fn nsec3_rdata_params(
            salt: &[u8],
            iterations: u16,
            flags: u8,
            next_hash: &[u8],
            types: &[u16],
        ) -> Vec<u8> {
            let mut out = vec![1u8, flags];
            out.extend_from_slice(&iterations.to_be_bytes());
            out.push(salt.len() as u8);
            out.extend_from_slice(salt);
            out.push(next_hash.len() as u8);
            out.extend_from_slice(next_hash);
            let bits = bitmap(types);
            out.push(0);
            out.push(bits.len() as u8);
            out.extend_from_slice(&bits);
            out
        }

        /// Builds a name from raw-octet labels (most significant last), so labels
        /// with non-printable octets like RFC 4034's `\001` and `\200` can be
        /// expressed for the canonical-ordering vector.
        fn octet_name(labels: &[&[u8]]) -> Name<'static> {
            let labels: Vec<simple_dns::Label<'static>> = labels
                .iter()
                .map(|label| simple_dns::Label::new_unchecked(label.to_vec()))
                .collect();
            Name::new_with_labels(&labels).into_owned()
        }

        /// An NSEC3 resource record whose owner is `owner_hash` under `zone`.
        fn nsec3_rr(
            zone: &str,
            owner_hash: &str,
            flags: u8,
            next_hash: &[u8],
            types: &[u16],
        ) -> ResourceRecord<'static> {
            let owner = format!("{owner_hash}.{zone}");
            let rdata = nsec3_rdata(flags, next_hash, types);
            ResourceRecord::new(
                Name::new_unchecked(&owner).into_owned(),
                CLASS::IN,
                3600,
                RData::NULL(
                    NSEC3_TYPE_CODE,
                    simple_dns::rdata::NULL::new(&rdata).unwrap().into_owned(),
                ),
            )
        }

        /// The base32hex hash of `name` with the RFC 5155 Appendix B parameters.
        fn hash(name: &str) -> String {
            base32hex_encode(&nsec3_hash(
                &Name::new_unchecked(name),
                &[0xaa, 0xbb, 0xcc, 0xdd],
                12,
            ))
        }

        #[test]
        fn nsec3_hash_matches_rfc5155_appendix_b() {
            // Known-answer vectors from RFC 5155 Appendix B (salt aabbccdd, 12
            // iterations, SHA-1).
            let cases = [
                ("example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
                ("a.example", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
                ("ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
                ("*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
                (
                    "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example",
                    "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
                ),
            ];
            for (name, expected) in cases {
                assert_eq!(hash(name), expected, "hash mismatch for {name}");
            }
        }

        #[test]
        fn base32hex_encode_matches_rfc4648() {
            assert_eq!(base32hex_encode(b""), "");
            assert_eq!(base32hex_encode(b"f"), "co");
            assert_eq!(base32hex_encode(b"foobar"), "cpnmuoj1e8");
        }

        #[test]
        fn canonical_name_cmp_orders_by_rightmost_label() {
            let cmp = |a: &str, b: &str| {
                canonical_name_cmp(&Name::new_unchecked(a), &Name::new_unchecked(b))
            };
            // A shorter name sorts before a longer one sharing its suffix.
            assert_eq!(cmp("example.com", "a.example.com"), Ordering::Less);
            // Comparison is by the rightmost label first, so the TLD dominates.
            assert_eq!(cmp("z.example.com", "a.example.org"), Ordering::Less);
            // The wildcard label sorts before ordinary labels.
            assert_eq!(cmp("*.example.com", "a.example.com"), Ordering::Less);
            // Case does not matter.
            assert_eq!(cmp("Example.COM", "example.com"), Ordering::Equal);
        }

        #[test]
        fn nsec_covers_handles_the_apex_wrap() {
            let covers = |owner: &str, next: &str, target: &str| {
                nsec_covers(
                    &Name::new_unchecked(owner),
                    &Name::new_unchecked(next),
                    &Name::new_unchecked(target),
                )
            };
            assert!(covers("a.example.com", "c.example.com", "b.example.com"));
            assert!(!covers("a.example.com", "c.example.com", "d.example.com"));
            // The last NSEC wraps back to the apex: names after the last owner are
            // covered even though the next name sorts earlier.
            assert!(covers("z.example.com", "example.com", "zz.example.com"));
        }

        #[test]
        fn nodata_nsec_proves_absent_type() {
            let signer = Signer::new();
            let nsec = nsec_rr(
                "host.example.com",
                "z.example.com",
                &[AAAA, RRSIG_BIT, NSEC_BIT],
            );
            let rrsig = signer.sign(
                std::slice::from_ref(&nsec),
                NSEC_BIT,
                "host.example.com",
                "example.com",
            );
            let authority = vec![nsec, rrsig];
            let qname = Name::new_unchecked("host.example.com");
            assert!(prove_nodata(&qname, A, &authority, &signer.keys()).is_ok());
        }

        #[test]
        fn nodata_nsec_rejects_present_type() {
            let signer = Signer::new();
            // The bit map now lists A, so A is not absent.
            let nsec = nsec_rr(
                "host.example.com",
                "z.example.com",
                &[A, AAAA, RRSIG_BIT, NSEC_BIT],
            );
            let rrsig = signer.sign(
                std::slice::from_ref(&nsec),
                NSEC_BIT,
                "host.example.com",
                "example.com",
            );
            let authority = vec![nsec, rrsig];
            let qname = Name::new_unchecked("host.example.com");
            assert!(matches!(
                prove_nodata(&qname, A, &authority, &signer.keys()),
                Err(DenialError::TypePresent { .. })
            ));
        }

        #[test]
        fn nodata_nsec_fails_closed_without_signature() {
            let signer = Signer::new();
            let nsec = nsec_rr(
                "host.example.com",
                "z.example.com",
                &[AAAA, RRSIG_BIT, NSEC_BIT],
            );
            // No RRSIG accompanies the NSEC, so nothing is validated.
            let authority = vec![nsec];
            let qname = Name::new_unchecked("host.example.com");
            assert!(matches!(
                prove_nodata(&qname, A, &authority, &signer.keys()),
                Err(DenialError::NoProof { .. })
            ));
        }

        #[test]
        fn nodata_nsec_fails_closed_under_wrong_key() {
            let signer = Signer::new();
            let stranger = Signer::new();
            let nsec = nsec_rr(
                "host.example.com",
                "z.example.com",
                &[AAAA, RRSIG_BIT, NSEC_BIT],
            );
            let rrsig = signer.sign(
                std::slice::from_ref(&nsec),
                NSEC_BIT,
                "host.example.com",
                "example.com",
            );
            let authority = vec![nsec, rrsig];
            let qname = Name::new_unchecked("host.example.com");
            // Validated against an unrelated zone's key, the NSEC does not verify.
            assert!(matches!(
                prove_nodata(&qname, A, &authority, &stranger.keys()),
                Err(DenialError::NoProof { .. })
            ));
        }

        #[test]
        fn nxdomain_nsec_covers_name_and_wildcard() {
            let signer = Signer::new();
            // One NSEC from the apex to z.example.com covers both nx.example.com
            // and the wildcard *.example.com.
            let nsec = nsec_rr(
                "example.com",
                "z.example.com",
                &[A, SOA, NS, RRSIG_BIT, NSEC_BIT],
            );
            let rrsig = signer.sign(
                std::slice::from_ref(&nsec),
                NSEC_BIT,
                "example.com",
                "example.com",
            );
            let authority = vec![nsec, rrsig];
            let qname = Name::new_unchecked("nx.example.com");
            assert!(prove_nxdomain(&qname, &authority, &signer.keys()).is_ok());
        }

        #[test]
        fn nxdomain_nsec_rejects_uncovered_name() {
            let signer = Signer::new();
            // The gap ends before nx.example.com, so it does not cover the name.
            let nsec = nsec_rr(
                "example.com",
                "a.example.com",
                &[A, SOA, NS, RRSIG_BIT, NSEC_BIT],
            );
            let rrsig = signer.sign(
                std::slice::from_ref(&nsec),
                NSEC_BIT,
                "example.com",
                "example.com",
            );
            let authority = vec![nsec, rrsig];
            let qname = Name::new_unchecked("nx.example.com");
            assert!(matches!(
                prove_nxdomain(&qname, &authority, &signer.keys()),
                Err(DenialError::NotCovered { .. })
            ));
        }

        #[test]
        fn no_ds_nsec_proves_insecure_delegation() {
            let parent = Signer::new();
            // The child has an NS record but no DS: an insecure delegation.
            let nsec = nsec_rr(
                "sub.example.com",
                "z.example.com",
                &[NS, RRSIG_BIT, NSEC_BIT],
            );
            let rrsig = parent.sign(
                std::slice::from_ref(&nsec),
                NSEC_BIT,
                "sub.example.com",
                "example.com",
            );
            let authority = vec![nsec, rrsig];
            let child = Name::new_unchecked("sub.example.com");
            assert!(prove_no_ds(&child, &authority, &parent.keys()).is_ok());
        }

        #[test]
        fn no_ds_nsec_rejects_present_ds() {
            let parent = Signer::new();
            // A DS bit means the delegation is signed, not insecure.
            let nsec = nsec_rr(
                "sub.example.com",
                "z.example.com",
                &[NS, DS, RRSIG_BIT, NSEC_BIT],
            );
            let rrsig = parent.sign(
                std::slice::from_ref(&nsec),
                NSEC_BIT,
                "sub.example.com",
                "example.com",
            );
            let authority = vec![nsec, rrsig];
            let child = Name::new_unchecked("sub.example.com");
            assert!(matches!(
                prove_no_ds(&child, &authority, &parent.keys()),
                Err(DenialError::SecureDelegation { .. })
            ));
        }

        #[test]
        fn wildcard_nsec_proves_no_closer_match() {
            let signer = Signer::new();
            // The answer came from *.example.com (2 labels). The next closer name
            // is host.example.com, which this NSEC covers.
            let nsec = nsec_rr(
                "example.com",
                "z.example.com",
                &[A, SOA, NS, RRSIG_BIT, NSEC_BIT],
            );
            let rrsig = signer.sign(
                std::slice::from_ref(&nsec),
                NSEC_BIT,
                "example.com",
                "example.com",
            );
            let authority = vec![nsec, rrsig];
            let qname = Name::new_unchecked("host.example.com");
            assert!(prove_wildcard(&qname, 2, &authority, &signer.keys()).is_ok());
        }

        #[test]
        fn wildcard_nsec_rejects_uncovered_next_closer() {
            let signer = Signer::new();
            // This NSEC does not cover host.example.com, so no closer-match proof.
            let nsec = nsec_rr("z.example.com", "zz.example.com", &[A, RRSIG_BIT, NSEC_BIT]);
            let rrsig = signer.sign(
                std::slice::from_ref(&nsec),
                NSEC_BIT,
                "z.example.com",
                "example.com",
            );
            let authority = vec![nsec, rrsig];
            let qname = Name::new_unchecked("host.example.com");
            assert!(matches!(
                prove_wildcard(&qname, 2, &authority, &signer.keys()),
                Err(DenialError::NoProof { .. })
            ));
        }

        #[test]
        fn nodata_nsec3_matches_hashed_owner() {
            let signer = Signer::new();
            let owner_hash = hash("a.example");
            let next = nsec3_hash(
                &Name::new_unchecked("z.example"),
                &[0xaa, 0xbb, 0xcc, 0xdd],
                12,
            );
            let nsec3 = nsec3_rr("example", &owner_hash, 0, &next, &[AAAA, RRSIG_BIT]);
            let owner = format!("{owner_hash}.example");
            let rrsig = signer.sign(
                std::slice::from_ref(&nsec3),
                NSEC3_TYPE_CODE,
                &owner,
                "example",
            );
            let authority = vec![nsec3, rrsig];
            let qname = Name::new_unchecked("a.example");
            assert!(prove_nodata(&qname, A, &authority, &signer.keys()).is_ok());
        }

        #[test]
        fn no_ds_nsec3_optout_proves_insecure_delegation() {
            let parent = Signer::new();
            let child = Name::new_unchecked("sub.example");
            let target = hash("sub.example");
            // An Opt-Out NSEC3 whose gap covers the child hash proves the child is
            // an unsigned delegation (RFC 5155 section 6). Bound the gap around it.
            let owner_hash = "0".repeat(target.len());
            let next = [0xffu8; 20];
            let nsec3 = nsec3_rr("example", &owner_hash, NSEC3_FLAG_OPT_OUT, &next, &[NS]);
            let owner = format!("{owner_hash}.example");
            let rrsig = parent.sign(
                std::slice::from_ref(&nsec3),
                NSEC3_TYPE_CODE,
                &owner,
                "example",
            );
            let authority = vec![nsec3, rrsig];
            assert!(target.as_str() > owner_hash.as_str());
            assert!(prove_no_ds(&child, &authority, &parent.keys()).is_ok());
        }

        #[test]
        fn nxdomain_nsec3_closest_encloser_proof() {
            let signer = Signer::new();
            // Prove x.a.example does not exist: a.example is the closest encloser,
            // x.a.example is the next closer, and *.a.example is the wildcard.
            let all_high = [0xffu8; 20];
            let low = "0".repeat(32);

            // Matches the closest encloser a.example.
            let encloser_hash = hash("a.example");
            let matcher = nsec3_rr("example", &encloser_hash, 0, &all_high, &[A, NS]);
            let matcher_owner = format!("{encloser_hash}.example");
            let matcher_sig = signer.sign(
                std::slice::from_ref(&matcher),
                NSEC3_TYPE_CODE,
                &matcher_owner,
                "example",
            );

            // A wide gap that covers both the next closer and the wildcard hashes.
            let cover = nsec3_rr("example", &low, 0, &all_high, &[]);
            let cover_owner = format!("{low}.example");
            let cover_sig = signer.sign(
                std::slice::from_ref(&cover),
                NSEC3_TYPE_CODE,
                &cover_owner,
                "example",
            );

            let authority = vec![matcher, matcher_sig, cover, cover_sig];
            let qname = Name::new_unchecked("x.a.example");
            assert!(prove_nxdomain(&qname, &authority, &signer.keys()).is_ok());
        }

        #[test]
        fn nsec3_iteration_cap_is_enforced() {
            // A record above the iteration cap is skipped, so no proof survives.
            let signer = Signer::new();
            let mut rdata = nsec3_rdata(0, &[0u8; 20], &[AAAA]);
            // Overwrite the iteration field (bytes 2..4) with a value above the cap.
            rdata[2..4].copy_from_slice(&(MAX_NSEC3_ITERATIONS + 1).to_be_bytes());
            let owner = format!("{}.example", hash("a.example"));
            let record = ResourceRecord::new(
                Name::new_unchecked(&owner).into_owned(),
                CLASS::IN,
                3600,
                RData::NULL(
                    NSEC3_TYPE_CODE,
                    simple_dns::rdata::NULL::new(&rdata).unwrap().into_owned(),
                ),
            );
            let rrsig = signer.sign(
                std::slice::from_ref(&record),
                NSEC3_TYPE_CODE,
                &owner,
                "example",
            );
            let authority = vec![record, rrsig];
            let qname = Name::new_unchecked("a.example");
            assert!(prove_nodata(&qname, A, &authority, &signer.keys()).is_err());
        }

        #[test]
        fn nsec3_hash_folds_case() {
            // The hash is over the lowercased wire form, so an uppercase name
            // hashes to the same value as its lowercase form (RFC 5155 section 5).
            assert_eq!(hash("EXAMPLE"), hash("example"));
            assert_eq!(hash("EXAMPLE"), "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom");
        }

        #[test]
        fn canonical_name_cmp_matches_rfc4034_example() {
            // The canonical ordering example from RFC 4034 section 6.1, ascending.
            // It exercises right-to-left label comparison, case folding, the
            // length tie-break, and labels with non-printable octets.
            let ordered = [
                octet_name(&[b"example"]),
                octet_name(&[b"a", b"example"]),
                octet_name(&[b"yljkjljk", b"a", b"example"]),
                octet_name(&[b"Z", b"a", b"example"]),
                octet_name(&[b"zABC", b"a", b"EXAMPLE"]),
                octet_name(&[b"z", b"example"]),
                octet_name(&[&[0x01], b"z", b"example"]),
                octet_name(&[b"*", b"z", b"example"]),
                octet_name(&[&[0x80], b"z", b"example"]),
            ];
            for (i, pair) in ordered.windows(2).enumerate() {
                assert_eq!(
                    canonical_name_cmp(&pair[0], &pair[1]),
                    Ordering::Less,
                    "names {i} and {} are out of canonical order",
                    i + 1
                );
            }
            // Case folding makes names differing only in case compare equal.
            assert_eq!(
                canonical_name_cmp(
                    &octet_name(&[b"Z", b"a", b"example"]),
                    &octet_name(&[b"z", b"a", b"example"]),
                ),
                Ordering::Equal
            );
        }

        #[test]
        fn nsec3_parse_rejects_truncated_rdata() {
            // Salt length runs past the end of the RDATA.
            let mut rdata = vec![1u8, 0, 0, 12, 8];
            rdata.extend_from_slice(&[0xaa, 0xbb]);
            assert!(Nsec3::parse(&rdata).is_none());

            // Hash length runs past the end.
            let mut rdata = vec![1u8, 0, 0, 12, 0, 20];
            rdata.extend_from_slice(&[0u8; 4]);
            assert!(Nsec3::parse(&rdata).is_none());

            // A bitmap window length runs past the end.
            let mut rdata = vec![1u8, 0, 0, 12, 0, 4];
            rdata.extend_from_slice(&[0u8; 4]);
            rdata.extend_from_slice(&[0, 10, 0, 0]);
            assert!(Nsec3::parse(&rdata).is_none());

            // An empty RDATA has no hash-algorithm byte.
            assert!(Nsec3::parse(&[]).is_none());
        }

        #[test]
        fn nsec_short_window_reports_absent_without_panic() {
            // A window block above 32 with a one-byte bitmap must not over-read: a
            // type whose byte index lies past the bitmap is reported absent.
            let nsec = NSEC {
                next_name: Name::new_unchecked("z.example.com").into_owned(),
                type_bit_maps: vec![NsecTypeBitMap {
                    window_block: 40,
                    bitmap: Cow::Owned(vec![0x01]),
                }],
            };
            // A type in a window that is not listed at all is absent.
            assert!(!nsec_type_present(&nsec, A));
            // A type in the short window whose byte index is past the bitmap.
            assert!(!nsec_type_present(&nsec, 40 * 256 + 255));
        }

        #[test]
        fn nsec3_reserved_flag_bits_rejected() {
            // Only the Opt-Out flag (0x01) is defined; a record setting any other
            // flag bit is dropped, so it cannot contribute to a proof (finding S4).
            let signer = Signer::new();
            let owner_hash = hash("a.example");
            let next = nsec3_hash(
                &Name::new_unchecked("z.example"),
                &[0xaa, 0xbb, 0xcc, 0xdd],
                12,
            );
            let nsec3 = nsec3_rr("example", &owner_hash, 0x02, &next, &[AAAA, RRSIG_BIT]);
            let owner = format!("{owner_hash}.example");
            let rrsig = signer.sign(
                std::slice::from_ref(&nsec3),
                NSEC3_TYPE_CODE,
                &owner,
                "example",
            );
            let authority = vec![nsec3, rrsig];
            let qname = Name::new_unchecked("a.example");
            assert!(matches!(
                prove_nodata(&qname, A, &authority, &signer.keys()),
                Err(DenialError::NoProof { .. })
            ));
        }

        #[test]
        fn nsec3_mismatched_salt_dropped() {
            // Every NSEC3 in a response must share the salt (RFC 5155 section 8.2).
            // A signed record under a different salt that would otherwise match the
            // queried name is dropped, so the NODATA is not proven (finding S1).
            let signer = Signer::new();
            let salt_reference = [0xaa, 0xbb, 0xcc, 0xdd];
            let salt_other = [0x11, 0x22, 0x33, 0x44];

            // The first validated record fixes the salt to aabbccdd and matches
            // nothing relevant.
            let reference_hash = base32hex_encode(&nsec3_hash(
                &Name::new_unchecked("other.example"),
                &salt_reference,
                12,
            ));
            let reference_rdata =
                nsec3_rdata_params(&salt_reference, 12, 0, &[0xff; 20], &[AAAA, RRSIG_BIT]);
            let reference_owner = format!("{reference_hash}.example");
            let reference_rr = ResourceRecord::new(
                Name::new_unchecked(&reference_owner).into_owned(),
                CLASS::IN,
                3600,
                RData::NULL(
                    NSEC3_TYPE_CODE,
                    simple_dns::rdata::NULL::new(&reference_rdata)
                        .unwrap()
                        .into_owned(),
                ),
            );
            let reference_sig = signer.sign(
                std::slice::from_ref(&reference_rr),
                NSEC3_TYPE_CODE,
                &reference_owner,
                "example",
            );

            // A record under a different salt that hashes to match a.example. It is
            // dropped for the salt mismatch, so no record matches the queried name.
            let match_hash = base32hex_encode(&nsec3_hash(
                &Name::new_unchecked("a.example"),
                &salt_other,
                12,
            ));
            let match_rdata =
                nsec3_rdata_params(&salt_other, 12, 0, &[0xff; 20], &[AAAA, RRSIG_BIT]);
            let match_owner = format!("{match_hash}.example");
            let match_rr = ResourceRecord::new(
                Name::new_unchecked(&match_owner).into_owned(),
                CLASS::IN,
                3600,
                RData::NULL(
                    NSEC3_TYPE_CODE,
                    simple_dns::rdata::NULL::new(&match_rdata)
                        .unwrap()
                        .into_owned(),
                ),
            );
            let match_sig = signer.sign(
                std::slice::from_ref(&match_rr),
                NSEC3_TYPE_CODE,
                &match_owner,
                "example",
            );

            let authority = vec![reference_rr, reference_sig, match_rr, match_sig];
            let qname = Name::new_unchecked("a.example");
            assert!(matches!(
                prove_nodata(&qname, A, &authority, &signer.keys()),
                Err(DenialError::NoProof { .. })
            ));
        }

        /// A bogus NSEC3 record with an RRSIG whose key tag and algorithm match
        /// `signer` but whose signature is invalid, so it forces a failed
        /// signature check but never validates. Used to pad the authority section.
        fn bogus_nsec3(signer: &Signer, owner_hash: &str) -> Vec<ResourceRecord<'static>> {
            let nsec3 = nsec3_rr("example", owner_hash, 0, &[0xffu8; 20], &[AAAA]);
            let owner = format!("{owner_hash}.example");
            let rrsig = RRSIG {
                type_covered: NSEC3_TYPE_CODE,
                algorithm: 13,
                labels: label_count(&owner),
                original_ttl: 3600,
                signature_expiration: now() + 3600,
                signature_inception: now() - 3600,
                key_tag: key_tag(&signer.dnskey),
                signer_name: Name::new_unchecked("example").into_owned(),
                signature: Cow::Owned(vec![0u8; 64]),
            };
            let sig = ResourceRecord::new(
                Name::new_unchecked(&owner).into_owned(),
                CLASS::IN,
                3600,
                RData::RRSIG(rrsig),
            );
            vec![nsec3, sig]
        }

        /// A genuinely signed NSEC3 that matches `a.example` and proves NODATA.
        fn signed_nodata_nsec3(signer: &Signer) -> Vec<ResourceRecord<'static>> {
            let owner_hash = hash("a.example");
            let next = nsec3_hash(
                &Name::new_unchecked("z.example"),
                &[0xaa, 0xbb, 0xcc, 0xdd],
                12,
            );
            let nsec3 = nsec3_rr("example", &owner_hash, 0, &next, &[AAAA, RRSIG_BIT]);
            let owner = format!("{owner_hash}.example");
            let rrsig = signer.sign(
                std::slice::from_ref(&nsec3),
                NSEC3_TYPE_CODE,
                &owner,
                "example",
            );
            vec![nsec3, rrsig]
        }

        #[test]
        fn nsec3_denial_record_cap_bounds_processing() {
            // Pad the authority section with more than the cap's worth of NSEC3
            // records, each carrying a tag- and algorithm-matching but bogus
            // RRSIG, then append a genuinely signed record that would prove the
            // NODATA. The cap stops before the real record is reached, so the
            // denial stays unproven (fail-closed) rather than driving unbounded
            // signature checks (finding H3).
            let signer = Signer::new();
            let mut authority = Vec::new();
            for i in 0..(MAX_DENIAL_RECORDS + 4) {
                authority.extend(bogus_nsec3(&signer, &format!("{i:032}")));
            }
            authority.extend(signed_nodata_nsec3(&signer));

            let qname = Name::new_unchecked("a.example");
            assert!(matches!(
                prove_nodata(&qname, A, &authority, &signer.keys()),
                Err(DenialError::NoProof { .. })
            ));
        }

        #[test]
        fn nsec3_denial_proof_survives_small_padding() {
            // A few pad records ahead of the real record stay within the cap, so a
            // legitimate proof still passes: the generous bound does not affect a
            // real denial (finding H3).
            let signer = Signer::new();
            let mut authority = Vec::new();
            for i in 0..3 {
                authority.extend(bogus_nsec3(&signer, &format!("{i:032}")));
            }
            authority.extend(signed_nodata_nsec3(&signer));

            let qname = Name::new_unchecked("a.example");
            assert!(prove_nodata(&qname, A, &authority, &signer.keys()).is_ok());
        }
    }

    // Fixed RSA-2048 PKCS#8 DER private key, generated once for this test.
    const RSA_PKCS8_DER: &[u8] = &[
        48, 130, 4, 189, 2, 1, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 4, 130,
        4, 167, 48, 130, 4, 163, 2, 1, 0, 2, 130, 1, 1, 0, 212, 200, 210, 240, 157, 150, 66, 159,
        158, 101, 64, 153, 240, 59, 130, 74, 212, 205, 101, 221, 87, 6, 237, 199, 145, 83, 9, 250,
        56, 29, 179, 248, 75, 253, 218, 50, 21, 128, 237, 246, 204, 37, 107, 16, 76, 128, 165, 174,
        28, 152, 151, 114, 195, 115, 8, 42, 29, 227, 106, 99, 241, 33, 208, 48, 182, 34, 27, 167,
        186, 3, 171, 168, 88, 105, 158, 169, 136, 234, 23, 121, 240, 59, 94, 245, 7, 76, 141, 1,
        248, 10, 128, 200, 84, 177, 202, 85, 57, 173, 202, 147, 245, 72, 135, 112, 157, 8, 205,
        130, 90, 52, 174, 196, 35, 81, 183, 194, 122, 35, 198, 120, 52, 52, 135, 58, 63, 214, 233,
        18, 186, 220, 19, 57, 75, 122, 40, 47, 206, 45, 99, 38, 136, 100, 42, 106, 206, 141, 47,
        133, 7, 253, 118, 128, 240, 92, 248, 215, 30, 235, 120, 249, 194, 241, 109, 233, 217, 250,
        79, 118, 0, 69, 196, 246, 244, 163, 251, 2, 116, 94, 44, 50, 123, 194, 96, 90, 190, 16, 33,
        209, 243, 164, 150, 125, 231, 244, 179, 0, 81, 165, 150, 176, 131, 80, 50, 142, 237, 185,
        227, 254, 126, 147, 174, 64, 142, 216, 166, 244, 37, 224, 237, 1, 46, 170, 147, 75, 81,
        135, 63, 23, 190, 9, 198, 253, 94, 248, 200, 204, 10, 126, 167, 114, 254, 94, 228, 191, 12,
        94, 98, 89, 72, 226, 211, 4, 74, 47, 50, 23, 2, 3, 1, 0, 1, 2, 130, 1, 0, 8, 32, 40, 120,
        170, 118, 147, 210, 17, 243, 190, 143, 205, 3, 99, 106, 90, 206, 2, 129, 210, 167, 159,
        191, 149, 230, 113, 228, 109, 152, 42, 29, 229, 62, 85, 194, 193, 50, 33, 228, 54, 207,
        134, 253, 204, 88, 194, 165, 154, 36, 158, 238, 156, 85, 113, 142, 95, 131, 38, 96, 237,
        83, 14, 145, 141, 162, 253, 35, 94, 144, 114, 167, 4, 110, 164, 28, 114, 154, 8, 142, 35,
        133, 11, 143, 66, 132, 24, 131, 188, 17, 31, 241, 219, 212, 200, 235, 229, 147, 249, 105,
        197, 8, 33, 89, 68, 229, 231, 211, 41, 44, 7, 48, 126, 67, 116, 156, 252, 154, 99, 205,
        219, 80, 128, 222, 209, 233, 71, 15, 218, 54, 112, 97, 156, 218, 245, 214, 98, 131, 109,
        134, 199, 12, 98, 98, 71, 204, 244, 68, 193, 43, 151, 104, 243, 45, 80, 242, 52, 16, 3,
        197, 158, 70, 66, 106, 164, 71, 1, 19, 0, 242, 108, 170, 255, 140, 94, 201, 216, 81, 42,
        34, 105, 97, 127, 64, 181, 166, 68, 200, 89, 99, 7, 27, 78, 61, 146, 129, 63, 146, 138, 57,
        160, 204, 143, 183, 172, 116, 72, 136, 36, 45, 205, 150, 92, 83, 153, 120, 142, 41, 109,
        51, 103, 201, 188, 48, 192, 120, 252, 195, 255, 152, 16, 161, 158, 103, 203, 245, 213, 158,
        85, 38, 140, 140, 15, 145, 86, 86, 225, 152, 91, 15, 246, 146, 61, 148, 193, 97, 2, 129,
        129, 0, 238, 156, 80, 13, 150, 181, 172, 232, 145, 103, 82, 241, 96, 200, 255, 223, 224,
        199, 151, 105, 67, 175, 15, 137, 250, 18, 219, 69, 224, 154, 158, 231, 204, 5, 14, 173, 94,
        45, 64, 136, 115, 78, 168, 189, 178, 109, 192, 2, 8, 73, 132, 214, 74, 35, 109, 183, 158,
        91, 114, 62, 143, 77, 141, 49, 188, 18, 94, 35, 25, 174, 43, 110, 181, 133, 13, 198, 232,
        121, 77, 177, 10, 60, 108, 231, 65, 226, 171, 105, 1, 157, 210, 109, 249, 66, 29, 96, 20,
        200, 160, 220, 137, 198, 252, 99, 15, 32, 40, 190, 94, 161, 110, 159, 179, 200, 75, 65,
        165, 139, 178, 86, 133, 243, 188, 152, 230, 204, 149, 101, 2, 129, 129, 0, 228, 74, 174,
        76, 80, 13, 253, 239, 198, 226, 179, 95, 235, 244, 55, 162, 216, 146, 217, 207, 27, 38, 97,
        151, 22, 237, 91, 242, 28, 172, 133, 122, 163, 49, 150, 27, 191, 106, 219, 112, 210, 96,
        130, 94, 120, 108, 35, 46, 17, 54, 23, 61, 212, 52, 93, 52, 3, 8, 80, 202, 139, 35, 75,
        122, 208, 141, 3, 73, 215, 248, 153, 86, 197, 98, 227, 249, 26, 66, 171, 32, 95, 175, 11,
        117, 121, 57, 9, 182, 71, 28, 111, 82, 187, 127, 61, 86, 24, 248, 46, 249, 109, 172, 120,
        13, 98, 168, 200, 170, 160, 239, 159, 181, 63, 174, 221, 103, 133, 89, 253, 177, 139, 30,
        98, 41, 127, 79, 159, 203, 2, 129, 129, 0, 157, 77, 149, 132, 239, 215, 67, 111, 106, 244,
        71, 252, 243, 70, 111, 81, 99, 121, 145, 123, 6, 240, 240, 248, 144, 81, 64, 23, 88, 19,
        247, 48, 111, 18, 226, 115, 46, 195, 252, 104, 56, 68, 34, 0, 53, 18, 31, 99, 247, 156,
        168, 35, 49, 107, 27, 216, 210, 96, 12, 247, 235, 55, 64, 31, 10, 146, 189, 86, 188, 134,
        83, 1, 192, 79, 64, 30, 226, 129, 157, 211, 90, 33, 45, 214, 99, 92, 16, 142, 192, 79, 16,
        60, 9, 248, 41, 47, 127, 100, 40, 144, 91, 144, 64, 48, 249, 246, 196, 133, 132, 19, 62,
        191, 176, 33, 26, 99, 227, 196, 45, 196, 214, 184, 49, 156, 71, 131, 149, 245, 2, 129, 128,
        33, 48, 154, 86, 141, 236, 250, 214, 57, 92, 12, 40, 13, 237, 219, 136, 217, 99, 192, 54,
        212, 3, 168, 124, 134, 224, 203, 85, 79, 197, 229, 66, 7, 39, 214, 99, 2, 89, 78, 190, 0,
        87, 247, 156, 52, 117, 196, 71, 150, 72, 254, 232, 6, 73, 246, 162, 241, 45, 236, 81, 6,
        25, 131, 135, 191, 122, 64, 216, 35, 134, 9, 5, 12, 125, 108, 23, 115, 49, 238, 31, 46,
        202, 12, 40, 112, 15, 82, 210, 37, 84, 132, 250, 202, 55, 157, 123, 62, 246, 22, 30, 61,
        75, 173, 200, 132, 103, 117, 133, 25, 16, 189, 111, 100, 106, 207, 213, 149, 21, 152, 68,
        143, 173, 67, 40, 53, 82, 38, 49, 2, 129, 128, 38, 120, 29, 182, 170, 56, 36, 191, 170, 22,
        80, 49, 32, 3, 156, 29, 203, 108, 10, 98, 80, 221, 115, 189, 178, 251, 94, 203, 210, 216,
        186, 119, 109, 0, 32, 154, 225, 208, 101, 197, 216, 172, 185, 179, 150, 139, 48, 216, 207,
        203, 116, 255, 221, 19, 194, 1, 216, 22, 13, 88, 48, 226, 37, 124, 31, 149, 246, 70, 33,
        76, 235, 216, 253, 121, 36, 53, 6, 209, 187, 141, 218, 148, 64, 222, 42, 85, 18, 254, 174,
        74, 19, 134, 251, 174, 49, 169, 230, 106, 95, 233, 195, 211, 128, 134, 121, 145, 113, 19,
        241, 62, 155, 197, 207, 133, 207, 81, 187, 64, 110, 168, 13, 81, 22, 50, 228, 212, 80, 214,
    ];

    // Fixed RSA-2048 test key material, extracted from a generated PKCS#8 key.
    const RSA_EXPONENT: &[u8] = &[1, 0, 1];
    const RSA_MODULUS: &[u8] = &[
        212, 200, 210, 240, 157, 150, 66, 159, 158, 101, 64, 153, 240, 59, 130, 74, 212, 205, 101,
        221, 87, 6, 237, 199, 145, 83, 9, 250, 56, 29, 179, 248, 75, 253, 218, 50, 21, 128, 237,
        246, 204, 37, 107, 16, 76, 128, 165, 174, 28, 152, 151, 114, 195, 115, 8, 42, 29, 227, 106,
        99, 241, 33, 208, 48, 182, 34, 27, 167, 186, 3, 171, 168, 88, 105, 158, 169, 136, 234, 23,
        121, 240, 59, 94, 245, 7, 76, 141, 1, 248, 10, 128, 200, 84, 177, 202, 85, 57, 173, 202,
        147, 245, 72, 135, 112, 157, 8, 205, 130, 90, 52, 174, 196, 35, 81, 183, 194, 122, 35, 198,
        120, 52, 52, 135, 58, 63, 214, 233, 18, 186, 220, 19, 57, 75, 122, 40, 47, 206, 45, 99, 38,
        136, 100, 42, 106, 206, 141, 47, 133, 7, 253, 118, 128, 240, 92, 248, 215, 30, 235, 120,
        249, 194, 241, 109, 233, 217, 250, 79, 118, 0, 69, 196, 246, 244, 163, 251, 2, 116, 94, 44,
        50, 123, 194, 96, 90, 190, 16, 33, 209, 243, 164, 150, 125, 231, 244, 179, 0, 81, 165, 150,
        176, 131, 80, 50, 142, 237, 185, 227, 254, 126, 147, 174, 64, 142, 216, 166, 244, 37, 224,
        237, 1, 46, 170, 147, 75, 81, 135, 63, 23, 190, 9, 198, 253, 94, 248, 200, 204, 10, 126,
        167, 114, 254, 94, 228, 191, 12, 94, 98, 89, 72, 226, 211, 4, 74, 47, 50, 23,
    ];
}
