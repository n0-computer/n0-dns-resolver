//! Additional DNSSEC known-answer and proof tests for the public toolkit.
//!
//! These tests complement the unit tests inside `src/dnssec.rs`. They call only
//! the public API ([`verify_ds`], [`key_tag`], [`verify_rrsig`],
//! [`verify_chain_with_anchors`], [`verify_chain_with_trust_anchors`],
//! [`prove_nodata`], [`prove_nxdomain`]), so the canonical signing that the
//! private helpers perform internally is reconstructed here independently. A
//! signature that validates therefore cross-checks this reimplementation against
//! the crate's own, and the published vectors (the root KSK-2017 DS and the RFC
//! 5155 Appendix B NSEC3 hashes) pin the behavior to external ground truth.
//!
//! Each test names its source: an RFC section, the IANA root-anchors file, or the
//! deliberate departure from an RFC example that the crate's hardening requires.

use std::{
    borrow::Cow,
    time::{SystemTime, UNIX_EPOCH},
};

use ring::{
    digest,
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use simple_dns::{
    CLASS, Name, ResourceRecord,
    rdata::{A, DNSKEY, DS, NSEC, NULL, NsecTypeBitMap, RData, RRSIG},
};

use crate::dnssec::{
    ChainError, ChainOfTrust, DelegatedZone, DenialError, DnssecError, ROOT_TRUST_ANCHORS,
    SignedRrset, TrustAnchor, key_tag, prove_nodata, prove_nxdomain, verify_chain_with_anchors,
    verify_chain_with_trust_anchors, verify_ds, verify_rrsig,
};

// Type codes used in NSEC and NSEC3 bit maps (RFC 1035, RFC 4034, RFC 5155).
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_SOA: u16 = 6;
const TYPE_MX: u16 = 15;
const TYPE_DS: u16 = 43;
const TYPE_RRSIG: u16 = 46;
const TYPE_NSEC: u16 = 47;
const TYPE_DNSKEY: u16 = 48;
const TYPE_NSEC3PARAM: u16 = 51;

/// The NSEC3 Opt-Out flag (RFC 5155 section 3.1.2.1).
const NSEC3_FLAG_OPT_OUT: u8 = 0x01;

/// The RFC 5155 Appendix B example salt (`aabbccdd`) and iteration count (12).
const RFC5155_SALT: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd];
const RFC5155_ITERATIONS: u16 = 12;

// ============================================================================
// Canonical-form helpers, reconstructed from RFC 4034 for the signing side.
// ============================================================================

/// Current Unix time in seconds, truncated to the RRSIG 32-bit field.
fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Counts the labels in a presentation-form name, treating `""` as the root.
fn label_count(name: &str) -> u8 {
    name.split('.').filter(|label| !label.is_empty()).count() as u8
}

/// Encodes a sequence of labels into canonical wire form (RFC 4034 section 6.1).
fn encode_labels<'a>(labels: impl Iterator<Item = &'a [u8]>, downcase: bool) -> Vec<u8> {
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

/// Canonical wire form of a presentation-form name, always downcased.
fn wire_name(name: &str) -> Vec<u8> {
    let name = Name::new_unchecked(name);
    encode_labels(name.as_bytes(), true)
}

/// Canonical DNSKEY RDATA (flags, protocol, algorithm, public key).
fn dnskey_rdata(dnskey: &DNSKEY<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + dnskey.public_key.len());
    out.extend_from_slice(&dnskey.flags.to_be_bytes());
    out.push(dnskey.protocol);
    out.push(dnskey.algorithm);
    out.extend_from_slice(&dnskey.public_key);
    out
}

/// Canonical DS RDATA (key tag, algorithm, digest type, digest).
fn ds_rdata(ds: &DS<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ds.digest.len());
    out.extend_from_slice(&ds.key_tag.to_be_bytes());
    out.push(ds.algorithm);
    out.push(ds.digest_type);
    out.extend_from_slice(&ds.digest);
    out
}

/// Canonical NSEC RDATA: the next owner name (not downcased, RFC 6840 section
/// 5.1) followed by the type bit map windows in ascending order.
fn nsec_rdata(nsec: &NSEC<'_>) -> Vec<u8> {
    let mut out = encode_labels(nsec.next_name.as_bytes(), false);
    let mut windows: Vec<&NsecTypeBitMap<'_>> = nsec.type_bit_maps.iter().collect();
    windows.sort_by_key(|window| window.window_block);
    for window in windows {
        out.push(window.window_block);
        out.push(window.bitmap.len() as u8);
        out.extend_from_slice(&window.bitmap);
    }
    out
}

/// Canonical RDATA for the record types these tests sign.
fn canonical_rdata(rdata: &RData<'_>) -> Vec<u8> {
    match rdata {
        RData::A(a) => a.address.to_be_bytes().to_vec(),
        RData::DNSKEY(dnskey) => dnskey_rdata(dnskey),
        RData::DS(ds) => ds_rdata(ds),
        RData::NSEC(nsec) => nsec_rdata(nsec),
        // NSEC3 (type 50) arrives as an unknown record whose raw RDATA is already
        // canonical.
        RData::NULL(50, null) => null.get_data().to_vec(),
        other => panic!("unsupported test RDATA: {}", u16::from(other.type_code())),
    }
}

/// Reconstructs the signed data for an RRSIG over an RRset (RFC 4035 section
/// 5.3.2, RFC 4034 sections 6.2 and 6.3).
///
/// This mirrors the crate's private `signed_data`. The RRsets these tests build
/// are consistent and never wildcard-expanded, so the owner is used as is.
fn signed_data(rrsig: &RRSIG<'_>, rrset: &[ResourceRecord<'_>]) -> Vec<u8> {
    let first = &rrset[0];
    let owner_wire = encode_labels(first.name.as_bytes(), true);

    let mut signed = Vec::new();
    signed.extend_from_slice(&rrsig.type_covered.to_be_bytes());
    signed.push(rrsig.algorithm);
    signed.push(rrsig.labels);
    signed.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
    signed.extend_from_slice(&rrsig.signature_expiration.to_be_bytes());
    signed.extend_from_slice(&rrsig.signature_inception.to_be_bytes());
    signed.extend_from_slice(&rrsig.key_tag.to_be_bytes());
    signed.extend_from_slice(&encode_labels(rrsig.signer_name.as_bytes(), true));

    let mut rdatas: Vec<Vec<u8>> = rrset.iter().map(|rr| canonical_rdata(&rr.rdata)).collect();
    rdatas.sort_unstable();
    rdatas.dedup();

    let class = first.class as u16;
    for rdata in rdatas {
        signed.extend_from_slice(&owner_wire);
        signed.extend_from_slice(&rrsig.type_covered.to_be_bytes());
        signed.extend_from_slice(&class.to_be_bytes());
        signed.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        signed.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        signed.extend_from_slice(&rdata);
    }
    signed
}

/// A single-key ECDSA P-256 (algorithm 13) zone that can sign RRsets and emit a
/// DS record over its own key.
struct TestKey {
    key_pair: EcdsaKeyPair,
    dnskey: DNSKEY<'static>,
    tag: u16,
    rng: SystemRandom,
}

impl TestKey {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        // The DNSKEY carries the 64-byte curve point x || y; ring returns the
        // uncompressed SEC1 point 0x04 || x || y (RFC 6605).
        let public_key = key_pair.public_key().as_ref()[1..].to_vec();
        // Flags 257: zone key plus secure entry point.
        let dnskey = DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: Cow::Owned(public_key),
        };
        let tag = key_tag(&dnskey);
        Self {
            key_pair,
            dnskey,
            tag,
            rng,
        }
    }

    fn keys(&self) -> Vec<DNSKEY<'static>> {
        vec![self.dnskey.clone()]
    }

    /// Signs `records` and returns the bare RRSIG.
    fn sign(
        &self,
        records: &[ResourceRecord<'static>],
        type_covered: u16,
        owner: &str,
        signer: &str,
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
            signer_name: Name::new_unchecked(signer).into_owned(),
            signature: Cow::Owned(Vec::new()),
        };
        let signed = signed_data(&rrsig, records);
        let signature = self.key_pair.sign(&self.rng, &signed).unwrap();
        rrsig.signature = Cow::Owned(signature.as_ref().to_vec());
        rrsig
    }

    /// Signs `records` and returns the RRSIG wrapped as a resource record, the
    /// form the denial proofs read from an authority section.
    fn sign_rr(
        &self,
        records: &[ResourceRecord<'static>],
        type_covered: u16,
        owner: &str,
        signer: &str,
    ) -> ResourceRecord<'static> {
        let rrsig = self.sign(records, type_covered, owner, signer);
        ResourceRecord::new(
            Name::new_unchecked(owner).into_owned(),
            CLASS::IN,
            3600,
            RData::RRSIG(rrsig),
        )
    }

    /// The self-signed DNSKEY RRset for the zone named `owner`.
    fn signed_dnskeys(&self, owner: &str) -> SignedRrset<'static> {
        let records = vec![ResourceRecord::new(
            Name::new_unchecked(owner).into_owned(),
            CLASS::IN,
            3600,
            RData::DNSKEY(self.dnskey.clone()),
        )];
        let rrsig = self.sign(&records, TYPE_DNSKEY, owner, owner);
        SignedRrset {
            records,
            rrsigs: vec![rrsig],
        }
    }

    /// A SHA-256 DS record (digest type 2) over this key, owned by `owner`.
    fn ds(&self, owner: &str) -> DS<'static> {
        let mut data = wire_name(owner);
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

/// Decodes an unpadded lowercase base32hex string into bytes (RFC 4648 section 7).
///
/// The RFC 5155 records publish their next hashed owner name in this encoding, so
/// decoding recovers the raw hash bytes for the NSEC3 RDATA.
fn base32hex_decode(input: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuv";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for byte in input.bytes() {
        let value = ALPHABET
            .iter()
            .position(|&c| c == byte)
            .expect("base32hex digit") as u32;
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// Decodes a standard base64 string into bytes (RFC 4648 section 4).
///
/// Used to recover the raw public key of the published root KSK from its DNSKEY
/// presentation form.
fn base64_decode(input: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for byte in input.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let value = ALPHABET
            .iter()
            .position(|&c| c == byte)
            .expect("base64 digit") as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// Builds a single-window (types below 256) NSEC/NSEC3 type bit map.
fn bitmap(types: &[u16]) -> Vec<u8> {
    let max = types.iter().copied().max().unwrap_or(0) as usize;
    let mut bytes = vec![0u8; max / 8 + 1];
    for &type_code in types {
        let offset = (type_code & 0xff) as usize;
        bytes[offset / 8] |= 1 << (7 - (offset % 8));
    }
    bytes
}

/// An NSEC resource record for `owner` pointing at `next` and listing `types`.
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

/// Raw NSEC3 RDATA (RFC 5155 section 3.2). An empty `types` emits no type bit map
/// window, as an empty non-terminal's NSEC3 does.
fn nsec3_rdata(flags: u8, next_hash: &[u8], types: &[u16]) -> Vec<u8> {
    let mut out = vec![1u8, flags];
    out.extend_from_slice(&RFC5155_ITERATIONS.to_be_bytes());
    out.push(RFC5155_SALT.len() as u8);
    out.extend_from_slice(RFC5155_SALT);
    out.push(next_hash.len() as u8);
    out.extend_from_slice(next_hash);
    if !types.is_empty() {
        let bits = bitmap(types);
        out.push(0);
        out.push(bits.len() as u8);
        out.extend_from_slice(&bits);
    }
    out
}

/// An NSEC3 resource record whose owner is `owner_hash.example`, with the next
/// hashed owner given as a base32hex string that is decoded to raw bytes.
fn nsec3_rr(
    owner_hash: &str,
    flags: u8,
    next_hash: &str,
    types: &[u16],
) -> ResourceRecord<'static> {
    let owner = format!("{owner_hash}.example");
    let rdata = nsec3_rdata(flags, &base32hex_decode(next_hash), types);
    ResourceRecord::new(
        Name::new_unchecked(&owner).into_owned(),
        CLASS::IN,
        3600,
        RData::NULL(50, NULL::new(&rdata).unwrap().into_owned()),
    )
}

// ============================================================================
// Published DS / key-tag vector: the root KSK-2017 trust anchor.
// ============================================================================

/// The root zone KSK-2017 public key (key tag 20326), from its published DNSKEY
/// presentation form. See <https://data.iana.org/root-anchors/root-anchors.xml>
/// for the matching DS digest.
const ROOT_KSK_2017_BASE64: &str = concat!(
    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3",
    "+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv",
    "ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF",
    "0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e",
    "oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd",
    "RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN",
    "R1AkUTV74bU=",
);

/// The root KSK-2017 hashes to the published DS and computes the published key
/// tag.
///
/// The DNSKEY public key is the real published KSK-2017. Its key tag must be
/// 20326 (RFC 4034 appendix B), and [`verify_ds`] against the first embedded
/// [`ROOT_TRUST_ANCHORS`] entry must succeed, since that anchor is the SHA-256 DS
/// over this exact key (RFC 4509, IANA root-anchors.xml).
#[test]
fn root_ksk_2017_matches_published_ds_and_key_tag() {
    let dnskey = DNSKEY {
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: Cow::Owned(base64_decode(ROOT_KSK_2017_BASE64)),
    };
    assert_eq!(key_tag(&dnskey), 20326);

    // The root owner name is the empty label, whose canonical wire form is a
    // single zero octet.
    let root = Name::new_unchecked("");
    let anchor_2017 = &ROOT_TRUST_ANCHORS[0];
    assert_eq!(anchor_2017.key_tag, 20326);
    assert!(verify_ds(&root, &dnskey, anchor_2017).is_ok());

    // The KSK-2024 anchor (key tag 38696) does not match this key.
    let anchor_2024 = &ROOT_TRUST_ANCHORS[1];
    assert!(verify_ds(&root, &dnskey, anchor_2024).is_err());

    // A DS with the right identifiers but a corrupted digest is a digest
    // mismatch, not a silent pass.
    let mut digest = anchor_2017.digest.to_vec();
    digest[0] ^= 0xFF;
    let tampered = DS {
        key_tag: 20326,
        algorithm: 8,
        digest_type: 2,
        digest: Cow::Owned(digest),
    };
    assert!(matches!(
        verify_ds(&root, &dnskey, &tampered),
        Err(DnssecError::DigestMismatch { .. })
    ));
}

// ============================================================================
// End-to-end chain of trust over a constructed root -> TLD -> zone -> leaf.
// ============================================================================

/// Builds a signed chain root -> `com` -> `example.com` -> `host.example.com`,
/// returning the chain, the root DS anchor, and the root DNSKEY.
///
/// The two zone cuts (root delegating `com`, `com` delegating `example.com`)
/// exercise a deeper walk than a single-delegation chain: the trusted key set is
/// carried down twice before the leaf is reached.
fn deep_chain() -> (ChainOfTrust<'static>, DS<'static>, DNSKEY<'static>) {
    let root = TestKey::new();
    let tld = TestKey::new();
    let zone = TestKey::new();

    let root_dnskeys = root.signed_dnskeys("");

    // DS(com) is published in the root and signed by the root key.
    let com_ds = vec![ResourceRecord::new(
        Name::new_unchecked("com").into_owned(),
        CLASS::IN,
        3600,
        RData::DS(tld.ds("com")),
    )];
    let com_ds_rrsig = root.sign(&com_ds, TYPE_DS, "com", "");

    // DS(example.com) is published in com and signed by the com key.
    let zone_ds = vec![ResourceRecord::new(
        Name::new_unchecked("example.com").into_owned(),
        CLASS::IN,
        3600,
        RData::DS(zone.ds("example.com")),
    )];
    let zone_ds_rrsig = tld.sign(&zone_ds, TYPE_DS, "example.com", "com");

    let target_records = vec![ResourceRecord::new(
        Name::new_unchecked("host.example.com").into_owned(),
        CLASS::IN,
        3600,
        RData::A(A {
            address: u32::from_be_bytes([192, 0, 2, 1]),
        }),
    )];
    let target_rrsig = zone.sign(&target_records, TYPE_A, "host.example.com", "example.com");

    let chain = ChainOfTrust {
        root_dnskeys,
        zones: vec![
            DelegatedZone {
                delegation: SignedRrset {
                    records: com_ds,
                    rrsigs: vec![com_ds_rrsig],
                },
                dnskeys: tld.signed_dnskeys("com"),
            },
            DelegatedZone {
                delegation: SignedRrset {
                    records: zone_ds,
                    rrsigs: vec![zone_ds_rrsig],
                },
                dnskeys: zone.signed_dnskeys("example.com"),
            },
        ],
        target: SignedRrset {
            records: target_records,
            rrsigs: vec![target_rrsig],
        },
    };
    (chain, root.ds(""), root.dnskey.clone())
}

#[test]
fn verify_chain_accepts_deep_root_tld_zone_leaf() {
    let (chain, anchor, root_key) = deep_chain();
    // The DS-form anchor validates the two-cut chain to the leaf.
    assert!(verify_chain_with_anchors(&chain, std::slice::from_ref(&anchor)).is_ok());
    // Pinning the same root by its DNSKEY validates the identical chain.
    let anchors = vec![TrustAnchor::Dnskey(root_key)];
    assert!(verify_chain_with_trust_anchors(&chain, &anchors).is_ok());
}

#[test]
fn verify_chain_rejects_broken_intermediate_ds() {
    let (mut chain, anchor, _) = deep_chain();
    // Corrupt the DS that com publishes for example.com. The com signature over
    // the DS RRset no longer matches, so descending that cut fails closed.
    let RData::DS(ds) = &mut chain.zones[1].delegation.records[0].rdata else {
        panic!("delegation record must be a DS");
    };
    let mut digest = ds.digest.to_vec();
    digest[0] ^= 0xFF;
    ds.digest = Cow::Owned(digest);
    assert!(matches!(
        verify_chain_with_anchors(&chain, std::slice::from_ref(&anchor)),
        Err(ChainError::Link { .. } | ChainError::NoMatchingDnskey { .. })
    ));
}

#[test]
fn verify_chain_rejects_tampered_leaf_signature() {
    let (mut chain, anchor, _) = deep_chain();
    let mut signature = chain.target.rrsigs[0].signature.to_vec();
    signature[0] ^= 0xFF;
    chain.target.rrsigs[0].signature = Cow::Owned(signature);
    assert!(matches!(
        verify_chain_with_anchors(&chain, std::slice::from_ref(&anchor)),
        Err(ChainError::Link { .. })
    ));
}

#[test]
fn verify_chain_rejects_missing_intermediate_dnskey() {
    let (mut chain, anchor, _) = deep_chain();
    // Drop the com DNSKEY records: the root's DS for com then commits to nothing.
    chain.zones[0].dnskeys.records.clear();
    assert!(matches!(
        verify_chain_with_anchors(&chain, std::slice::from_ref(&anchor)),
        Err(ChainError::NoDnskeys { .. })
    ));
}

#[test]
fn verify_chain_rejects_untrusted_root() {
    let (chain, _, _) = deep_chain();
    // A DS over an unrelated key does not anchor this root.
    let stranger = TestKey::new();
    assert!(matches!(
        verify_chain_with_anchors(&chain, std::slice::from_ref(&stranger.ds(""))),
        Err(ChainError::UntrustedRoot { .. })
    ));
    // Nor does a DNSKEY-form anchor over an unrelated key.
    let anchors = vec![TrustAnchor::Dnskey(stranger.dnskey.clone())];
    assert!(matches!(
        verify_chain_with_trust_anchors(&chain, &anchors),
        Err(ChainError::UntrustedRoot { .. })
    ));
}

// ============================================================================
// RFC 5155 Appendix B NSEC3 denial proofs, driven through the public API.
// ============================================================================

/// Signs a set of NSEC3 records under `signer` and returns the authority section
/// (each record followed by its RRSIG).
fn signed_nsec3_authority(
    signer: &TestKey,
    records: &[ResourceRecord<'static>],
) -> Vec<ResourceRecord<'static>> {
    let mut authority = Vec::new();
    for record in records {
        let owner = record.name.to_string();
        let rrsig = signer.sign_rr(std::slice::from_ref(record), 50, &owner, "example");
        authority.push(record.clone());
        authority.push(rrsig);
    }
    authority
}

/// The RFC 5155 Appendix B.1 NXDOMAIN proof is rejected while its covering NSEC3
/// is opt-out, and accepted once opt-out is cleared.
///
/// The three records are the verbatim Appendix B.1 example for `a.c.x.w.example`:
/// `b4um...` matches the closest encloser `x.w.example`, `0p9m... -> 2t7b...`
/// covers the next closer `c.x.w.example`, and `35m... -> b4um...` covers the
/// wildcard `*.x.w.example`. Appendix B.1 sets the Opt-Out flag on every record,
/// but an opt-out NSEC3 does not prove the next closer is absent (RFC 7129 section
/// 5.3), so the crate rejects the proof. Clearing opt-out on the covering records
/// makes the same three-record layout prove the name absent, confirming the flag
/// is what blocks the proof.
#[test]
fn rfc5155_b1_nxdomain_optout_next_closer_rejected() {
    let signer = TestKey::new();
    let qname = Name::new_unchecked("a.c.x.w.example");

    let build = |flags: u8| {
        let records = vec![
            // Covers the next closer c.x.w.example.
            nsec3_rr(
                "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
                flags,
                "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
                &[
                    TYPE_MX,
                    TYPE_DNSKEY,
                    TYPE_NS,
                    TYPE_SOA,
                    TYPE_NSEC3PARAM,
                    TYPE_RRSIG,
                ],
            ),
            // Matches the closest encloser x.w.example.
            nsec3_rr(
                "b4um86eghhds6nea196smvmlo4ors995",
                flags,
                "gjeqe526plbf1g8mklp59enfd789njgi",
                &[TYPE_MX, TYPE_RRSIG],
            ),
            // Covers the wildcard *.x.w.example.
            nsec3_rr(
                "35mthgpgcu1qg68fab165klnsnk3dpvl",
                flags,
                "b4um86eghhds6nea196smvmlo4ors995",
                &[TYPE_NS, TYPE_DS, TYPE_RRSIG],
            ),
        ];
        signed_nsec3_authority(&signer, &records)
    };

    // Verbatim Appendix B.1 (opt-out set) does not prove the name absent.
    assert!(matches!(
        prove_nxdomain(&qname, &build(NSEC3_FLAG_OPT_OUT), &signer.keys()),
        Err(DenialError::NoProof { .. })
    ));
    // The same records without opt-out prove NXDOMAIN.
    assert!(prove_nxdomain(&qname, &build(0), &signer.keys()).is_ok());
}

/// The RFC 5155 Appendix B.2 NODATA proof for `ns1.example. MX`.
///
/// The single NSEC3 `2t7b...` matches the hashed owner of `ns1.example` and lists
/// `A RRSIG` but not `MX`, so the MX type is proven absent. Querying for a type
/// the record does list (A) instead shows the type present.
#[test]
fn rfc5155_b2_nodata_matches_hashed_owner() {
    let signer = TestKey::new();
    let record = nsec3_rr(
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
        NSEC3_FLAG_OPT_OUT,
        "2vptu5timamqttgl4luu9kg21e0aor3s",
        &[TYPE_A, TYPE_RRSIG],
    );
    let authority = signed_nsec3_authority(&signer, std::slice::from_ref(&record));
    let qname = Name::new_unchecked("ns1.example");

    assert!(prove_nodata(&qname, TYPE_MX, &authority, &signer.keys()).is_ok());
    assert!(matches!(
        prove_nodata(&qname, TYPE_A, &authority, &signer.keys()),
        Err(DenialError::TypePresent { .. })
    ));
}

/// The RFC 5155 Appendix B.2.1 NODATA proof for an empty non-terminal.
///
/// Querying `y.w.example. A` matches the NSEC3 `ji6n...`, whose type bit map is
/// empty because `y.w.example` exists only as an ancestor of `x.y.w.example`. An
/// empty bit map proves every type absent, so the A query is a valid NODATA.
#[test]
fn rfc5155_b21_nodata_empty_non_terminal() {
    let signer = TestKey::new();
    let record = nsec3_rr(
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
        NSEC3_FLAG_OPT_OUT,
        "k8udemvp1j2f7eg6jebps17vp3n8i58h",
        &[],
    );
    let authority = signed_nsec3_authority(&signer, std::slice::from_ref(&record));
    let qname = Name::new_unchecked("y.w.example");
    assert!(prove_nodata(&qname, TYPE_A, &authority, &signer.keys()).is_ok());
}

// ============================================================================
// NSEC covering-range edge case: the last NSEC wraps at the zone apex.
// ============================================================================

/// An NSEC NXDOMAIN proof works when the covering NSEC is the last in the zone,
/// whose next owner name is the apex (RFC 4034 section 6.1, RFC 4035 section 5.4).
///
/// Proving `zz.example.com` absent needs two records. The last NSEC in the zone,
/// `z.example.com -> example.com`, wraps back to the apex and so covers every name
/// sorting after `z.example.com`, including `zz.example.com`. The apex NSEC
/// `example.com -> a.example.com` covers the wildcard `*.example.com`, which sorts
/// between the apex and `a`. Together they leave no room for a wildcard match.
#[test]
fn nsec_nxdomain_wraps_at_zone_apex() {
    let signer = TestKey::new();

    let last = nsec_rr(
        "z.example.com",
        "example.com",
        &[TYPE_A, TYPE_RRSIG, TYPE_NSEC],
    );
    let last_sig = signer.sign_rr(
        std::slice::from_ref(&last),
        TYPE_NSEC,
        "z.example.com",
        "example.com",
    );
    let apex = nsec_rr(
        "example.com",
        "a.example.com",
        &[TYPE_SOA, TYPE_NS, TYPE_RRSIG, TYPE_NSEC],
    );
    let apex_sig = signer.sign_rr(
        std::slice::from_ref(&apex),
        TYPE_NSEC,
        "example.com",
        "example.com",
    );

    let authority = vec![last, last_sig, apex, apex_sig];
    let qname = Name::new_unchecked("zz.example.com");
    assert!(prove_nxdomain(&qname, &authority, &signer.keys()).is_ok());
}

// ============================================================================
// Malformed-input rejection at the public toolkit boundary.
// ============================================================================

/// [`verify_rrsig`] rejects an empty or inconsistent RRset once the key and time
/// checks pass (RFC 4035 section 5.3.1).
///
/// Both inputs carry a key whose tag, algorithm, and validity window all match the
/// RRSIG, so the failure is the RRset shape rather than an earlier precondition.
#[test]
fn verify_rrsig_rejects_malformed_rrset() {
    let signer = TestKey::new();
    let record = ResourceRecord::new(
        Name::new_unchecked("www.example.com").into_owned(),
        CLASS::IN,
        3600,
        RData::A(A {
            address: u32::from_be_bytes([192, 0, 2, 1]),
        }),
    );
    let rrsig = signer.sign(
        std::slice::from_ref(&record),
        TYPE_A,
        "www.example.com",
        "example.com",
    );

    // An empty RRset has nothing to validate.
    assert!(matches!(
        verify_rrsig(&rrsig, &[], &signer.dnskey),
        Err(DnssecError::EmptyRrset { .. })
    ));

    // Two records with different owner names are not one RRset.
    let other = ResourceRecord::new(
        Name::new_unchecked("other.example.com").into_owned(),
        CLASS::IN,
        3600,
        RData::A(A {
            address: u32::from_be_bytes([192, 0, 2, 2]),
        }),
    );
    assert!(matches!(
        verify_rrsig(&rrsig, &[record, other], &signer.dnskey),
        Err(DnssecError::InconsistentRrset { .. })
    ));
}
