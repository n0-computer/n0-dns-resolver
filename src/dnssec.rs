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
//! This is deliberately narrow. It validates a single signature or delegation
//! link, not a chain of trust: it does not walk DNSKEY and DS records from the
//! root trust anchor down to a name, so nothing here proves that a name is
//! genuinely signed from the root. NSEC and NSEC3 authenticated denial of
//! existence is not covered. Only two signature algorithms are supported:
//! ECDSA P-256 SHA-256 (algorithm 13, RFC 6605) and RSA/SHA-256 (algorithm 8,
//! RFC 5702).
//!
//! The canonical forms follow RFC 4034 section 6, and the signature input
//! follows RFC 4035 section 5.3.
//!
//! The record types come from [`simple_dns`], which this crate re-exports under
//! the `dnssec` feature so callers can name them without a second dependency.

use std::time::{SystemTime, UNIX_EPOCH};

use n0_error::{AnyError, e, stack_error};
use ring::{digest, signature};
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, TYPE,
    rdata::{DNSKEY, DS, OPT, RData, RRSIG},
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

/// The protocol value every DNSKEY must carry (RFC 4034 section 2.1.2).
const DNSKEY_PROTOCOL: u8 = 3;

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
    if dnskey.algorithm != rrsig.algorithm {
        return Err(e!(DnssecError::InvalidKey));
    }
    if key_tag(dnskey) != rrsig.key_tag {
        return Err(e!(DnssecError::KeyTagMismatch));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as u32;
    if now < rrsig.signature_inception {
        return Err(e!(DnssecError::SignatureNotYetValid));
    }
    if now > rrsig.signature_expiration {
        return Err(e!(DnssecError::SignatureExpired));
    }

    let signed = signed_data(rrsig, rrset)?;
    verify_signature(rrsig, dnskey, &signed)
}

/// A parsed DNS resource record, re-exported from [`simple_dns`] for use with
/// [`verify_rrsig`].
pub type ResourceRecord<'a> = simple_dns::ResourceRecord<'a>;

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

    // RRSIG RDATA without the trailing signature field. The signer name is used
    // exactly as it appears in the RRSIG (uncompressed, not downcased) so the
    // bytes match what the signer signed.
    let mut signed = Vec::new();
    signed.extend_from_slice(&rrsig.type_covered.to_be_bytes());
    signed.push(rrsig.algorithm);
    signed.push(rrsig.labels);
    signed.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
    signed.extend_from_slice(&rrsig.signature_expiration.to_be_bytes());
    signed.extend_from_slice(&rrsig.signature_inception.to_be_bytes());
    signed.extend_from_slice(&rrsig.key_tag.to_be_bytes());
    signed.extend_from_slice(&encode_name(rrsig.signer_name.as_bytes(), false));

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
/// The supported types (A, AAAA, DNSKEY, DS) carry no embedded domain names, so
/// their canonical RDATA is their plain wire RDATA. Other types return
/// [`DnssecError::UnsupportedRecordType`].
fn canonical_rdata(rdata: &RData<'_>) -> Result<Vec<u8>, DnssecError> {
    match rdata {
        RData::A(a) => Ok(a.address.to_be_bytes().to_vec()),
        RData::AAAA(aaaa) => Ok(aaaa.address.to_be_bytes().to_vec()),
        RData::DNSKEY(dnskey) => Ok(dnskey_rdata(dnskey)),
        RData::DS(ds) => Ok(ds_rdata(ds)),
        other => Err(e!(DnssecError::UnsupportedRecordType {
            type_code: u16::from(other.type_code()),
        })),
    }
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
/// Dispatches on the RRSIG algorithm number: 13 is ECDSA P-256 SHA-256
/// (RFC 6605), 8 is RSA/SHA-256 (RFC 5702). Any other algorithm is unsupported.
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
        8 => {
            let (exponent, modulus) = split_rsa_public_key(&dnskey.public_key)?;
            let components = signature::RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            };
            components
                .verify(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    signed,
                    &rrsig.signature,
                )
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

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ring::{
        rand::SystemRandom,
        signature::{
            ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
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
    fn build_dnssec_query_sets_do_bit() {
        let (_, bytes) = build_dnssec_query("example.com", TYPE::A).unwrap();
        // The OPT record still parses and the DO bit is set in its TTL flags.
        let packet = Packet::parse(&bytes).unwrap();
        assert!(packet.opt().is_some(), "query must carry an OPT record");
        let flags_hi = bytes[bytes.len() - 4];
        assert_eq!(flags_hi & 0x80, 0x80, "DO bit must be set");
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
