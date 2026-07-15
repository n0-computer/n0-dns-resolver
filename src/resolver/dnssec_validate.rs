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
//! [`crate::Error::DnssecBogus`]. Two cases lean on the denial-of-existence
//! proofs. A wildcard-expanded answer validates only when the authority section
//! proves no closer match exists. A delegation with no DS is accepted as
//! Insecure (unsigned) when the authority section proves the DS is truly absent,
//! rather than being rejected. Only the final answer RRset is validated; CNAME
//! hops are followed but not individually checked. Authenticating a bare
//! NODATA or NXDOMAIN answer is not yet wired: the resolver validates positive
//! answers, so a negative answer still fails closed rather than being proven.

use n0_error::{AnyError, e, stack_error};
use simple_dns::{
    Name, Packet, TYPE,
    rdata::{RData, RRSIG},
};
use tracing::{debug, warn};

use super::SimpleDnsResolver;
use crate::{
    Error,
    dnssec::{
        ChainError, DelegatedZone, DenialError, ROOT_TRUST_ANCHORS, ResourceRecord, SignedRrset,
        build_dnssec_query, descend_zone, prove_no_ds, prove_wildcard, trust_root,
        verify_rrset_with_keys,
    },
};

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
        // Take the signing zone from the most specific surviving signer, which is
        // the RRset's actual zone apex. Honest RRSIGs over one RRset all name that
        // apex, but an on-path attacker can prepend a bogus RRSIG signed by an
        // ancestor zone; picking the first survivor would then build the chain too
        // shallow and reject a legitimate answer.
        let Some(signing_rrsig) = most_specific_signer(&target.rrsigs) else {
            return Err(e!(ValidateError::SignerNotAuthoritative {
                signer: rejected_signer.unwrap_or_default(),
                owner: owner.to_string(),
            }));
        };

        // A wildcard-expanded answer (RRSIG labels below the owner's label count)
        // is a valid signature over `*.zone`. Proving it applies to this name
        // needs an authority-section NSEC or NSEC3 showing no closer match exists
        // (RFC 4035 section 5.3.4); that proof runs after the chain validates the
        // signing zone's keys.
        let wildcard_labels =
            is_wildcard_expansion(signing_rrsig.labels, &owner).then_some(signing_rrsig.labels);

        // The RRSIG signer names the zone that signed the answer. Validate from
        // the root down through every zone cut between them.
        let signing_zone = signing_rrsig.signer_name.to_string();
        debug!(zone = %signing_zone, "validating answer against DNSSEC chain");

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

        // Discover the real secure zone cuts between the root and the signing
        // zone. Not every label boundary is a delegation: a zone can hold names
        // several labels deep, and a delegation may skip labels. Query the DS at
        // each ancestor and descend on the ones that publish a signed DS RRset.
        //
        // When an ancestor has no DS, it is either a non-cut or an insecure
        // (unsigned) delegation. If the DS response carries an NSEC or NSEC3,
        // validated against the trusted parent keys, that proves the DS is truly
        // absent, then everything at or below that cut is unsigned. The answer's
        // own zone is thereby proven insecure, so we accept it as unsigned rather
        // than failing (RFC 4035 section 4.3, RFC 5155 section 8.6).
        //
        // Without such a proof the ancestor is treated as a non-cut and skipped,
        // which keeps the walk fail-closed. A stripped DS on a genuinely signed
        // delegation yields no valid absence proof (the parent's signature cannot
        // be forged), so the signing zone's keys never enter the trusted set and
        // the target's RRSIG matches no trusted key, failing the chain as before.
        for zone in zone_ancestors(&signing_zone) {
            let ds_response = self.fetch_raw(&zone, TYPE::DS).await?;
            if let Some(delegation) = parse_signed_rrset(&ds_response, &zone, TYPE::DS) {
                let dnskeys = self
                    .fetch_signed_rrset(&zone, TYPE::DNSKEY)
                    .await?
                    .ok_or_else(|| e!(ValidateError::MissingDnskey { zone: zone.clone() }))?;
                let delegated = DelegatedZone {
                    delegation,
                    dnskeys,
                };
                trusted = descend_zone(&trusted, &delegated)
                    .map_err(|source| e!(ValidateError::Chain, source))?;
            } else if let Ok(child) = Name::new(&zone) {
                let authority = authority_records(&ds_response);
                if prove_no_ds(&child, &authority, &trusted).is_ok() {
                    debug!(zone = %zone, "insecure delegation proven; accepting answer as unsigned");
                    return Ok(());
                }
                debug!(zone = %zone, "no signed DS, treating as a non-cut and skipping");
            }
        }

        // The signing zone's keys are now trusted. Validate the answer RRset.
        verify_rrset_with_keys(&target, &trusted)
            .map_err(|source| e!(ValidateError::Chain, source))?;

        // Finally, a wildcard-expanded answer needs its closer-match proof from
        // the same response's authority section, validated against the signing
        // zone keys we just trusted.
        if let Some(labels) = wildcard_labels {
            let authority = authority_records(response);
            prove_wildcard(&owner, labels, &authority, &trusted).map_err(|source| {
                e!(ValidateError::WildcardUnproven {
                    owner: owner.to_string(),
                    source,
                })
            })?;
        }
        Ok(())
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

/// Returns whether `signer` may sign records owned by `owner`.
///
/// A zone signs only the names at or below its apex, so the signer must equal
/// `owner` or be an ancestor of it: its labels must be a suffix of `owner`'s,
/// compared case-insensitively. This rejects an RRSIG whose signer is an
/// unrelated (but validly signed) zone, which would otherwise chain to the root
/// and validate.
/// Returns the RRSIG with the most specific (longest) signer name.
///
/// All authoritative RRSIGs over one RRset name the same zone in an honest
/// response. Choosing the longest signer keeps the chain anchored at the RRset's
/// real zone apex even if an on-path attacker injects an RRSIG signed by a
/// shallower ancestor zone.
fn most_specific_signer<'a>(rrsigs: &'a [RRSIG<'static>]) -> Option<&'a RRSIG<'static>> {
    rrsigs
        .iter()
        .max_by_key(|sig| sig.signer_name.as_bytes().count())
}

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
        rdata::{A, RData, RRSIG},
    };

    use super::*;

    #[test]
    fn most_specific_signer_prefers_the_deepest_zone() {
        let rrsig = |signer: &str| RRSIG {
            type_covered: u16::from(TYPE::A),
            algorithm: 13,
            labels: 3,
            original_ttl: 300,
            signature_expiration: 1_800_000_000,
            signature_inception: 1_700_000_000,
            key_tag: 1,
            signer_name: Name::new_unchecked(signer).into_owned(),
            signature: Cow::Owned(vec![0u8; 64]),
        };
        // The RRset's real apex (example.com) must win over an injected
        // ancestor-signed RRSIG (com), regardless of order.
        let rrsigs = vec![rrsig("com"), rrsig("example.com")];
        assert_eq!(
            most_specific_signer(&rrsigs)
                .unwrap()
                .signer_name
                .to_string(),
            "example.com"
        );
        let rrsigs = vec![rrsig("example.com"), rrsig("com")];
        assert_eq!(
            most_specific_signer(&rrsigs)
                .unwrap()
                .signer_name
                .to_string(),
            "example.com"
        );
        assert!(most_specific_signer(&[]).is_none());
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
}
