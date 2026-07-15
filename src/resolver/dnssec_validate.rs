//! Resolver-side DNSSEC validation: fetch the chain and walk it (feature `dnssec`).
//!
//! [`SimpleDnsResolver::validate_answer`] is the entry point the lookup path
//! calls when [`crate::Builder::validate_dnssec`] is set. It extracts the answer
//! RRset and its RRSIG, fetches the signing zone's DNSKEY RRset and the DS chain
//! up to the root, and hands the assembled [`ChainOfTrust`] to [`verify_chain`].
//!
//! Validation is fail-closed. An answer with no RRSIG, a zone with no fetchable
//! DNSKEY or DS RRset, or a chain that does not validate all map to
//! [`crate::Error::DnssecBogus`]. Denial of existence (NSEC and NSEC3) is not
//! implemented, so unsigned names and negative answers are rejected rather than
//! proven, which is the intended fail-closed behavior. Only the final answer
//! RRset is validated; CNAME hops are followed but not individually checked.

use n0_error::{AnyError, e, stack_error};
use simple_dns::{Name, Packet, TYPE, rdata::RData};
use tracing::{debug, warn};

use super::SimpleDnsResolver;
use crate::{
    Error,
    dnssec::{
        ChainError, ChainOfTrust, DelegatedZone, ResourceRecord, SignedRrset, build_dnssec_query,
        verify_chain,
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
    /// No DNSKEY RRset with its signature could be fetched for a zone.
    #[error("no signed DNSKEY RRset for zone {zone}")]
    MissingDnskey { zone: String },
    /// No DS RRset with its signature could be fetched for a zone.
    #[error("no signed DS RRset for zone {zone}")]
    MissingDs { zone: String },
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
        let target = parse_signed_rrset(response, host, qtype)
            .ok_or_else(|| e!(ValidateError::MissingSignature))?;

        // The signer name is attacker-controlled, so it must be checked against
        // the answer before it is trusted to name the signing zone. Only the
        // answer's own zone or an ancestor may sign it (RFC 4035 5.3.1);
        // otherwise the holder of any signed zone could sign records for any
        // name and the chain to the root would still validate.
        let owner = target
            .records
            .first()
            .ok_or_else(|| e!(ValidateError::MissingSignature))?
            .name
            .clone();
        if !signer_is_authoritative(&target.rrsig.signer_name, &owner) {
            return Err(e!(ValidateError::SignerNotAuthoritative {
                signer: target.rrsig.signer_name.to_string(),
                owner: owner.to_string(),
            }));
        }

        // The RRSIG signer names the zone that signed the answer. Validate from
        // the root down through every zone cut between them.
        let signing_zone = target.rrsig.signer_name.to_string();
        debug!(zone = %signing_zone, "validating answer against DNSSEC chain");

        let root_dnskeys = self
            .fetch_signed_rrset(".", TYPE::DNSKEY)
            .await?
            .ok_or_else(|| {
                e!(ValidateError::MissingDnskey {
                    zone: ".".to_string(),
                })
            })?;

        let mut zones = Vec::new();
        for zone in zone_ancestors(&signing_zone) {
            let delegation = self
                .fetch_signed_rrset(&zone, TYPE::DS)
                .await?
                .ok_or_else(|| e!(ValidateError::MissingDs { zone: zone.clone() }))?;
            let dnskeys = self
                .fetch_signed_rrset(&zone, TYPE::DNSKEY)
                .await?
                .ok_or_else(|| e!(ValidateError::MissingDnskey { zone: zone.clone() }))?;
            zones.push(DelegatedZone {
                delegation,
                dnskeys,
            });
        }

        let chain = ChainOfTrust {
            root_dnskeys,
            zones,
            target,
        };
        verify_chain(&chain).map_err(|source| e!(ValidateError::Chain, source))
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
        let (_id, query) = build_dnssec_query(name, qtype)
            .map_err(|err| e!(ValidateError::Fetch, AnyError::from_stack(err)))?;
        let response = self
            .send_query(&query)
            .await
            .map_err(|err| e!(ValidateError::Fetch, AnyError::from_stack(err)))?;
        Ok(parse_signed_rrset(&response, name, qtype))
    }
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

/// Extracts the `qtype` RRset owned by `expected_owner` and its RRSIG.
///
/// Finds the RRSIG in the answer section that is owned by `expected_owner` and
/// covers `qtype`, then gathers every answer record of `qtype` under that same
/// owner. Requiring the owner ties the returned RRset to the name that was
/// queried, so a signed RRset for a different name in the same response cannot
/// stand in for it. Returns `None` when the response does not parse, the
/// expected name is invalid, or no such RRSIG or records are present, all of
/// which the caller treats as a missing signature.
fn parse_signed_rrset(
    response: &[u8],
    expected_owner: &str,
    qtype: TYPE,
) -> Option<SignedRrset<'static>> {
    let packet = Packet::parse(response).ok()?;
    let covered = u16::from(qtype);
    let owner = Name::new(expected_owner).ok()?;

    let rrsig_rr = packet.answers.iter().find(|rr| {
        rr.name == owner && matches!(&rr.rdata, RData::RRSIG(sig) if sig.type_covered == covered)
    })?;
    let RData::RRSIG(rrsig) = &rrsig_rr.rdata else {
        return None;
    };
    let rrsig = rrsig.clone().into_owned();

    let records: Vec<ResourceRecord<'static>> = packet
        .answers
        .iter()
        .filter(|rr| u16::from(rr.rdata.type_code()) == covered && rr.name == owner)
        .map(|rr| rr.clone().into_owned())
        .collect();
    if records.is_empty() {
        return None;
    }
    Some(SignedRrset { records, rrsig })
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
        assert_eq!(signed.rrsig.signer_name.to_string(), "example.com");
        assert_eq!(signed.rrsig.key_tag, 12345);
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
