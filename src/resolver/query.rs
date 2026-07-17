//! DNS packet construction and response parsing using `simple_dns`.

use std::net::{Ipv4Addr, Ipv6Addr};

use n0_error::{e, stack_error};
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, TYPE, header_buffer,
    rdata::{A, AAAA, RData, SVCB},
};

use crate::{
    CaaRecordData, HttpsRecord, MxRecordData, Record, RecordKind, ResponseCode, SrvRecordData,
    SvcbRecordData, TxtRecordData,
};

/// Errors that can occur while building a query packet or parsing a response.
///
/// Mapped to [`crate::Error`] by the resolver layer.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, std_sources)]
pub(super) enum QueryError {
    #[error("invalid domain name: {name}")]
    BuildQuery { name: String },
    #[error("malformed DNS response")]
    Malformed {},
    #[error("response did not match query")]
    Unexpected {},
    #[error("domain name does not exist (NXDOMAIN)")]
    NxDomain {},
    #[error("server returned error: {rcode:?}")]
    ServerFailure { rcode: RCODE },
}

/// Maps a `simple_dns` [`RCODE`] onto the public [`ResponseCode`].
pub(super) fn response_code(rcode: RCODE) -> ResponseCode {
    match rcode {
        RCODE::ServerFailure => ResponseCode::ServerFailure,
        RCODE::Refused => ResponseCode::Refused,
        RCODE::FormatError => ResponseCode::FormatError,
        RCODE::NotImplemented => ResponseCode::NotImplemented,
        _ => ResponseCode::Other,
    }
}

/// Length of a fixed DNS message header (RFC 1035 Section 4.1.1).
///
/// A buffer shorter than this cannot be a DNS message. The header-flag helpers
/// index into the first four bytes without bounds-checking, so callers on raw
/// network input guard against shorter buffers first.
const DNS_HEADER_LEN: usize = 12;

/// EDNS(0) advertised UDP payload size.
///
/// 1232 bytes is the current recommended safe value per RFC 6891 and the
/// DNS flag day 2020 recommendations. This avoids IP fragmentation on
/// common path MTUs while allowing responses much larger than the
/// original 512-byte RFC 1035 limit.
const EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

/// Builds a DNS query packet for the given host and query type.
///
/// The query includes an EDNS(0) OPT record advertising support for
/// responses up to [`EDNS_UDP_PAYLOAD_SIZE`] bytes over UDP.
///
/// Returns `(query_id, wire_bytes)`.
pub(super) fn build_query(host: &str, qtype: TYPE) -> Result<(u16, Vec<u8>), QueryError> {
    let id: u16 = rand::random();
    let mut packet = Packet::new_query(id);
    packet.set_flags(PacketFlag::RECURSION_DESIRED);

    let name = Name::new(host).map_err(|_| {
        e!(QueryError::BuildQuery {
            name: host.to_string()
        })
    })?;
    let question = Question::new(name, QTYPE::TYPE(qtype), QCLASS::CLASS(CLASS::IN), false);
    packet.questions.push(question);

    // Add EDNS(0) OPT record to advertise larger UDP payload support.
    *packet.opt_mut() = Some(simple_dns::rdata::OPT {
        udp_packet_size: EDNS_UDP_PAYLOAD_SIZE,
        version: 0,
        opt_codes: vec![],
    });

    let bytes = packet.build_bytes_vec().map_err(|_| {
        e!(QueryError::BuildQuery {
            name: host.to_string()
        })
    })?;
    Ok((id, bytes))
}

/// Sets the EDNS(0) DO (DNSSEC OK) bit on a query built by [`build_query`].
///
/// `simple_dns` does not model the DO bit, so it is set directly on the built
/// bytes. The DO bit is the high bit of the OPT record's TTL flags field
/// (RFC 6891 section 6.1.3). [`build_query`] emits the OPT record last with no
/// options, so its flags high byte sits four bytes from the end. When the buffer
/// is too short to hold an OPT record this is a no-op.
#[cfg(feature = "dnssec")]
pub(super) fn set_do_bit(bytes: &mut [u8]) {
    if let Some(flags_hi) = bytes.len().checked_sub(4).and_then(|i| bytes.get_mut(i)) {
        *flags_hi |= 0x80;
    }
}

/// Returns the RCODE if `data` is a failure that warrants trying another
/// nameserver (SERVFAIL, REFUSED, or FORMERR), otherwise `None`.
///
/// SERVFAIL and REFUSED mean this server cannot answer for the name; FORMERR
/// means it rejected the query itself (often the EDNS OPT record — the caller
/// retries without EDNS before this, see [`strip_edns`]). In every case another
/// nameserver may still resolve the name, so the race should move on rather than
/// treat the response as final.
///
/// Reads just the RCODE from the header so it works on the raw response before
/// the packet is fully parsed or validated. A spoofed RCODE here is harmless:
/// at worst it makes the race try another server, and the eventual response is
/// still validated by [`check_response`].
pub(super) fn retryable_failure_rcode(data: &[u8]) -> Option<RCODE> {
    // `header_buffer::rcode` indexes `data[2..4]` without a bounds check, so a
    // response shorter than a DNS header would panic. This runs on raw,
    // unvalidated bytes before `check_response`, so guard the length here.
    if data.len() < DNS_HEADER_LEN {
        return None;
    }
    match header_buffer::rcode(data) {
        Ok(rcode @ (RCODE::ServerFailure | RCODE::Refused | RCODE::FormatError)) => Some(rcode),
        _ => None,
    }
}

/// Returns whether `data` is a response with a FORMERR (format error) RCODE.
///
/// A FORMERR from a server or middlebox often means it could not parse our
/// query, commonly because of the EDNS(0) OPT record; the caller retries the
/// same server without EDNS (see [`strip_edns`]) before moving on. Reads only
/// the header RCODE, so it runs on raw bytes before full validation.
pub(super) fn is_format_error(data: &[u8]) -> bool {
    data.len() >= DNS_HEADER_LEN && matches!(header_buffer::rcode(data), Ok(RCODE::FormatError))
}

/// Rebuilds `query` without its EDNS(0) OPT record, or `None` if it has none.
///
/// RFC 6891 Section 6.2.2 calls for retrying without EDNS when a server rejects
/// the OPT record. The transaction ID, flags, and question are preserved so the
/// response to the stripped query still passes [`check_response`].
pub(super) fn strip_edns(query: &[u8]) -> Option<Vec<u8>> {
    let mut packet = Packet::parse(query).ok()?;
    packet.opt()?;
    *packet.opt_mut() = None;
    packet.build_bytes_vec().ok()
}

/// Derives the RFC 2308 negative-caching TTL from a response's authority SOA.
///
/// On a NODATA or NXDOMAIN answer an authoritative server includes an SOA record
/// in the authority section; the negative result should be cached for no longer
/// than `min(SOA MINIMUM, SOA record TTL)`. Returns `None` when no SOA is
/// present, so the caller can fall back to a fixed default.
pub(super) fn negative_ttl(data: &[u8]) -> Option<u32> {
    let packet = Packet::parse(data).ok()?;
    packet.name_servers.iter().find_map(|rr| match &rr.rdata {
        RData::SOA(soa) => Some(rr.ttl.min(soa.minimum)),
        _ => None,
    })
}

/// Maximum CNAME chain depth to prevent infinite loops.
pub(super) const MAX_CNAME_DEPTH: usize = 8;

/// Returns every name in the CNAME chain starting at `start_name`: the start
/// name, then each CNAME target, ending at the final canonical name.
///
/// Records of the queried type can be attached to any name along the chain, not
/// just the final one, so extraction matches against the whole chain the way a
/// recursive resolver does. Bounded by [`MAX_CNAME_DEPTH`].
fn cname_chain<'a>(packet: &'a Packet<'a>, start_name: &Name<'a>) -> Vec<Name<'a>> {
    let mut chain = vec![start_name.clone()];
    let mut current = start_name.clone();
    for _ in 0..MAX_CNAME_DEPTH {
        let Some(RData::CNAME(cname)) = packet
            .answers
            .iter()
            .find(|rr| rr.name == current)
            .map(|rr| &rr.rdata)
        else {
            break;
        };
        current = cname.0.clone();
        chain.push(current.clone());
    }
    chain
}

/// Resolves the CNAME chain in the answer section starting from `start_name`.
///
/// Returns the final canonical name after following all CNAMEs, or the
/// original name if no CNAME records are present.
fn resolve_cname_chain<'a>(packet: &'a Packet<'a>, start_name: &Name<'a>) -> Name<'a> {
    let mut chain = cname_chain(packet, start_name);
    // `cname_chain` always includes at least the start name.
    chain.pop().unwrap_or_else(|| start_name.clone())
}

/// Returns the CNAME target for a query name, if the response contains a CNAME
/// but no final records of the requested type for that name.
///
/// This is used for recursive CNAME following: when the server returns only a
/// CNAME without the final record, the caller issues a new query for the target.
pub(super) fn cname_target(packet: &Packet<'_>, qname: &str) -> Option<String> {
    let name = Name::new(qname).ok()?;
    let canonical = resolve_cname_chain(packet, &name);
    (canonical != name).then(|| canonical.to_string())
}

/// Validates a response against the query that produced it, then surfaces its RCODE.
///
/// Per RFC 5452 a response is only trustworthy if it echoes the query: the QR
/// flag must be set, the transaction ID must match, and the response must carry
/// exactly the one question we asked, by name, type, and class. Without the
/// question check an off-path attacker who guesses the 16-bit ID could supply
/// its own question and have its answers accepted for an arbitrary name. A
/// `NameError` RCODE maps to [`QueryError::NxDomain`] and any other non-`NoError`
/// RCODE to [`QueryError::ServerFailure`].
pub(super) fn check_response(
    packet: &Packet,
    expected_id: u16,
    expected_name: &Name<'_>,
    expected_type: TYPE,
) -> Result<(), QueryError> {
    if !packet.has_flags(PacketFlag::RESPONSE) {
        return Err(e!(QueryError::Unexpected));
    }
    if packet.id() != expected_id {
        return Err(e!(QueryError::Unexpected));
    }
    // The response must echo exactly the question we sent (RFC 1035 4.1.2).
    match packet.questions.as_slice() {
        [question]
            if &question.qname == expected_name
                && question.qtype == QTYPE::TYPE(expected_type)
                && question.qclass == QCLASS::CLASS(CLASS::IN) => {}
        _ => return Err(e!(QueryError::Unexpected)),
    }
    match packet.rcode() {
        RCODE::NoError => Ok(()),
        RCODE::NameError => Err(e!(QueryError::NxDomain)),
        rcode => Err(e!(QueryError::ServerFailure { rcode })),
    }
}

/// Extracts matching records from a validated DNS response, following CNAME chains.
///
/// The caller must already have validated the response with [`check_response`];
/// this walks the CNAME chain anchored on the question and extracts records of
/// the requested type using `extract` at every name along the chain. Returns the
/// records and the minimum TTL across them.
fn parse_response<T>(
    data: &[u8],
    extract: impl Fn(&Name<'_>, &RData<'_>) -> Option<T>,
) -> Result<(Vec<T>, u32), QueryError> {
    let packet = Packet::parse(data).map_err(|_| e!(QueryError::Malformed))?;

    // The chain is empty only for a response with no question section, which
    // `check_response` already rejects; extraction then matches nothing.
    let chain = packet
        .questions
        .first()
        .map(|question| cname_chain(&packet, &question.qname))
        .unwrap_or_default();

    let mut results = Vec::new();
    let mut min_ttl = u32::MAX;
    for rr in &packet.answers {
        if !chain.contains(&rr.name) {
            continue;
        }
        // A CNAME along the chain bounds the cached lifetime too: a short-TTL
        // CNAME must not be served past its intended life because the final
        // records happen to carry a longer TTL. Fold its TTL even though it is
        // not itself an extracted record. This bounds the CNAMEs present in this
        // response; a chain followed across separate queries only passes its
        // final response here, so those intermediate CNAME TTLs are not folded.
        if matches!(rr.rdata, RData::CNAME(_)) {
            min_ttl = min_ttl.min(rr.ttl);
        } else if let Some(val) = extract(&rr.name, &rr.rdata) {
            results.push(val);
            min_ttl = min_ttl.min(rr.ttl);
        }
    }
    if min_ttl == u32::MAX {
        min_ttl = 0;
    }
    Ok((results, min_ttl))
}

/// Parses the records of `kind` from a DNS response, following CNAME chains.
///
/// One dispatch replaces a parse function per kind: it picks the `extract`
/// closure for `kind` and runs [`parse_response`], returning the matching
/// [`Record`]s and the minimum TTL across them.
pub(super) fn parse_records(
    data: &[u8],
    kind: RecordKind,
) -> Result<(Vec<Record>, u32), QueryError> {
    match kind {
        RecordKind::A => parse_response(data, |_, rdata| match rdata {
            RData::A(A { address }) => Some(Record::A(Ipv4Addr::from(*address))),
            _ => None,
        }),
        RecordKind::Aaaa => parse_response(data, |_, rdata| match rdata {
            RData::AAAA(AAAA { address }) => Some(Record::Aaaa(Ipv6Addr::from(*address))),
            _ => None,
        }),
        RecordKind::Txt => parse_response(data, |_, rdata| match rdata {
            RData::TXT(txt) => Some(Record::Txt(extract_txt_record_data(txt))),
            _ => None,
        }),
        RecordKind::Ns => parse_response(data, |_, rdata| match rdata {
            RData::NS(ns) => Some(Record::Ns(ns.0.to_string())),
            _ => None,
        }),
        RecordKind::Srv => parse_response(data, |_, rdata| match rdata {
            RData::SRV(srv) => Some(Record::Srv(SrvRecordData {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                target: srv.target.to_string(),
            })),
            _ => None,
        }),
        RecordKind::Mx => parse_response(data, |_, rdata| match rdata {
            RData::MX(mx) => Some(Record::Mx(MxRecordData {
                preference: mx.preference,
                exchange: mx.exchange.to_string(),
            })),
            _ => None,
        }),
        RecordKind::Caa => parse_response(data, |_, rdata| match rdata {
            RData::CAA(caa) => Some(Record::Caa(CaaRecordData {
                flag: caa.flag,
                tag: caa.tag.to_string(),
                value: caa.value.as_ref().into(),
            })),
            _ => None,
        }),
        RecordKind::Svcb => parse_response(data, |_, rdata| match rdata {
            RData::SVCB(svcb) => Some(Record::Svcb(extract_svcb(svcb))),
            _ => None,
        }),
        RecordKind::Https => parse_response(data, |name, rdata| match rdata {
            RData::HTTPS(https) => Some(Record::Https(HttpsRecord::new(
                name.to_string(),
                extract_svcb(&https.0),
            ))),
            _ => None,
        }),
    }
}

/// Wraps an SVCB or HTTPS record for return.
///
/// HTTPS records reuse the SVCB rdata, so both kinds share this. The parsed
/// record is cloned into an owned form; [`SvcbRecordData`] exposes its common
/// parameters through accessors.
fn extract_svcb(svcb: &SVCB<'_>) -> SvcbRecordData {
    SvcbRecordData::new(svcb.clone().into_owned())
}

/// Extracts the raw content of a TXT record into `TxtRecordData`.
///
/// Converts the TXT record's character strings into raw bytes. In iroh's
/// DNS encoding, each TXT record typically contains a single character
/// string (one `key=value` attribute), and each attribute is published as
/// a separate TXT ResourceRecord.
///
/// We use `String::try_from` which concatenates all character strings in
/// the record into one byte sequence. This preserves the raw content
/// without the destructive key=value parsing that `TXT::attributes()` does
/// (which uses a HashMap and would lose ordering and deduplicate keys).
fn extract_txt_record_data(txt: &simple_dns::rdata::TXT<'_>) -> TxtRecordData {
    // Preserve each character-string as its own raw bytes, matching the
    // `TxtRecordData` "list of character strings" contract. The previous
    // `String::try_from` concatenated all strings into one and required UTF-8,
    // so a multi-string record collapsed and any binary TXT (some SPF/DKIM)
    // silently became empty. `iter_raw` yields each string split on its first
    // `=`; reconstruct the original bytes so the round trip is exact.
    txt.iter_raw()
        .map(|(key, value)| match value {
            Some(value) => {
                let mut bytes = Vec::with_capacity(key.len() + 1 + value.len());
                bytes.extend_from_slice(key);
                bytes.push(b'=');
                bytes.extend_from_slice(value);
                bytes.into_boxed_slice()
            }
            None => Box::<[u8]>::from(key),
        })
        .collect()
}

/// Returns true if the response has the TC (truncation) flag set.
///
/// Reads only the header flags, so it works even on a truncated packet whose
/// body fails to parse. A buffer too short to hold a header is treated as not
/// truncated; it will fail to parse downstream.
pub(super) fn is_truncated(data: &[u8]) -> bool {
    // As in `server_failure_rcode`, guard against a short buffer: this runs on
    // the raw UDP datagram before any validation, and `header_buffer::has_flags`
    // would panic indexing `data[2..4]` on fewer than four bytes.
    if data.len() < DNS_HEADER_LEN {
        return false;
    }
    header_buffer::has_flags(data, PacketFlag::TRUNCATION).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use simple_dns::{
        CLASS, CharacterString, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, ResourceRecord,
        rdata::{A, CAA, CNAME, MX, RData, SRV, TXT},
    };

    use super::*;

    /// Build a query packet for `host` with type A, return (id, bytes).
    fn make_query(host: &str) -> (u16, Vec<u8>) {
        build_query(host, TYPE::A).unwrap()
    }

    /// Parses the A records from `data` and returns just their addresses and TTL,
    /// so the A-focused tests can compare against `Vec<Ipv4Addr>` directly.
    fn parse_a_addrs(data: &[u8]) -> (Vec<Ipv4Addr>, u32) {
        let (records, ttl) = parse_records(data, RecordKind::A).unwrap();
        let addrs = records
            .into_iter()
            .filter_map(|r| match r {
                Record::A(ip) => Some(ip),
                _ => None,
            })
            .collect();
        (addrs, ttl)
    }

    /// Build a response with A records for `name`.
    fn a_response(id: u16, name: &str, addrs: &[Ipv4Addr]) -> Vec<u8> {
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        // Echo the question back (needed for CNAME resolution in parse functions).
        packet.questions.push(Question::new(
            Name::new_unchecked(name),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        for addr in addrs {
            packet.answers.push(ResourceRecord::new(
                Name::new_unchecked(name),
                CLASS::IN,
                300,
                RData::A(A {
                    address: u32::from(*addr),
                }),
            ));
        }
        packet.build_bytes_vec().unwrap()
    }

    /// Build a response containing a CNAME from `alias` -> `canonical`, plus
    /// A records under the canonical name (the common "both in one response" case).
    fn cname_with_a_response(id: u16, alias: &str, canonical: &str, addrs: &[Ipv4Addr]) -> Vec<u8> {
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked(alias),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        // CNAME record
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked(alias),
            CLASS::IN,
            300,
            RData::CNAME(CNAME(Name::new_unchecked(canonical))),
        ));
        // A records for the canonical name
        for addr in addrs {
            packet.answers.push(ResourceRecord::new(
                Name::new_unchecked(canonical),
                CLASS::IN,
                300,
                RData::A(A {
                    address: u32::from(*addr),
                }),
            ));
        }
        packet.build_bytes_vec().unwrap()
    }

    /// Build a response containing only a CNAME (no final A record).
    fn cname_only_response(id: u16, alias: &str, canonical: &str) -> Vec<u8> {
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked(alias),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked(alias),
            CLASS::IN,
            300,
            RData::CNAME(CNAME(Name::new_unchecked(canonical))),
        ));
        packet.build_bytes_vec().unwrap()
    }

    #[test]
    fn build_query_includes_edns_opt() {
        let (_, bytes) = build_query("example.com", TYPE::A).unwrap();
        let packet = Packet::parse(&bytes).unwrap();
        let opt = packet.opt().expect("query should include OPT record");
        assert_eq!(opt.udp_packet_size, 1232);
        assert_eq!(opt.version, 0);
    }

    #[test]
    fn strip_edns_removes_opt_and_preserves_question() {
        let (id, bytes) = build_query("example.com", TYPE::A).unwrap();
        assert!(Packet::parse(&bytes).unwrap().opt().is_some());

        let stripped = strip_edns(&bytes).expect("query has EDNS to strip");
        let packet = Packet::parse(&stripped).unwrap();
        assert!(packet.opt().is_none(), "OPT should be removed");
        assert_eq!(packet.id(), id, "transaction ID preserved");
        let question = &packet.questions[0];
        assert_eq!(question.qname, Name::new_unchecked("example.com"));
        assert_eq!(question.qtype, QTYPE::TYPE(TYPE::A));

        // A query already without EDNS yields None.
        assert!(strip_edns(&stripped).is_none());
    }

    #[test]
    fn formerr_is_detected_and_retryable() {
        let (id, _) = make_query("example.com");
        let mut resp = a_response(id, "example.com", &[Ipv4Addr::new(1, 2, 3, 4)]);
        // A NoError response is neither a FORMERR nor otherwise retryable.
        assert!(!is_format_error(&resp));
        assert_eq!(retryable_failure_rcode(&resp), None);

        // The RCODE is the low nibble of header byte 3. FORMERR = 1.
        resp[3] = (resp[3] & 0xF0) | 0x01;
        assert!(is_format_error(&resp));
        assert_eq!(retryable_failure_rcode(&resp), Some(RCODE::FormatError));

        // SERVFAIL (2) and REFUSED (5) are retryable but not FORMERR.
        resp[3] = (resp[3] & 0xF0) | 0x02;
        assert!(!is_format_error(&resp));
        assert_eq!(retryable_failure_rcode(&resp), Some(RCODE::ServerFailure));
    }

    #[test]
    fn negative_ttl_is_min_of_soa_ttl_and_minimum() {
        let (id, _) = make_query("nx.example.com");
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RESPONSE);
        packet.questions.push(Question::new(
            Name::new_unchecked("nx.example.com"),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.name_servers.push(ResourceRecord::new(
            Name::new_unchecked("example.com"),
            CLASS::IN,
            900,
            RData::SOA(simple_dns::rdata::SOA {
                mname: Name::new_unchecked("ns.example.com"),
                rname: Name::new_unchecked("hostmaster.example.com"),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 300,
            }),
        ));
        let bytes = packet.build_bytes_vec().unwrap();
        // min(record TTL 900, SOA minimum 300) = 300.
        assert_eq!(negative_ttl(&bytes), Some(300));

        // A response with no SOA in the authority section yields None.
        let plain = a_response(id, "example.com", &[Ipv4Addr::new(1, 2, 3, 4)]);
        assert_eq!(negative_ttl(&plain), None);
    }

    #[test]
    fn parse_a_no_cname() {
        let (id, _) = make_query("example.com");
        let resp = a_response(id, "example.com", &[Ipv4Addr::new(1, 2, 3, 4)]);
        let (addrs, ttl) = parse_a_addrs(&resp);
        assert_eq!(addrs, [Ipv4Addr::new(1, 2, 3, 4)]);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn parse_a_with_cname_in_response() {
        let (id, _) = make_query("alias.example.com");
        let resp = cname_with_a_response(
            id,
            "alias.example.com",
            "real.example.com",
            &[Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
        );
        let (addrs, _) = parse_a_addrs(&resp);
        assert_eq!(
            addrs,
            [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
    }

    #[test]
    fn parse_a_with_chained_cname() {
        // alias -> middle -> real, A records on real
        let (id, _) = make_query("alias.example.com");
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked("alias.example.com"),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("alias.example.com"),
            CLASS::IN,
            300,
            RData::CNAME(CNAME(Name::new_unchecked("middle.example.com"))),
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("middle.example.com"),
            CLASS::IN,
            300,
            RData::CNAME(CNAME(Name::new_unchecked("real.example.com"))),
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("real.example.com"),
            CLASS::IN,
            300,
            RData::A(A {
                address: u32::from(Ipv4Addr::new(5, 6, 7, 8)),
            }),
        ));
        let resp = packet.build_bytes_vec().unwrap();
        let (addrs, _) = parse_a_addrs(&resp);
        assert_eq!(addrs, [Ipv4Addr::new(5, 6, 7, 8)]);
    }

    #[test]
    fn cname_target_extracts_target_for_recursive_follow() {
        let id = 1234;
        let resp = cname_only_response(id, "alias.example.com", "real.example.com");
        let packet = Packet::parse(&resp).unwrap();
        let target = cname_target(&packet, "alias.example.com");
        assert_eq!(target.as_deref(), Some("real.example.com"));
    }

    /// Builds a reply packet echoing one question for `name`/`qtype`, plus an A
    /// answer, so `check_response` has something to validate.
    fn reply_with_question(id: u16, name: &str, qtype: TYPE) -> Packet<'static> {
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked(name).into_owned(),
            QTYPE::TYPE(qtype),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet
    }

    #[test]
    fn check_response_accepts_a_matching_reply() {
        let name = Name::new_unchecked("example.com");
        let packet = reply_with_question(42, "example.com", TYPE::A);
        assert!(check_response(&packet, 42, &name, TYPE::A).is_ok());
    }

    #[test]
    fn check_response_rejects_mismatches() {
        let name = Name::new_unchecked("example.com");

        // Wrong transaction id.
        let packet = reply_with_question(42, "example.com", TYPE::A);
        assert!(matches!(
            check_response(&packet, 7, &name, TYPE::A),
            Err(QueryError::Unexpected { .. })
        ));

        // Question name does not echo the query.
        let packet = reply_with_question(42, "attacker.example", TYPE::A);
        assert!(matches!(
            check_response(&packet, 42, &name, TYPE::A),
            Err(QueryError::Unexpected { .. })
        ));

        // Question type does not match.
        let packet = reply_with_question(42, "example.com", TYPE::AAAA);
        assert!(matches!(
            check_response(&packet, 42, &name, TYPE::A),
            Err(QueryError::Unexpected { .. })
        ));

        // No question section at all.
        let mut packet = reply_with_question(42, "example.com", TYPE::A);
        packet.questions.clear();
        assert!(matches!(
            check_response(&packet, 42, &name, TYPE::A),
            Err(QueryError::Unexpected { .. })
        ));
    }

    #[test]
    fn cname_target_returns_none_when_no_cname() {
        let id = 1234;
        let resp = a_response(id, "example.com", &[Ipv4Addr::new(1, 2, 3, 4)]);
        let packet = Packet::parse(&resp).unwrap();
        let target = cname_target(&packet, "example.com");
        assert_eq!(target, None);
    }

    /// Builds a reply for `name` carrying a single `rdata` answer, so a parse
    /// test can drive [`parse_records`] against one record of a given kind.
    fn reply_with_answer(name: &str, qtype: TYPE, rdata: RData<'_>) -> Vec<u8> {
        let mut packet = Packet::new_reply(1);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked(name),
            QTYPE::TYPE(qtype),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            300,
            rdata,
        ));
        packet.build_bytes_vec().unwrap()
    }

    #[test]
    fn parse_ns_record() {
        let resp = reply_with_answer(
            "example.com",
            TYPE::NS,
            RData::NS(Name::new_unchecked("ns1.example.com").into()),
        );
        let (records, ttl) = parse_records(&resp, RecordKind::Ns).unwrap();
        assert_eq!(ttl, 300);
        let [Record::Ns(name)] = records.as_slice() else {
            panic!("expected one NS record, got {records:?}");
        };
        assert_eq!(name, "ns1.example.com");
    }

    #[test]
    fn parse_srv_record() {
        let resp = reply_with_answer(
            "_sip._tcp.example.com",
            TYPE::SRV,
            RData::SRV(SRV {
                priority: 10,
                weight: 20,
                port: 5060,
                target: Name::new_unchecked("sip.example.com"),
            }),
        );
        let (records, _) = parse_records(&resp, RecordKind::Srv).unwrap();
        let [Record::Srv(srv)] = records.as_slice() else {
            panic!("expected one SRV record, got {records:?}");
        };
        assert_eq!(srv.priority, 10);
        assert_eq!(srv.weight, 20);
        assert_eq!(srv.port, 5060);
        assert_eq!(srv.target, "sip.example.com");
    }

    #[test]
    fn parse_mx_record() {
        let resp = reply_with_answer(
            "example.com",
            TYPE::MX,
            RData::MX(MX {
                preference: 5,
                exchange: Name::new_unchecked("mail.example.com"),
            }),
        );
        let (records, _) = parse_records(&resp, RecordKind::Mx).unwrap();
        let [Record::Mx(mx)] = records.as_slice() else {
            panic!("expected one MX record, got {records:?}");
        };
        assert_eq!(mx.preference, 5);
        assert_eq!(mx.exchange, "mail.example.com");
    }

    #[test]
    fn parse_caa_record() {
        let resp = reply_with_answer(
            "example.com",
            TYPE::CAA,
            RData::CAA(CAA {
                flag: 0,
                tag: CharacterString::new(b"issue").unwrap(),
                value: b"letsencrypt.org".as_slice().into(),
            }),
        );
        let (records, _) = parse_records(&resp, RecordKind::Caa).unwrap();
        let [Record::Caa(caa)] = records.as_slice() else {
            panic!("expected one CAA record, got {records:?}");
        };
        assert_eq!(caa.flag, 0);
        assert_eq!(caa.tag, "issue");
        assert_eq!(&*caa.value, b"letsencrypt.org");
    }

    /// Builds an SVCB rdata in ServiceMode with the parameters we decode set, so
    /// both the SVCB and HTTPS parse tests can share one endpoint description.
    fn sample_svcb() -> SVCB<'static> {
        let mut svcb = SVCB::new(1, Name::new_unchecked("svc.example.com"));
        svcb.set_alpn(&["h2".try_into().unwrap(), "h3".try_into().unwrap()]);
        svcb.set_port(8443);
        svcb.set_ipv4hint(&[u32::from(Ipv4Addr::new(192, 0, 2, 1))]);
        svcb.set_ipv6hint(&[u128::from(Ipv6Addr::LOCALHOST)]);
        svcb
    }

    fn assert_sample_svcb(svcb: &SvcbRecordData) {
        assert_eq!(svcb.priority(), 1);
        assert_eq!(svcb.target(), "svc.example.com");
        assert_eq!(svcb.alpn(), ["h2", "h3"]);
        assert_eq!(svcb.port(), Some(8443));
        assert_eq!(svcb.ipv4hint(), [Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(svcb.ipv6hint(), [Ipv6Addr::LOCALHOST]);
    }

    #[test]
    fn parse_svcb_record() {
        let resp = reply_with_answer("svc.example.com", TYPE::SVCB, RData::SVCB(sample_svcb()));
        let (records, _) = parse_records(&resp, RecordKind::Svcb).unwrap();
        let [Record::Svcb(svcb)] = records.as_slice() else {
            panic!("expected one SVCB record, got {records:?}");
        };
        assert_sample_svcb(svcb);
    }

    #[test]
    fn parse_https_record() {
        let resp = reply_with_answer(
            "svc.example.com",
            TYPE::HTTPS,
            RData::HTTPS(sample_svcb().into()),
        );
        let (records, _) = parse_records(&resp, RecordKind::Https).unwrap();
        let [Record::Https(https)] = records.as_slice() else {
            panic!("expected one HTTPS record, got {records:?}");
        };
        assert_sample_svcb(https.svcb());
    }

    /// The [`HttpsRecord`] helpers apply the RFC 9460 rules a raw parameter read
    /// would miss: AliasMode vs ServiceMode, the root-target-uses-owner rule
    /// (Section 2.5.2), and the default `http/1.1` ALPN (Sections 7.1.1 and 9.5).
    #[test]
    fn https_record_helpers() {
        // Parse one HTTPS record from raw rdata; the owner is EXAMPLE_WIRE.
        fn https(rdata: &[u8]) -> HttpsRecord {
            let resp = raw_response(TYPE_HTTPS, EXAMPLE_WIRE, EXAMPLE_WIRE, TYPE_HTTPS, rdata);
            let (records, _) = parse_records(&resp, RecordKind::Https).expect("vector parses");
            match records.as_slice() {
                [Record::Https(https)] => https.clone(),
                other => panic!("expected one HTTPS record, got {other:?}"),
            }
        }

        // ServiceMode (priority 1), root target, alpn=[h2]: the default http/1.1
        // is appended, and the root target resolves to the owner name.
        let svc = https(b"\x00\x01\x00\x00\x01\x00\x03\x02h2");
        assert!(svc.is_service() && !svc.is_alias());
        assert_eq!(svc.alpn(), ["h2"]);
        assert_eq!(svc.alpn_protocols(), ["h2", "http/1.1"]);
        assert!(svc.supports_http2());
        assert!(!svc.supports_http3());
        assert_eq!(svc.effective_target(), "example.com");

        // no-default-alpn suppresses the http/1.1 default.
        let no_default = https(b"\x00\x01\x00\x00\x01\x00\x03\x02h2\x00\x02\x00\x00");
        assert!(no_default.no_default_alpn());
        assert_eq!(no_default.alpn_protocols(), ["h2"]);

        // AliasMode (priority 0): no endpoint, so no ALPN; the target is used as-is.
        let alias = https(b"\x00\x00\x03svc\x07example\x03com\x00");
        assert!(alias.is_alias());
        assert!(alias.alpn_protocols().is_empty());
        assert_eq!(alias.effective_target(), "svc.example.com");
    }

    /// The header-peek helpers run on raw, unvalidated bytes before the response
    /// is checked, so a short buffer must return a value rather than panic.
    #[test]
    fn header_helpers_do_not_panic_on_short_input() {
        for data in [&[][..], &[0][..], &[0, 0][..], &[0, 0, 0][..]] {
            assert_eq!(retryable_failure_rcode(data), None);
            assert!(!is_format_error(data));
            assert!(!is_truncated(data));
        }
    }

    /// A TXT record with several character-strings must preserve each one as its
    /// own raw bytes, including binary and `key=value` content, rather than
    /// concatenating them or dropping non-UTF-8 data.
    #[test]
    fn parse_txt_preserves_character_strings() {
        let (id, _) = make_query("example.com");
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked("example.com"),
            QTYPE::TYPE(TYPE::TXT),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        let mut txt = TXT::new();
        txt.add_char_string(CharacterString::new(b"first".as_slice()).unwrap());
        // Contains an `=` (exercises the split-and-rejoin) and a non-UTF-8 byte.
        txt.add_char_string(CharacterString::new(b"k=\xff\x00".as_slice()).unwrap());
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("example.com"),
            CLASS::IN,
            300,
            RData::TXT(txt),
        ));
        let resp = packet.build_bytes_vec().unwrap();

        let (records, _) = parse_records(&resp, RecordKind::Txt).unwrap();
        let [Record::Txt(data)] = records.as_slice() else {
            panic!("expected one TXT record, got {records:?}");
        };
        let strings: Vec<&[u8]> = data.iter().collect();
        assert_eq!(strings, [b"first".as_slice(), b"k=\xff\x00".as_slice()]);
    }

    /// The `example.com` owner name in wire form, used by the hand-assembled
    /// packets below for both the question and the single answer.
    const EXAMPLE_WIRE: &[u8] = b"\x07example\x03com\x00";

    /// SVCB and HTTPS record type codes (RFC 9460 Section 14.1 and 14.2).
    const TYPE_SVCB: u16 = 64;
    const TYPE_HTTPS: u16 = 65;

    /// Assembles a minimal DNS response with one question and one answer, giving
    /// a test full control over the answer's raw name bytes, type, and rdata.
    ///
    /// The builder in `simple_dns` will not emit malformed or non-canonical wire
    /// forms, so tests that need RFC Appendix D rdata vectors, a wrong rdlength,
    /// or a specific compression pointer assemble the bytes here and feed them
    /// straight through [`parse_records`].
    fn raw_response(
        qtype: u16,
        question_name: &[u8],
        answer_name: &[u8],
        rtype: u16,
        rdata: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header: id, flags (QR set), then qd=1, an=1, ns=0, ar=0.
        buf.extend_from_slice(&0x1234u16.to_be_bytes());
        buf.extend_from_slice(&0x8000u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        // Question section.
        buf.extend_from_slice(question_name);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        // Answer section.
        buf.extend_from_slice(answer_name);
        buf.extend_from_slice(&rtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        buf.extend_from_slice(&300u32.to_be_bytes()); // TTL
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(rdata);
        buf
    }

    /// Wraps a raw SVCB or HTTPS rdata vector in a one-answer response and returns
    /// the parsed record data, so the RFC 9460 Appendix D vectors drive straight
    /// through [`parse_records`].
    fn parse_svcb_vector(rtype: u16, kind: RecordKind, rdata: &[u8]) -> SvcbRecordData {
        let resp = raw_response(rtype, EXAMPLE_WIRE, EXAMPLE_WIRE, rtype, rdata);
        let (records, _) = parse_records(&resp, kind).expect("vector should parse");
        match records.as_slice() {
            [Record::Svcb(svcb)] => svcb.clone(),
            [Record::Https(https)] => https.svcb().clone(),
            other => panic!("expected one SVCB/HTTPS record, got {other:?}"),
        }
    }

    /// RFC 9460 Appendix D.1: an AliasMode record has priority 0, a target, and
    /// no parameters.
    #[test]
    fn parse_svcb_aliasmode_vector() {
        let svcb = parse_svcb_vector(
            TYPE_SVCB,
            RecordKind::Svcb,
            b"\x00\x00\x03foo\x07example\x03com\x00",
        );
        assert_eq!(svcb.priority(), 0);
        assert_eq!(svcb.target(), "foo.example.com");
        assert!(svcb.alpn().is_empty());
        assert_eq!(svcb.port(), None);
        assert!(svcb.ipv4hint().is_empty());
        assert!(svcb.ipv6hint().is_empty());
    }

    /// RFC 9460 Appendix D.2.3: a ServiceMode record whose target is the root,
    /// which surfaces as an empty target string.
    #[test]
    fn parse_svcb_root_target_vector() {
        let svcb = parse_svcb_vector(TYPE_SVCB, RecordKind::Svcb, b"\x00\x01\x00");
        assert_eq!(svcb.priority(), 1);
        assert_eq!(svcb.target(), "");
    }

    /// RFC 9460 Appendix D.2.4: a record carrying only the `port` parameter.
    #[test]
    fn parse_svcb_port_vector() {
        let svcb = parse_svcb_vector(
            TYPE_SVCB,
            RecordKind::Svcb,
            b"\x00\x10\x03foo\x07example\x03com\x00\x00\x03\x00\x02\x00\x35",
        );
        assert_eq!(svcb.priority(), 16);
        assert_eq!(svcb.target(), "foo.example.com");
        assert_eq!(svcb.port(), Some(53));
    }

    /// The same D.2.4 vector must parse identically through the HTTPS path, which
    /// reuses the SVCB rdata.
    #[test]
    fn parse_https_port_vector() {
        let https = parse_svcb_vector(
            TYPE_HTTPS,
            RecordKind::Https,
            b"\x00\x10\x03foo\x07example\x03com\x00\x00\x03\x00\x02\x00\x35",
        );
        assert_eq!(https.priority(), 16);
        assert_eq!(https.port(), Some(53));
    }

    /// RFC 9460 Appendix D.2.7: two IPv6 hints.
    #[test]
    fn parse_svcb_ipv6hint_vector() {
        let svcb = parse_svcb_vector(
            TYPE_SVCB,
            RecordKind::Svcb,
            b"\x00\x01\x03foo\x07example\x03com\x00\x00\x06\x00\x20\
              \x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\
              \x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x53\x00\x01",
        );
        assert_eq!(svcb.priority(), 1);
        assert_eq!(svcb.target(), "foo.example.com");
        assert_eq!(
            svcb.ipv6hint(),
            [
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0x0053, 1),
            ]
        );
    }

    /// RFC 9460 Appendix D.2.10: `mandatory`, `alpn`, and `ipv4hint` together,
    /// stored out of presentation order but sorted on the wire.
    #[test]
    fn parse_svcb_mandatory_alpn_ipv4hint_vector() {
        let svcb = parse_svcb_vector(
            TYPE_SVCB,
            RecordKind::Svcb,
            b"\x00\x10\x03foo\x07example\x03org\x00\
              \x00\x00\x00\x04\x00\x01\x00\x04\
              \x00\x01\x00\x09\x02h2\x05h3-19\
              \x00\x04\x00\x04\xc0\x00\x02\x01",
        );
        assert_eq!(svcb.priority(), 16);
        assert_eq!(svcb.target(), "foo.example.org");
        assert_eq!(svcb.alpn(), ["h2", "h3-19"]);
        assert_eq!(svcb.ipv4hint(), [Ipv4Addr::new(192, 0, 2, 1)]);
    }

    /// `simple_dns` rejects SvcParamKeys that are not strictly ascending on the
    /// wire (RFC 9460 Section 2.2). Such a packet must surface as a clean parse
    /// error rather than panicking.
    #[test]
    fn parse_svcb_out_of_order_params_is_malformed() {
        // Priority 1, root target, then `port` (key 3) before `alpn` (key 1).
        let rdata = b"\x00\x01\x00\
                      \x00\x03\x00\x02\x00\x35\
                      \x00\x01\x00\x09\x02h2\x05h3-19";
        let resp = raw_response(TYPE_SVCB, EXAMPLE_WIRE, EXAMPLE_WIRE, TYPE_SVCB, rdata);
        assert!(matches!(
            parse_records(&resp, RecordKind::Svcb),
            Err(QueryError::Malformed { .. })
        ));
    }

    /// An A answer whose rdlength is 3 rather than 4 is malformed. It must yield a
    /// clean parse error, not a panic on a short read.
    #[test]
    fn parse_a_with_short_rdata_is_malformed() {
        let resp = raw_response(
            u16::from(TYPE::A),
            EXAMPLE_WIRE,
            EXAMPLE_WIRE,
            u16::from(TYPE::A),
            b"\x01\x02\x03",
        );
        assert!(matches!(
            parse_records(&resp, RecordKind::A),
            Err(QueryError::Malformed { .. })
        ));
    }

    /// An answer whose owner name is a compression pointer to the question name
    /// resolves to that name, so the record is matched and returned.
    #[test]
    fn parse_a_with_compression_pointer_resolves() {
        // The question name begins at offset 12, right after the fixed header.
        let pointer = (0xc000u16 | 12u16).to_be_bytes();
        let resp = raw_response(
            u16::from(TYPE::A),
            EXAMPLE_WIRE,
            &pointer,
            u16::from(TYPE::A),
            &[10, 0, 0, 7],
        );
        let (addrs, _) = parse_a_addrs(&resp);
        assert_eq!(addrs, [Ipv4Addr::new(10, 0, 0, 7)]);
    }

    /// A self-referential compression pointer must be rejected as a clean parse
    /// error. `simple_dns` only follows strictly-backward pointers, so a pointer
    /// to its own offset fails without looping.
    #[test]
    fn parse_a_with_circular_pointer_is_malformed() {
        // The answer name sits right after the 12-byte header and the question
        // (name + qtype + qclass); point it at its own offset.
        let answer_offset = 12 + EXAMPLE_WIRE.len() + 4;
        let pointer = (0xc000u16 | answer_offset as u16).to_be_bytes();
        let resp = raw_response(
            u16::from(TYPE::A),
            EXAMPLE_WIRE,
            &pointer,
            u16::from(TYPE::A),
            &[10, 0, 0, 7],
        );
        assert!(matches!(
            parse_records(&resp, RecordKind::A),
            Err(QueryError::Malformed { .. })
        ));
    }

    /// A record attached to an intermediate name in the CNAME chain (not the
    /// query name or the final canonical name) must still be collected, matching
    /// how recursive resolvers extract from the whole chain.
    #[test]
    fn parse_collects_records_on_intermediate_cname_name() {
        let (id, _) = make_query("alias.example.com");
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked("alias.example.com"),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("alias.example.com"),
            CLASS::IN,
            300,
            RData::CNAME(CNAME(Name::new_unchecked("middle.example.com"))),
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("middle.example.com"),
            CLASS::IN,
            300,
            RData::CNAME(CNAME(Name::new_unchecked("real.example.com"))),
        ));
        // The A record sits on the intermediate `middle`, not the final `real`.
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("middle.example.com"),
            CLASS::IN,
            300,
            RData::A(A {
                address: u32::from(Ipv4Addr::new(9, 9, 9, 9)),
            }),
        ));
        let resp = packet.build_bytes_vec().unwrap();

        let (addrs, _) = parse_a_addrs(&resp);
        assert_eq!(addrs, [Ipv4Addr::new(9, 9, 9, 9)]);
    }

    /// The SVCB accessors surface the ECH config, the mandatory key list, and the
    /// no-default-alpn flag.
    #[test]
    fn svcb_exposes_ech_mandatory_and_no_default_alpn() {
        use simple_dns::rdata::{SVCB, SVCParam};

        let mut svcb = SVCB::new(1, Name::new_unchecked("svc.example.com"));
        svcb.set_alpn(&["h2".try_into().unwrap()]);
        svcb.set_mandatory([1u16].into_iter());
        svcb.set_no_default_alpn();
        svcb.set_param(SVCParam::Ech(std::borrow::Cow::Borrowed(
            b"echconfig".as_slice(),
        )));
        let resp = reply_with_answer("svc.example.com", TYPE::SVCB, RData::SVCB(svcb));

        let (records, _) = parse_records(&resp, RecordKind::Svcb).unwrap();
        let [Record::Svcb(data)] = records.as_slice() else {
            panic!("expected one SVCB record, got {records:?}");
        };
        assert_eq!(data.mandatory(), vec![1]);
        assert!(data.no_default_alpn());
        assert_eq!(data.ech().as_deref(), Some(b"echconfig".as_slice()));
    }

    /// `into_boxed_slices` hands over the character strings without copying.
    #[test]
    fn txt_into_boxed_slices_hands_over_storage() {
        let data = TxtRecordData::from(vec![
            b"a".to_vec().into_boxed_slice(),
            b"bb".to_vec().into_boxed_slice(),
        ]);
        let slices = data.into_boxed_slices();
        assert_eq!(slices.len(), 2);
        assert_eq!(&*slices[0], b"a");
        assert_eq!(&*slices[1], b"bb");
    }

    /// A short-TTL CNAME in the chain bounds the returned min TTL, so the alias
    /// is not cached past the CNAME's intended lifetime even when the final
    /// records carry a longer TTL.
    #[test]
    fn cname_ttl_bounds_the_min_ttl() {
        let (id, _) = make_query("alias.example.com");
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked("alias.example.com"),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("alias.example.com"),
            CLASS::IN,
            50,
            RData::CNAME(CNAME(Name::new_unchecked("real.example.com"))),
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("real.example.com"),
            CLASS::IN,
            300,
            RData::A(A {
                address: u32::from(Ipv4Addr::new(1, 2, 3, 4)),
            }),
        ));
        let resp = packet.build_bytes_vec().unwrap();

        let (records, ttl) = parse_records(&resp, RecordKind::A).unwrap();
        assert_eq!(ttl, 50);
        assert_eq!(records.len(), 1);
    }
}
