//! End-to-end resolver scenarios ported from hickory-resolver, driven through
//! the public API against a mock UDP nameserver.

use std::net::Ipv4Addr;

use simple_dns::RCODE;

use super::{a, caa, cname, mx, ns, qname, reply, resolver_for, spawn_mock, srv, txt};
use crate::{Record, RecordKind};

/// A CNAME that only the second query resolves: the first response carries the
/// CNAME alone, so the resolver follows it and queries the target name, which
/// then answers with an address.
///
/// Modeled on hickory-resolver `caching_client.rs::test_multi_hop_cname_preserves_final_sections`,
/// which walks a CNAME chain to the record at its end.
#[tokio::test]
async fn cname_chain_resolves_across_hops() {
    let server = spawn_mock(|query| {
        let name = qname(query)?;
        let answers = match name.as_str() {
            "alias.example" => vec![cname("alias.example", "target.example")],
            "target.example" => vec![a("target.example", Ipv4Addr::new(10, 0, 0, 1))],
            _ => return Some(reply(query, RCODE::NameError, vec![])),
        };
        Some(reply(query, RCODE::NoError, answers))
    })
    .await;

    let resolver = resolver_for(server.addr());
    let addrs: Vec<_> = resolver
        .lookup_ipv4("alias.example".to_string())
        .await
        .expect("alias resolves across the CNAME hop")
        .collect();

    assert_eq!(addrs, [Ipv4Addr::new(10, 0, 0, 1)]);
    assert_eq!(server.query_count(), 2, "one query per CNAME hop");
}

/// A record attached to an intermediate name in the CNAME chain, not the query
/// name or the final canonical name, is still collected, the way a recursive
/// resolver extracts from the whole chain in a single response.
///
/// Modeled on hickory-resolver `caching_client.rs::test_multi_hop_cname_preserves_final_sections`,
/// exercised end-to-end.
#[tokio::test]
async fn records_attach_to_intermediate_cname_name() {
    let server = spawn_mock(|query| {
        Some(reply(
            query,
            RCODE::NoError,
            vec![
                cname("alias.example", "middle.example"),
                cname("middle.example", "real.example"),
                // The A record sits on the intermediate name, not on `real`.
                a("middle.example", Ipv4Addr::new(9, 9, 9, 9)),
            ],
        ))
    })
    .await;

    let resolver = resolver_for(server.addr());
    let addrs: Vec<_> = resolver
        .lookup_ipv4("alias.example".to_string())
        .await
        .expect("intermediate-name record resolves")
        .collect();

    assert_eq!(addrs, [Ipv4Addr::new(9, 9, 9, 9)]);
    assert_eq!(
        server.query_count(),
        1,
        "the whole chain is in one response"
    );
}

/// A NoError response with no matching records is NODATA: the name exists but
/// has no records of the requested kind, so the lookup returns an empty result
/// rather than an error.
///
/// Modeled on hickory-resolver `caching_client.rs::test_empty_cache`, where an
/// empty answer surfaces as a no-records outcome under NoError.
#[tokio::test]
async fn nodata_answer_returns_empty_result() {
    let server = spawn_mock(|query| Some(reply(query, RCODE::NoError, vec![]))).await;

    let resolver = resolver_for(server.addr());
    let records = resolver
        .lookup_record("empty.example".to_string(), RecordKind::A)
        .await
        .expect("NODATA is an empty result, not an error");

    assert!(records.is_empty());
}

/// A negative (NODATA) result is cached, so a second lookup for the same name is
/// served from the cache and never reaches the nameserver.
///
/// Modeled on hickory-resolver `caching_client.rs::test_from_cache`, where a
/// cached result answers the second lookup without another query.
#[tokio::test]
async fn negative_caching_collapses_second_lookup() {
    let server = spawn_mock(|query| Some(reply(query, RCODE::NoError, vec![]))).await;

    let resolver = resolver_for(server.addr());
    for _ in 0..2 {
        let records = resolver
            .lookup_record("nodata.example".to_string(), RecordKind::A)
            .await
            .expect("NODATA is an empty result");
        assert!(records.is_empty());
    }

    assert_eq!(
        server.query_count(),
        1,
        "the second lookup is served from the negative cache"
    );
}

/// Search-list expansion walks the search domains, skips a suffix that does not
/// resolve, and falls through to the bare name, which answers.
///
/// Modeled on hickory-resolver `resolver.rs::search_list_test`, which loops over
/// the search list past a non-resolving suffix to reach a name that answers.
#[tokio::test]
async fn search_list_expansion_reaches_bare_name() {
    let server = spawn_mock(|query| {
        let name = qname(query)?;
        if name == "myhost" {
            Some(reply(
                query,
                RCODE::NoError,
                vec![a("myhost", Ipv4Addr::new(10, 1, 1, 1))],
            ))
        } else {
            // The `myhost.search.invalid` expansion does not exist.
            Some(reply(query, RCODE::NameError, vec![]))
        }
    })
    .await;

    let mut resolver = resolver_for(server.addr());
    // A short name (no dots, under ndots) tries the search suffix first, then the
    // bare name; only the bare name resolves here.
    resolver.set_search(vec!["search.invalid".to_string()], 1);

    let addrs: Vec<_> = resolver
        .lookup_ipv4("myhost".to_string())
        .await
        .expect("resolves via the bare name after the search suffix fails")
        .collect();

    assert_eq!(addrs, [Ipv4Addr::new(10, 1, 1, 1)]);
}

/// When the intended (bare) name is NXDOMAIN but an appended search candidate
/// is NODATA, the bare name's NXDOMAIN wins. The first authoritative negative in
/// search order is the answer, so an appended candidate's empty result never
/// masks a name that genuinely does not exist.
///
/// Guards the negative-answer precedence in [`DnsResolver::lookup_record`]
/// against a regression found in adversarial review, where any NODATA across the
/// search list overrode an NXDOMAIN of the queried name.
///
/// [`DnsResolver::lookup_record`]: crate::DnsResolver::lookup_record
#[tokio::test]
async fn bare_nxdomain_wins_over_appended_nodata() {
    let server = spawn_mock(|query| {
        let name = qname(query)?;
        // The bare name does not exist; the appended search name exists with no
        // records of this kind (NODATA, a NoError reply with no answers).
        let rcode = if name == "host.example" {
            RCODE::NameError
        } else {
            RCODE::NoError
        };
        Some(reply(query, rcode, vec![]))
    })
    .await;

    let mut resolver = resolver_for(server.addr());
    // Two labels exceed ndots, so the bare name is tried first, then the suffix.
    resolver.set_search(vec!["corp.local".to_string()], 1);

    let result = resolver
        .lookup_record("host.example".to_string(), RecordKind::A)
        .await;

    assert!(
        matches!(result, Err(crate::Error::NxDomain { .. })),
        "the bare NXDOMAIN must win over the appended NODATA, got {result:?}",
    );
}

/// A transient failure (SERVFAIL) on one search candidate must not let a later
/// candidate's negative answer be cached: we never learned whether the flaky
/// name exists, so pinning the queried name as absent would suppress it once the
/// failure clears. The second lookup must reach the network again.
///
/// Guards the no-cache-on-indeterminate rule in
/// [`DnsResolver::lookup_record`], added after adversarial review.
///
/// [`DnsResolver::lookup_record`]: crate::DnsResolver::lookup_record
#[tokio::test]
async fn transient_failure_blocks_negative_caching() {
    let server = spawn_mock(|query| {
        let name = qname(query)?;
        // The appended candidate fails indeterminately; the bare name is NXDOMAIN.
        let rcode = if name == "host.flaky" {
            RCODE::ServerFailure
        } else {
            RCODE::NameError
        };
        Some(reply(query, rcode, vec![]))
    })
    .await;

    let mut resolver = resolver_for(server.addr());
    // A single label is under ndots, so the search suffix is tried first.
    resolver.set_search(vec!["flaky".to_string()], 1);

    let first = resolver
        .lookup_record("host".to_string(), RecordKind::A)
        .await;
    assert!(matches!(first, Err(crate::Error::NxDomain { .. })));
    let after_first = server.query_count();

    let second = resolver
        .lookup_record("host".to_string(), RecordKind::A)
        .await;
    assert!(matches!(second, Err(crate::Error::NxDomain { .. })));

    assert!(
        server.query_count() > after_first,
        "a transient failure must leave the negative uncached, forcing a re-query",
    );
}

/// An SRV lookup returns the parsed priority, weight, port, and target.
///
/// Modeled on hickory-resolver `caching_client.rs::test_non_recursive_srv_query`.
#[tokio::test]
async fn srv_lookup_end_to_end() {
    let server = spawn_mock(|query| {
        Some(reply(
            query,
            RCODE::NoError,
            vec![srv("_sip._tcp.example", 10, 20, 5060, "sip.example")],
        ))
    })
    .await;

    let resolver = resolver_for(server.addr());
    let records = resolver
        .lookup_record("_sip._tcp.example".to_string(), RecordKind::Srv)
        .await
        .expect("SRV resolves");

    let [Record::Srv(data)] = records.as_slice() else {
        panic!("expected one SRV record, got {records:?}");
    };
    assert_eq!(data.priority, 10);
    assert_eq!(data.weight, 20);
    assert_eq!(data.port, 5060);
    assert_eq!(data.target, "sip.example");
}

/// An MX lookup returns the parsed preference and exchange.
///
/// Exercises RFC 1035 Section 3.3.9 (MX RDATA) end-to-end through
/// [`DnsResolver::lookup_record`].
///
/// [`DnsResolver::lookup_record`]: crate::DnsResolver::lookup_record
#[tokio::test]
async fn mx_lookup_end_to_end() {
    let server = spawn_mock(|query| {
        Some(reply(
            query,
            RCODE::NoError,
            vec![mx("example", 5, "mail.example")],
        ))
    })
    .await;

    let resolver = resolver_for(server.addr());
    let records = resolver
        .lookup_record("example".to_string(), RecordKind::Mx)
        .await
        .expect("MX resolves");

    let [Record::Mx(data)] = records.as_slice() else {
        panic!("expected one MX record, got {records:?}");
    };
    assert_eq!(data.preference, 5);
    assert_eq!(data.exchange, "mail.example");
}

/// A CAA lookup returns the flag, tag, and raw value as they appear on the wire.
///
/// Exercises RFC 8659 (CAA RDATA) end-to-end through
/// [`DnsResolver::lookup_record`].
///
/// [`DnsResolver::lookup_record`]: crate::DnsResolver::lookup_record
#[tokio::test]
async fn caa_lookup_end_to_end() {
    let server = spawn_mock(|query| {
        Some(reply(
            query,
            RCODE::NoError,
            vec![caa("example", 0, "issue", b"letsencrypt.org")],
        ))
    })
    .await;

    let resolver = resolver_for(server.addr());
    let records = resolver
        .lookup_record("example".to_string(), RecordKind::Caa)
        .await
        .expect("CAA resolves");

    let [Record::Caa(data)] = records.as_slice() else {
        panic!("expected one CAA record, got {records:?}");
    };
    assert_eq!(data.flag, 0);
    assert_eq!(data.tag, "issue");
    assert_eq!(&*data.value, b"letsencrypt.org");
}

/// An NS lookup returns the nameserver name via the generic
/// [`DnsResolver::lookup_record`] path.
///
/// Modeled on hickory-resolver `caching_client.rs::test_single_ns_query_response`.
///
/// [`DnsResolver::lookup_record`]: crate::DnsResolver::lookup_record
#[tokio::test]
async fn ns_lookup_end_to_end() {
    let server = spawn_mock(|query| {
        Some(reply(
            query,
            RCODE::NoError,
            vec![ns("example", "ns1.example")],
        ))
    })
    .await;

    let resolver = resolver_for(server.addr());
    let records = resolver
        .lookup_record("example".to_string(), RecordKind::Ns)
        .await
        .expect("NS resolves");

    let [Record::Ns(name)] = records.as_slice() else {
        panic!("expected one NS record, got {records:?}");
    };
    assert_eq!(name, "ns1.example");
}

/// A TXT lookup preserves each character-string of the record as its own bytes,
/// rather than concatenating them, matching the RFC 1035 Section 3.3.14 model of
/// a TXT record as a list of character-strings.
#[tokio::test]
async fn txt_lookup_preserves_character_strings() {
    let server = spawn_mock(|query| {
        Some(reply(
            query,
            RCODE::NoError,
            vec![txt("txt.example", &[b"v=spf1", b"-all"])],
        ))
    })
    .await;

    let resolver = resolver_for(server.addr());
    let records: Vec<_> = resolver
        .lookup_txt("txt.example".to_string())
        .await
        .expect("TXT resolves")
        .collect();

    assert_eq!(records.len(), 1);
    let strings: Vec<Vec<u8>> = records[0].iter().map(<[u8]>::to_vec).collect();
    assert_eq!(strings, [b"v=spf1".to_vec(), b"-all".to_vec()]);
}
