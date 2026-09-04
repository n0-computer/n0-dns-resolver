//! Side-by-side lookups against iroh's hickory glue, using mock nameservers.
//!
//! Happy-path A/AAAA/TXT answers already match (see the `compare_iroh_lookups`
//! example). These tests pin the remaining differences.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE,
    rdata::{A, RData},
};

use super::{a, qname, reply, spawn_mock};
use crate::{DnsProtocol, DnsResolver, Error, InvalidResponseReason, Nameserver};

const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);
const NAME: &str = "test.example";

/// iroh's hickory construction: explicit nameservers, no system config, no
/// query-time public fallback, negatives not cached.
fn iroh_hickory(addrs: impl IntoIterator<Item = SocketAddr>) -> TokioResolver {
    let mut config = ResolverConfig::default();
    for addr in addrs {
        let mut transport = ConnectionConfig::udp();
        transport.port = addr.port();
        config.add_name_server(NameServerConfig::new(addr.ip(), false, vec![transport]));
    }
    let mut options = ResolverOpts::default();
    options.negative_max_ttl = Some(Duration::ZERO);
    options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6;
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    *builder.options_mut() = options;
    builder.build().expect("hickory config works")
}

async fn n0_ipv4(resolver: &DnsResolver) -> Result<Vec<Ipv4Addr>, crate::Error> {
    resolver
        .lookup_ipv4(NAME.to_string())
        .await
        .map(Iterator::collect)
}

async fn hickory_ipv4(resolver: &TokioResolver) -> Result<Vec<Ipv4Addr>, String> {
    match resolver.ipv4_lookup(NAME).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::A(addr) => Some(addr.0),
                _ => None,
            })
            .collect()),
        Err(err) => Err(err.to_string()),
    }
}

/// When the primary nameserver SERVFAILs, this crate escalates to its fallback
/// tier and still answers. iroh's hickory glue does not: it only adds Google
/// when system config cannot be read, never after a failed query.
#[tokio::test]
async fn fallback_answers_after_primary_servfail() {
    let bad = spawn_mock(|query| Some(reply(query, RCODE::ServerFailure, vec![]))).await;
    let good = spawn_mock(|query| Some(reply(query, RCODE::NoError, vec![a(NAME, ANSWER)]))).await;

    let n0 = DnsResolver::builder()
        .without_system_defaults()
        .nameserver(bad.addr(), DnsProtocol::Udp)
        .fallback_nameservers([Nameserver::new(good.addr(), DnsProtocol::Udp)])
        .build();
    let n0_addrs = n0_ipv4(&n0).await.expect("n0-dns should use the fallback");
    assert_eq!(n0_addrs, [ANSWER]);

    let hickory = iroh_hickory([bad.addr()]);
    let hickory_res = hickory_ipv4(&hickory).await;
    assert!(
        hickory_res.is_err(),
        "iroh hickory has no query-time fallback, got {hickory_res:?}"
    );
}

/// `reset` keeps cached positives, so a second lookup after a network-change
/// rebuild does not hit the nameserver. iroh's hickory glue builds a new
/// resolver and starts cold.
#[tokio::test]
async fn reset_keeps_positive_cache() {
    let expected = ANSWER;
    let n0_server =
        spawn_mock(move |query| Some(reply(query, RCODE::NoError, vec![a(NAME, expected)]))).await;
    let n0 = DnsResolver::builder()
        .without_system_defaults()
        .disable_fallback()
        .nameserver(n0_server.addr(), DnsProtocol::Udp)
        .build();
    assert_eq!(n0_ipv4(&n0).await.unwrap(), [expected]);
    let n0_after_first = n0_server.query_count();
    let n0 = n0.reset();
    assert_eq!(n0_ipv4(&n0).await.unwrap(), [expected]);
    assert_eq!(
        n0_server.query_count(),
        n0_after_first,
        "n0-dns reset should serve the cached answer"
    );

    let hickory_server =
        spawn_mock(move |query| Some(reply(query, RCODE::NoError, vec![a(NAME, expected)]))).await;
    let hickory = iroh_hickory([hickory_server.addr()]);
    assert_eq!(hickory_ipv4(&hickory).await.unwrap(), [expected]);
    let hickory_after_first = hickory_server.query_count();
    let hickory = iroh_hickory([hickory_server.addr()]);
    assert_eq!(hickory_ipv4(&hickory).await.unwrap(), [expected]);
    assert!(
        hickory_server.query_count() > hickory_after_first,
        "iroh hickory reset is a new resolver with an empty cache"
    );
}

/// A nameserver that echoes the question in a different case is accepted by
/// hickory (RFC 4343) and rejected here: name comparison is case-sensitive.
#[tokio::test]
async fn case_folded_question_is_rejected_here() {
    let server = spawn_mock(|query| {
        let question = query.questions.first()?;
        let upper = question.qname.to_string().to_ascii_uppercase();
        let mut packet = Packet::new_reply(query.id());
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        *packet.rcode_mut() = RCODE::NoError;
        packet.questions.push(Question::new(
            Name::new_unchecked(&upper).into_owned(),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked(NAME).into_owned(),
            CLASS::IN,
            300,
            RData::A(A {
                address: u32::from(ANSWER),
            }),
        ));
        Some(packet.build_bytes_vec().expect("reply builds"))
    })
    .await;

    let n0 = DnsResolver::builder()
        .without_system_defaults()
        .disable_fallback()
        .nameserver(server.addr(), DnsProtocol::Udp)
        .build();
    let n0_res = n0_ipv4(&n0).await;
    assert!(
        matches!(
            n0_res,
            Err(Error::InvalidResponse {
                reason: InvalidResponseReason::QuestionMismatch,
                ..
            })
        ),
        "n0-dns should reject a case-folded question, got {n0_res:?}"
    );

    let hickory = iroh_hickory([server.addr()]);
    let hickory_addrs = hickory_ipv4(&hickory)
        .await
        .expect("hickory should accept a case-folded question");
    assert_eq!(hickory_addrs, [ANSWER]);
}

/// Sanity: when the nameserver echoes the question as sent, both resolvers
/// return the same address (the live example covers public names).
#[tokio::test]
async fn matching_question_case_agrees() {
    let server = spawn_mock(|query| {
        let name = qname(query).unwrap_or_default();
        Some(reply(query, RCODE::NoError, vec![a(&name, ANSWER)]))
    })
    .await;

    let n0 = DnsResolver::builder()
        .without_system_defaults()
        .disable_fallback()
        .nameserver(server.addr(), DnsProtocol::Udp)
        .build();
    let hickory = iroh_hickory([server.addr()]);

    assert_eq!(n0_ipv4(&n0).await.unwrap(), [ANSWER]);
    assert_eq!(hickory_ipv4(&hickory).await.unwrap(), [ANSWER]);
}
