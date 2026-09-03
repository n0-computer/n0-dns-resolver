//! Compares this crate against hickory-resolver on links that lose UDP.
//!
//! Each test builds a two-device patchbay lab: one device runs a small
//! authoritative nameserver that answers over both UDP and TCP, the other runs
//! both resolvers against it. Only the loss mechanism differs between tests.
//!
//! Loss is introduced in one of two places. [`UdpPolicy`] makes the nameserver
//! itself discard datagrams, which is deterministic and isolates retransmit
//! pacing from everything else. `netem` on the client's uplink drops datagrams
//! at random, which is closer to a real link but noisy. The deterministic tests
//! are the ones to read when comparing the two resolvers; the random one exists
//! to confirm the deterministic result is not an artifact of the drop policy.
//!
//! Each test prints a table and asserts what we want to stay true: that a
//! lookup returning an answer returns the right one, that our latency holds
//! against hickory's on the two deterministic scenarios, and that a healthy
//! network still costs exactly one datagram per lookup. The random-loss test
//! only reports, since its numbers move between runs.
//!
//! The table carries latency and, beside it, the queries the nameserver
//! received per lookup split by transport. Retransmitting early trades packets
//! for latency, so both halves of that trade are measured. The counts are what
//! one nameserver saw; the fan-out across several is not measured here.
//!
//! Run them with:
//!
//! ```sh
//! cargo nextest run --test patchbay_lossy --no-capture
//! ```
//!
//! patchbay needs Linux user namespaces. It runs rootless; no `sudo` is
//! involved.

#![cfg(target_os = "linux")]

use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    proto::rr::RData as HickoryRData,
};
use n0_dns_resolver::{DnsProtocol, DnsResolver, Nameserver};
use patchbay::{Lab, LinkCondition, LinkDirection, TestGuard};
use simple_dns::{
    CLASS, Packet, PacketFlag, QTYPE, ResourceRecord, TYPE,
    rdata::{A, RData},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

/// Initializes the user namespace before any thread is spawned.
///
/// patchbay needs this to run rootless, and it has to happen while the process
/// is still single-threaded. This runs from ELF `.init_array`, before the Rust
/// runtime is up, so it uses patchbay's libc-only entry point rather than
/// `init_userns`: the latter allocates and returns a `Result` that could only be
/// reported by panicking, which is not something this context can do. A failure
/// here is silent by design and surfaces in [`fixture`], where it can be
/// explained.
#[ctor::ctor(unsafe)]
fn userns_ctor() {
    unsafe { patchbay::init_userns_for_ctor() };
}

/// The address every A query is answered with.
const ANSWER: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);

/// TTL on the answers, long enough that no lookup in a test re-queries.
const ANSWER_TTL: u32 = 300;

/// Ceiling on our own median in the scenarios that lose datagrams.
///
/// Those are floored either at two retransmit intervals or, where UDP never
/// answers at all, at the resolver's 900ms delay before TCP starts. The bound is
/// deliberately well clear of both: it exists to catch a return to the
/// six-second behaviour, not to pin the exact delay, and a tight bound would
/// flake whenever a loaded runner adds scheduling latency.
const LATENCY_CEILING: Duration = Duration::from_millis(1500);

/// Cap on a single lookup, past which we record it as a failure.
///
/// Above our own worst case for one nameserver (6 s covering the datagrams and
/// the TCP query beside them) and above hickory's (two pool passes of 5 s), so
/// a lookup only hits this when the resolver has stopped making progress.
const LOOKUP_CAP: Duration = Duration::from_secs(15);

// ── The test nameserver ─────────────────────────────────────────────────

/// How the test nameserver treats incoming UDP datagrams.
///
/// TCP is always answered, matching the middlebox behavior we care about:
/// UDP/53 is the transport that gets dropped, TCP/53 keeps working.
#[derive(Debug, Clone, Copy)]
enum UdpPolicy {
    /// Answers every datagram.
    Answer,
    /// Drops the first `n` datagrams of each transaction, then answers.
    ///
    /// Both resolvers reuse one transaction id across the retransmits of a
    /// single query, so `n` counts datagrams within a lookup rather than across
    /// lookups. `DropFirst(1)` therefore discards a lookup's opening datagram
    /// and answers its first retransmit, and the gap between the two is the
    /// retransmit interval we are measuring.
    DropFirst(u32),
    /// Never answers over UDP.
    Blackhole,
}

impl UdpPolicy {
    /// Returns whether to discard a datagram carrying transaction id `id`.
    ///
    /// `seen` counts the datagrams already received per transaction id.
    fn drops(&self, id: u16, seen: &Mutex<HashMap<u16, u32>>) -> bool {
        match self {
            Self::Answer => false,
            Self::Blackhole => true,
            Self::DropFirst(n) => {
                let mut seen = seen.lock().expect("poisoned");
                let count = seen.entry(id).or_insert(0);
                *count += 1;
                *count <= *n
            }
        }
    }
}

/// Builds a reply to `query`: the echoed question plus one A record.
///
/// Any name is answered with [`ANSWER`], so a test can use a fresh name for
/// every lookup to step around both resolvers' caches without registering each
/// one first. A query for anything other than A gets an empty NOERROR.
///
/// Returns `None` for a query we cannot answer, such as one with no question.
fn build_reply(query: &Packet<'_>) -> Option<Vec<u8>> {
    let question = query.questions.first()?;
    let mut reply = Packet::new_reply(query.id());
    reply.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
    reply.questions.push(question.clone());
    if question.qtype == QTYPE::TYPE(TYPE::A) {
        reply.answers.push(ResourceRecord::new(
            question.qname.clone(),
            CLASS::IN,
            ANSWER_TTL,
            RData::A(A {
                address: u32::from(ANSWER),
            }),
        ));
    }
    reply.build_bytes_vec().ok()
}

/// Queries the test nameserver received, per resolver.
///
/// Indexed the way [`run_rounds`] orders its samples: 0 is this crate, 1 is
/// hickory. The nameserver attributes each query by the name asked for, since
/// [`run_rounds`] gives the two resolvers disjoint name prefixes.
#[derive(Debug, Default)]
struct Counts {
    /// Datagrams that arrived, including ones the drop policy then discards.
    udp: [AtomicU64; 2],
    /// Queries that arrived over TCP, not TCP connections.
    tcp: [AtomicU64; 2],
}

impl Counts {
    /// Returns the index for the resolver that asked for `name`.
    ///
    /// Returns `None` for a name from neither, which no test sends.
    fn index_of(name: &str) -> Option<usize> {
        match () {
            _ if name.starts_with("n0-") => Some(0),
            _ if name.starts_with("hi-") => Some(1),
            _ => None,
        }
    }

    /// Counts one query that arrived over UDP.
    fn record_udp(&self, query: &Packet<'_>) {
        self.record(&self.udp, query);
    }

    /// Counts one query that arrived over TCP.
    fn record_tcp(&self, query: &Packet<'_>) {
        self.record(&self.tcp, query);
    }

    /// Counts one query against `counters`, attributed by its question.
    fn record(&self, counters: &[AtomicU64; 2], query: &Packet<'_>) {
        let Some(question) = query.questions.first() else {
            return;
        };
        if let Some(idx) = Self::index_of(&question.qname.to_string()) {
            counters[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns the current `(udp, tcp)` totals for resolver `idx`.
    fn get(&self, idx: usize) -> (u64, u64) {
        (
            self.udp[idx].load(Ordering::Relaxed),
            self.tcp[idx].load(Ordering::Relaxed),
        )
    }
}

/// Serves DNS on `socket`, applying `policy` to each datagram.
async fn serve_udp(socket: UdpSocket, policy: UdpPolicy, counts: Arc<Counts>) {
    let seen = Mutex::new(HashMap::new());
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let Ok(query) = Packet::parse(&buf[..n]) else {
            continue;
        };
        // Count before the policy runs. A datagram the policy discards still
        // crossed the network, and the network cost is what we are measuring.
        counts.record_udp(&query);
        if policy.drops(query.id(), &seen) {
            tracing::debug!(id = query.id(), "test nameserver: dropping datagram");
            continue;
        }
        let Some(reply) = build_reply(&query) else {
            continue;
        };
        let _ = socket.send_to(&reply, peer).await;
    }
}

/// Serves DNS on `listener`, answering every query.
///
/// Each connection is read in a loop rather than served once, because our
/// resolver pools TCP connections and sends follow-up queries on the same one.
async fn serve_tcp(listener: TcpListener, counts: Arc<Counts>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let counts = counts.clone();
        tokio::spawn(async move {
            loop {
                let Ok(len) = stream.read_u16().await else {
                    return;
                };
                let mut buf = vec![0u8; len as usize];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let Ok(query) = Packet::parse(&buf) else {
                    return;
                };
                counts.record_tcp(&query);
                let Some(reply) = build_reply(&query) else {
                    return;
                };
                if stream
                    .write_all(&(reply.len() as u16).to_be_bytes())
                    .await
                    .is_err()
                    || stream.write_all(&reply).await.is_err()
                {
                    return;
                }
            }
        });
    }
}

// ── The resolvers under test ────────────────────────────────────────────

/// Builds this crate's resolver, pointed at exactly one UDP nameserver.
///
/// No system configuration and no fallback tier, so every lookup exercises the
/// one server the test controls.
fn build_n0(server: SocketAddr) -> DnsResolver {
    DnsResolver::builder()
        .nameserver(Nameserver::new(server, DnsProtocol::Udp))
        .build()
}

/// Builds a hickory resolver against the same single nameserver.
///
/// `udp_and_tcp` matches what `read_system_conf` produces for a resolv.conf
/// entry, which is the configuration users actually run. Options are left at
/// their defaults: 5 s timeout, two attempts, two concurrent requests.
fn build_hickory(server: SocketAddr) -> Result<TokioResolver> {
    let config = ResolverConfig::from_parts(
        None,
        vec![],
        vec![NameServerConfig::udp_and_tcp(server.ip())],
    );
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .context("build hickory resolver")
}

/// Looks up one A record with this crate's resolver.
async fn lookup_n0(resolver: &DnsResolver, name: &str) -> Option<Ipv4Addr> {
    resolver
        .lookup_ipv4(name)
        .await
        .ok()
        .and_then(|addrs| addrs.first().copied())
}

/// Looks up one A record with hickory.
async fn lookup_hickory(resolver: &TokioResolver, name: &str) -> Option<Ipv4Addr> {
    let lookup = resolver.ipv4_lookup(name).await.ok()?;
    lookup.answers().iter().find_map(|r| match &r.data {
        HickoryRData::A(a) => Some(a.0),
        _ => None,
    })
}

// ── Measurement ─────────────────────────────────────────────────────────

/// Latency samples for one resolver over one run.
///
/// A `None` entry is a lookup that failed or exceeded [`LOOKUP_CAP`].
#[derive(Debug)]
struct Samples {
    label: &'static str,
    lookups: Vec<Option<Duration>>,
    /// Datagrams this resolver put on the wire over the whole run.
    ///
    /// Filled in by [`Fixture::run`] from the nameserver's counters, which
    /// [`run_rounds`] cannot reach from inside the client's namespace task.
    udp: u64,
    /// Queries this resolver sent over TCP over the whole run.
    tcp: u64,
}

impl Samples {
    /// Returns how many lookups completed within [`LOOKUP_CAP`].
    fn ok(&self) -> usize {
        self.lookups.iter().filter(|s| s.is_some()).count()
    }

    /// Returns the successful latencies at the given quantile, or `None` if
    /// every lookup failed.
    ///
    /// `q` is a fraction from 0 to 1; 0.5 is the median. Uses nearest-rank on
    /// the successes only, so a run with failures reports the latency of the
    /// lookups that did complete and the failure count separately.
    fn quantile(&self, q: f64) -> Option<Duration> {
        let mut ok: Vec<Duration> = self.lookups.iter().flatten().copied().collect();
        if ok.is_empty() {
            return None;
        }
        ok.sort_unstable();
        let rank = ((q * ok.len() as f64).ceil() as usize).clamp(1, ok.len());
        Some(ok[rank - 1])
    }
}

/// Returns this crate's samples out of a run.
fn ours(samples: &[Samples]) -> &Samples {
    samples
        .iter()
        .find(|s| s.label == "n0")
        .expect("n0 samples")
}

/// Returns the median latency of the resolver labelled `label`.
///
/// # Panics
///
/// Panics if that resolver answered nothing, since a scenario that measures
/// latency has nothing to say when every lookup failed.
fn median(samples: &[Samples], label: &str) -> Duration {
    samples
        .iter()
        .find(|s| s.label == label)
        .and_then(|s| s.quantile(0.5))
        .unwrap_or_else(|| panic!("{label} answered nothing"))
}

/// Prints a comparison table for one scenario.
fn report(scenario: &str, samples: &[Samples]) {
    println!("\n{scenario}");
    println!(
        "  {:<9} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "resolver", "ok", "p50", "p90", "max", "udp/qry", "tcp/qry"
    );
    let fmt = |d: Option<Duration>| match d {
        Some(d) => format!("{:.1} ms", d.as_secs_f64() * 1000.0),
        None => "-".to_string(),
    };
    for s in samples {
        let rounds = s.lookups.len() as f64;
        println!(
            "  {:<9} {:>7} {:>9} {:>9} {:>9} {:>9} {:>9}",
            s.label,
            format!("{}/{}", s.ok(), s.lookups.len()),
            fmt(s.quantile(0.5)),
            fmt(s.quantile(0.9)),
            fmt(s.quantile(1.0)),
            format!("{:.2}", s.udp as f64 / rounds),
            format!("{:.2}", s.tcp as f64 / rounds),
        );
    }
    println!();
}

/// Runs `rounds` lookups with each resolver, alternating which one goes first.
///
/// Every lookup uses a fresh name so neither resolver's cache is consulted, and
/// each is capped at [`LOOKUP_CAP`]. Running them one at a time rather than
/// concurrently keeps the two resolvers from competing for the same lossy link,
/// which would make the comparison a measure of scheduling rather than of
/// retransmit behavior.
async fn run_rounds(server: SocketAddr, rounds: usize) -> Result<[Samples; 2]> {
    /// Times one lookup, asserting that a successful one returns [`ANSWER`].
    async fn measure(
        label: &str,
        name: &str,
        lookup: impl Future<Output = Option<Ipv4Addr>>,
    ) -> Option<Duration> {
        let start = Instant::now();
        let got = tokio::time::timeout(LOOKUP_CAP, lookup)
            .await
            .ok()
            .flatten();
        assert!(
            got.is_none() || got == Some(ANSWER),
            "{label} resolved {name} to {got:?}, expected {ANSWER}"
        );
        got.map(|_| start.elapsed())
    }

    let n0 = build_n0(server);
    let hickory = build_hickory(server)?;
    let mut n0_lookups = Vec::with_capacity(rounds);
    let mut hickory_lookups = Vec::with_capacity(rounds);

    for round in 0..rounds {
        let n0_name = format!("n0-{round}.lossy.test.");
        let hickory_name = format!("hi-{round}.lossy.test.");
        // Alternate the order so neither resolver systematically warms the link
        // for the other.
        if round % 2 == 0 {
            n0_lookups.push(measure("n0", &n0_name, lookup_n0(&n0, &n0_name)).await);
            hickory_lookups.push(
                measure(
                    "hickory",
                    &hickory_name,
                    lookup_hickory(&hickory, &hickory_name),
                )
                .await,
            );
        } else {
            hickory_lookups.push(
                measure(
                    "hickory",
                    &hickory_name,
                    lookup_hickory(&hickory, &hickory_name),
                )
                .await,
            );
            n0_lookups.push(measure("n0", &n0_name, lookup_n0(&n0, &n0_name)).await);
        }
    }

    Ok([
        Samples {
            label: "n0",
            lookups: n0_lookups,
            udp: 0,
            tcp: 0,
        },
        Samples {
            label: "hickory",
            lookups: hickory_lookups,
            udp: 0,
            tcp: 0,
        },
    ])
}

/// A lab with a nameserver device and a client device on one router.
struct Fixture {
    /// The client device, where both resolvers run.
    client: patchbay::Device,
    /// The nameserver's address, as the client should query it.
    server_addr: SocketAddr,
    /// Records pass or fail into the lab's event log. Marked by [`Fixture::ok`].
    guard: TestGuard,
    /// Keeps the lab alive for as long as the fixture lives.
    _lab: Lab,
    /// Queries the nameserver has received, per resolver.
    counts: Arc<Counts>,
    /// Keeps the nameserver task alive for as long as the fixture lives.
    _server: tokio::task::JoinHandle<()>,
}

/// Builds the lab and starts the test nameserver with the given UDP policy.
async fn fixture(policy: UdpPolicy) -> Result<Fixture> {
    let lab = Lab::new().await.context(
        "failed to build the patchbay lab; it needs unprivileged user namespaces \
         (CONFIG_USER_NS, and kernel.unprivileged_userns_clone=1 where that knob exists)",
    )?;
    let net = lab.add_router("net").build().await?;
    let server = lab.add_device("ns").uplink(net.id()).build().await?;
    let client = lab.add_device("client").uplink(net.id()).build().await?;

    let server_ip = server.ip().context("nameserver device has no IPv4")?;
    let server_addr = SocketAddr::new(IpAddr::V4(server_ip), 53);

    let counts = Arc::new(Counts::default());
    let server_counts = counts.clone();
    // The first lookup must not race the nameserver's binds. A datagram sent
    // before UDP/53 exists is dropped by the kernel without the drop policy ever
    // seeing it, which silently makes that lookup one datagram unluckier than
    // the scenario says it is.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let task = server.spawn(move |_dev| async move {
        let udp = UdpSocket::bind(server_addr).await.expect("bind udp/53");
        let tcp = TcpListener::bind(server_addr).await.expect("bind tcp/53");
        let _ = ready_tx.send(());
        tokio::join!(
            serve_udp(udp, policy, server_counts.clone()),
            serve_tcp(tcp, server_counts),
        );
    })?;
    ready_rx.await.context("nameserver failed to bind")?;

    Ok(Fixture {
        client,
        server_addr,
        guard: lab.test_guard(),
        counts,
        _lab: lab,
        _server: task,
    })
}

impl Fixture {
    /// Applies a link condition to the client's uplink, in both directions.
    async fn impair_client(&self, condition: LinkCondition) -> Result<()> {
        self.client
            .iface("eth0")
            .context("client has no eth0")?
            .set_condition(condition, LinkDirection::Both)
            .await
    }

    /// Runs the comparison on the client device and returns both resolvers' samples.
    ///
    /// The packet counts on the samples are this run's alone: they are taken as
    /// the difference across the run, so a fixture reused for several scenarios
    /// reports each one separately.
    async fn run(&self, rounds: usize) -> Result<[Samples; 2]> {
        let server_addr = self.server_addr;
        let before = [self.counts.get(0), self.counts.get(1)];
        let mut samples = self
            .client
            .spawn(move |_dev| async move { run_rounds(server_addr, rounds).await })?
            .await
            .context("client task panicked")??;
        for (idx, s) in samples.iter_mut().enumerate() {
            let (udp, tcp) = self.counts.get(idx);
            s.udp = udp - before[idx].0;
            s.tcp = tcp - before[idx].1;
        }
        Ok(samples)
    }

    /// Marks the lab's test guard as passed.
    fn ok(self) {
        self.guard.ok();
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// A clean link, as the baseline the lossy runs are read against.
///
/// Both resolvers should answer in single-digit milliseconds. If this one is
/// slow, the lab rather than the resolver is the problem.
#[tokio::test(flavor = "current_thread")]
async fn no_loss_baseline() -> Result<()> {
    let fixture = fixture(UdpPolicy::Answer).await?;
    let samples = fixture.run(6).await?;
    report("no_loss_baseline", &samples);
    // Both resolvers answering is a check on the lab rather than on either of
    // them: if a clean link fails here, nothing below this line means anything.
    for s in &samples {
        assert_eq!(
            s.ok(),
            s.lookups.len(),
            "{} failed on a clean link",
            s.label
        );
    }
    // The packet counts are asserted for this crate only. hickory's are in the
    // table for scale, but they are a fact about hickory's defaults, and pinning
    // them here would turn a version bump there into a failure here.
    let n0 = ours(&samples);
    // Retransmitting early should cost nothing when nothing is lost.
    assert_eq!(
        n0.udp,
        n0.lookups.len() as u64,
        "n0 should send exactly one datagram per lookup on a clean link"
    );
    assert_eq!(n0.tcp, 0, "n0 should not fall back to TCP on a clean link");
    fixture.ok();
    Ok(())
}

/// The nameserver drops the opening datagram of every lookup.
///
/// This is the measurement that matters. There is no random loss anywhere, so
/// each lookup's latency is the resolver's retransmit interval plus one round
/// trip, and nothing else. Both resolvers retransmit on a timer while the first
/// datagram is still outstanding, so both should land near their retransmit
/// interval rather than near any timeout.
#[tokio::test(flavor = "current_thread")]
async fn first_datagram_dropped() -> Result<()> {
    let fixture = fixture(UdpPolicy::DropFirst(1)).await?;
    let samples = fixture.run(5).await?;
    report("first_datagram_dropped", &samples);
    for s in &samples {
        assert_eq!(
            s.ok(),
            s.lookups.len(),
            "{} failed to recover from a single lost datagram",
            s.label
        );
    }
    let (ours, theirs) = (median(&samples, "n0"), median(&samples, "hickory"));
    assert!(
        ours <= theirs * 2,
        "n0 median {ours:?} should be within 2x hickory's {theirs:?}"
    );
    fixture.ok();
    Ok(())
}

/// The nameserver drops the first two datagrams of every lookup.
///
/// Past hickory's `max_retries = 3` limit for a single pool pass, so hickory
/// falls back on its 5 s timeout. Our third datagram is still inside the run, so
/// UDP should carry it on its own, two retransmit intervals in and well before
/// the TCP query is due.
///
/// That last part is the assertion that catches a regression of the pacing.
/// The retransmit interval is scaled off the nameserver's smoothed RTT, so if
/// the intervals a lookup spends waiting were ever folded back into that RTT,
/// the interval would grow with every lossy lookup here: the third datagram
/// would slip past the TCP join delay, and TCP would start answering lookups
/// that UDP should have.
#[tokio::test(flavor = "current_thread")]
async fn first_two_datagrams_dropped() -> Result<()> {
    let fixture = fixture(UdpPolicy::DropFirst(2)).await?;
    let samples = fixture.run(5).await?;
    report("first_two_datagrams_dropped", &samples);
    for s in &samples {
        assert_eq!(
            s.ok(),
            s.lookups.len(),
            "{} failed to recover from two lost datagrams",
            s.label
        );
    }
    let n0 = ours(&samples);
    assert_eq!(
        n0.tcp, 0,
        "n0 should recover over UDP here; a TCP query means the retransmit \
         interval has drifted past the join delay"
    );
    let median = median(&samples, "n0");
    assert!(
        median < LATENCY_CEILING,
        "n0 median {median:?} should be two retransmit intervals, not seconds"
    );
    fixture.ok();
    Ok(())
}

/// UDP is black-holed while TCP/53 answers normally.
///
/// This is the network from the real-world log: every datagram to the gateway
/// disappears, but the same address answers over TCP in tens of milliseconds.
/// We join UDP with TCP once the datagrams go unanswered; hickory does not,
/// because `try_tcp_on_error` defaults to false, so it fails outright here.
///
/// The cost should be the delay before TCP starts plus a TCP round trip, and it
/// should not grow across lookups as the server's smoothed RTT absorbs it.
#[tokio::test(flavor = "current_thread")]
async fn udp_blackhole_tcp_works() -> Result<()> {
    let fixture = fixture(UdpPolicy::Blackhole).await?;
    let samples = fixture.run(3).await?;
    report("udp_blackhole_tcp_works", &samples);
    let n0 = ours(&samples);
    assert_eq!(
        n0.ok(),
        n0.lookups.len(),
        "the TCP fallback should carry every lookup when UDP is black-holed"
    );
    let ours = median(&samples, "n0");
    assert!(
        ours < LATENCY_CEILING,
        "n0 median {ours:?} should be near the TCP join delay, not seconds past it"
    );
    fixture.ok();
    Ok(())
}

/// Random datagram loss on the client's uplink.
///
/// Closer to a real link than the drop policies, and correspondingly noisy:
/// `netem` drops in both directions independently, so an exchange completes
/// with probability `(1 - loss)^2`. Read this as corroboration of
/// [`first_datagram_dropped`], not as a measurement in its own right.
#[tokio::test(flavor = "current_thread")]
async fn random_udp_loss() -> Result<()> {
    let fixture = fixture(UdpPolicy::Answer).await?;
    for loss in [20.0, 40.0] {
        fixture
            .impair_client(LinkCondition::new().latency_ms(20).random_loss(loss))
            .await?;
        let samples = fixture.run(8).await?;
        report(&format!("random_udp_loss loss={loss}%"), &samples);
    }
    fixture.ok();
    Ok(())
}
