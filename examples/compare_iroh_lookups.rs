//! Compare iroh's real lookups: this crate vs the current iroh hickory glue.
//!
//! iroh resolves relay hostnames (A/AAAA) and `_iroh.<z32>.<origin>` TXT records
//! at the configured DNS discovery origin (`dns.iroh.link.` in production).
//!
//! With no extra args, it publishes a fresh `_iroh` TXT via pkarr (same path
//! as default discovery) and compares that lookup too. Pass an origin and z32
//! to use an existing name instead.
//!
//! Run:
//! ```text
//! cargo run --example compare_iroh_lookups
//! cargo run --example compare_iroh_lookups -- staging-dns.iroh.link. <z32>
//! ```

use std::{
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use hickory_resolver::{
    TokioResolver,
    config::{ResolverConfig, ResolverOpts},
    net::{NetError, runtime::TokioRuntimeProvider},
    proto::rr::RData,
};
use n0_dns_resolver::DnsResolver;
use tracing::warn;

/// Production DNS discovery origin (`iroh_dns::N0_DNS_ENDPOINT_ORIGIN_PROD`).
const DNS_ORIGIN_PROD: &str = "dns.iroh.link.";

/// Production relay hostnames from `iroh::defaults::prod`.
const RELAY_HOSTS: &[&str] = &[
    "use1-1.relay.n0.iroh.link.",
    "usw1-1.relay.n0.iroh.link.",
    "euc1-1.relay.n0.iroh.link.",
    "aps1-1.relay.n0.iroh.link.",
];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt::try_init();
    }

    let mut origin = DNS_ORIGIN_PROD.to_string();
    let mut z32s: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    if let Some(first) = args.next() {
        origin = first;
        z32s.extend(args);
    }
    if !origin.ends_with('.') {
        origin.push('.');
    }

    let hickory = iroh_hickory::HickoryResolver::system_defaults();
    let n0 = DnsResolver::new();
    let _ = n0.nameservers();

    let mut queries = build_queries(&origin, &z32s);
    if z32s.is_empty() {
        let name = publish_iroh_txt().await;
        wait_for_txt(&n0, &hickory, &name).await;
        queries.push(Query::Txt(name));
    }

    let mut first = Vec::with_capacity(queries.len());
    for query in &queries {
        first.push(tokio::join!(
            timed(hickory.lookup(query)),
            timed(n0_lookup(&n0, query))
        ));
    }

    let mut cache = Vec::with_capacity(queries.len());
    for query in &queries {
        cache.push((
            timed(hickory.lookup(query)).await.0,
            timed(n0_lookup(&n0, query)).await.0,
        ));
    }

    let mut mismatches = 0;
    let mut first_hickory = Duration::ZERO;
    let mut first_n0 = Duration::ZERO;
    let mut cache_hickory = Duration::ZERO;
    let mut cache_n0 = Duration::ZERO;
    for (i, query) in queries.iter().enumerate() {
        let ((h_first, h_out), (n_first, n_out)) = &first[i];
        let (h_cache, n_cache) = cache[i];
        first_hickory += *h_first;
        first_n0 += *n_first;
        cache_hickory += h_cache;
        cache_n0 += n_cache;
        let times = format!("{h_first:.0?}/{n_first:.0?}  cache {h_cache:.0?}/{n_cache:.0?}");
        if h_out == n_out {
            println!("ok    {query}  {n_out}  {times}");
        } else {
            mismatches += 1;
            println!("FAIL  {query}  {times}");
            println!("        hickory  {h_out}");
            println!("        n0-dns   {n_out}");
        }
    }

    let n = queries.len();
    if mismatches == 0 {
        println!(
            "PASS  {n}/{n}  first {first_hickory:.0?}/{first_n0:.0?}  cache {cache_hickory:.0?}/{cache_n0:.0?}  (hickory/n0-dns)"
        );
    } else {
        println!("FAIL  {mismatches}/{n} differ");
        std::process::exit(1);
    }
}

fn build_queries(origin: &str, z32s: &[String]) -> Vec<Query> {
    let mut queries = Vec::new();
    for host in RELAY_HOSTS {
        queries.push(Query::Ipv4((*host).to_string()));
        queries.push(Query::Ipv6((*host).to_string()));
    }
    for z32 in z32s {
        queries.push(Query::Txt(format!("_iroh.{z32}.{origin}")));
    }
    queries
}

async fn timed<T>(fut: impl Future<Output = T>) -> (Duration, T) {
    let start = Instant::now();
    let value = fut.await;
    (start.elapsed(), value)
}

async fn n0_lookup(resolver: &DnsResolver, query: &Query) -> Outcome {
    match query {
        Query::Ipv4(host) => match resolver.lookup_ipv4(host.clone()).await {
            Ok(addrs) => Outcome::v4(addrs.collect()),
            Err(err) => Outcome::from_n0_err(err),
        },
        Query::Ipv6(host) => match resolver.lookup_ipv6(host.clone()).await {
            Ok(addrs) => Outcome::v6(addrs.collect()),
            Err(err) => Outcome::from_n0_err(err),
        },
        Query::Txt(host) => match resolver.lookup_txt(host.clone()).await {
            Ok(records) => Outcome::txt(
                records
                    .map(|txt| txt.iter().map(<[u8]>::to_vec).collect())
                    .collect(),
            ),
            Err(err) => Outcome::from_n0_err(err),
        },
    }
}

#[derive(Debug, Clone)]
enum Query {
    Ipv4(String),
    Ipv6(String),
    Txt(String),
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Query::Ipv4(name) => write!(f, "A    {name}"),
            Query::Ipv6(name) => write!(f, "AAAA {name}"),
            Query::Txt(name) => write!(f, "TXT  {name}"),
        }
    }
}

/// Comparable lookup result. Addresses and TXT strings are sorted so order
/// differences do not count as a mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Addrs(Vec<IpAddr>),
    Txt(Vec<Vec<Vec<u8>>>),
    NxDomain,
    Empty,
    Error(String),
}

impl Outcome {
    fn v4(mut addrs: Vec<Ipv4Addr>) -> Self {
        addrs.sort();
        if addrs.is_empty() {
            Self::Empty
        } else {
            Self::Addrs(addrs.into_iter().map(IpAddr::V4).collect())
        }
    }

    fn v6(mut addrs: Vec<Ipv6Addr>) -> Self {
        addrs.sort();
        if addrs.is_empty() {
            Self::Empty
        } else {
            Self::Addrs(addrs.into_iter().map(IpAddr::V6).collect())
        }
    }

    fn txt(mut records: Vec<Vec<Vec<u8>>>) -> Self {
        records.sort();
        if records.is_empty() {
            Self::Empty
        } else {
            Self::Txt(records)
        }
    }

    fn from_n0_err(err: n0_dns_resolver::Error) -> Self {
        match err {
            n0_dns_resolver::Error::NxDomain { .. } => Self::NxDomain,
            other => Self::Error(other.to_string()),
        }
    }

    fn from_hickory_err(err: NetError) -> Self {
        if err.is_nx_domain() {
            Self::NxDomain
        } else if err.is_no_records_found() {
            Self::Empty
        } else {
            Self::Error(err.to_string())
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Addrs(addrs) => {
                let s: Vec<_> = addrs.iter().map(ToString::to_string).collect();
                write!(f, "[{}]", s.join(", "))
            }
            Outcome::Txt(records) => {
                let s: Vec<_> = records
                    .iter()
                    .map(|txt| {
                        txt.iter()
                            .map(|part| String::from_utf8_lossy(part).into_owned())
                            .collect::<Vec<_>>()
                            .join("")
                    })
                    .collect();
                write!(f, "[{}]", s.join(" | "))
            }
            Outcome::NxDomain => write!(f, "NXDOMAIN"),
            Outcome::Empty => write!(f, "(no records)"),
            Outcome::Error(err) => write!(f, "error: {err}"),
        }
    }
}

/// Hickory glue copied from `iroh-dns` `HickoryResolver` (`iroh-dns/src/dns.rs`).
///
/// This is what iroh uses today: system DNS config, Google only if that read
/// fails, `negative_max_ttl = 0`, IPv4-then-IPv6 strategy.
mod iroh_hickory {
    use super::*;

    /// Deprecated IPv6 site-local anycast addresses still configured by Windows.
    /// Copied from iroh-dns.
    const WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS: [IpAddr; 3] = [
        IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2)),
        IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3)),
    ];

    pub struct HickoryResolver {
        resolver: TokioResolver,
    }

    impl HickoryResolver {
        /// `DnsResolver::new()` / `Builder::default().with_system_defaults().build()`.
        pub fn system_defaults() -> Self {
            Self {
                resolver: Self::build_resolver(),
            }
        }

        pub fn clear_cache(&self) {
            self.resolver.clear_cache();
        }

        fn build_resolver() -> TokioResolver {
            let (config, mut options) = match Self::system_config() {
                Ok((config, options)) => (config, options),
                Err(reason) => {
                    warn!(
                        %reason,
                        "Failed to read the system's DNS config, using Google DNS servers as fallback."
                    );
                    (
                        ResolverConfig::udp_and_tcp(&hickory_resolver::config::GOOGLE),
                        ResolverOpts::default(),
                    )
                }
            };

            options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6;
            options.negative_max_ttl = Some(Duration::ZERO);

            let mut hickory_builder =
                TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
            *hickory_builder.options_mut() = options;
            hickory_builder.build().expect("config works")
        }

        fn system_config() -> Result<(ResolverConfig, ResolverOpts), NetError> {
            let (system_config, options) = hickory_resolver::system_conf::read_system_conf()?;

            let mut config = ResolverConfig::default();
            if let Some(name) = system_config.domain() {
                config.set_domain(name.clone());
            }
            for name in system_config.search() {
                config.add_search(name.clone());
            }
            for nameserver_cfg in system_config.name_servers() {
                if !WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS.contains(&nameserver_cfg.ip) {
                    config.add_name_server(nameserver_cfg.clone());
                }
            }
            Ok((config, options))
        }

        pub async fn lookup(&self, query: &Query) -> Outcome {
            let resolver = self.resolver.clone();
            match query {
                Query::Ipv4(host) => match resolver.ipv4_lookup(host.clone()).await {
                    Ok(lookup) => Outcome::v4(
                        lookup
                            .answers()
                            .iter()
                            .filter_map(|record| match &record.data {
                                RData::A(addr) => Some(addr.0),
                                _ => None,
                            })
                            .collect(),
                    ),
                    Err(err) => Outcome::from_hickory_err(err),
                },
                Query::Ipv6(host) => match resolver.ipv6_lookup(host.clone()).await {
                    Ok(lookup) => Outcome::v6(
                        lookup
                            .answers()
                            .iter()
                            .filter_map(|record| match &record.data {
                                RData::AAAA(addr) => Some(addr.0),
                                _ => None,
                            })
                            .collect(),
                    ),
                    Err(err) => Outcome::from_hickory_err(err),
                },
                Query::Txt(host) => match resolver.txt_lookup(host.clone()).await {
                    Ok(lookup) => Outcome::txt(
                        lookup
                            .answers()
                            .iter()
                            .filter_map(|record| match &record.data {
                                RData::TXT(txt) => Some(
                                    txt.txt_data
                                        .iter()
                                        .map(|s| s.as_ref().to_vec())
                                        .collect::<Vec<Vec<u8>>>(),
                                ),
                                _ => None,
                            })
                            .collect(),
                    ),
                    Err(err) => Outcome::from_hickory_err(err),
                },
            }
        }
    }
}

/// Publish an `_iroh` TXT the same way default discovery does (pkarr PUT).
/// Returns the FQDN to look up.
async fn publish_iroh_txt() -> String {
    use std::sync::Arc;

    use iroh_base::SecretKey;
    use simple_dns::{CLASS, Name, Packet, rdata::RData};

    const PKARR_RELAY: &str = "https://dns.iroh.link/pkarr";
    const TXT_VALUE: &str = "relay=https://use1-1.relay.n0.iroh.link.";

    let secret = SecretKey::generate();
    let z32 = secret.public().to_z32();
    let name = format!("_iroh.{z32}.dns.iroh.link.");

    let mut packet = Packet::new_reply(0);
    let mut txt = simple_dns::rdata::TXT::new();
    txt.add_string(TXT_VALUE).expect("txt fits");
    packet.answers.push(simple_dns::ResourceRecord::new(
        Name::new_unchecked(&format!("_iroh.{z32}")).into_owned(),
        CLASS::IN,
        30,
        RData::TXT(txt.into_owned()),
    ));
    let encoded = packet.build_bytes_vec_compressed().expect("packet builds");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_micros() as u64;
    let mut signable = format!("3:seqi{timestamp}e1:v{}:", encoded.len()).into_bytes();
    signable.extend_from_slice(&encoded);
    let signature = secret.sign(&signable);
    let mut body = Vec::new();
    body.extend_from_slice(&signature.to_bytes());
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&encoded);

    #[cfg(feature = "tls-ring")]
    let provider = rustls::crypto::ring::default_provider();
    #[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocols")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .expect("https client");
    let url = format!("{PKARR_RELAY}/{z32}");
    let status = client
        .put(&url)
        .body(body)
        .send()
        .await
        .unwrap_or_else(|err| panic!("pkarr PUT {url}: {err}"))
        .status();
    assert!(status.is_success(), "pkarr PUT {url} failed: {status}");
    name
}

async fn wait_for_txt(n0: &DnsResolver, hickory: &iroh_hickory::HickoryResolver, name: &str) {
    use n0_future::time;

    // dns.iroh.link serves the packet immediately; recursive resolvers may
    // still have an NXDOMAIN for a few hundred milliseconds.
    time::sleep(Duration::from_secs(1)).await;

    let query = Query::Txt(name.to_string());
    let deadline = time::Instant::now() + Duration::from_secs(15);
    loop {
        let n0_out = n0_lookup(n0, &query).await;
        let hickory_out = hickory.lookup(&query).await;
        let ready =
            n0_out.to_string().contains("relay=") && hickory_out.to_string().contains("relay=");
        if ready {
            n0.clear_cache();
            hickory.clear_cache();
            return;
        }
        if time::Instant::now() >= deadline {
            panic!("timed out waiting for TXT at {name}: n0-dns={n0_out} hickory={hickory_out}");
        }
        time::sleep(Duration::from_millis(250)).await;
    }
}
