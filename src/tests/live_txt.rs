//! Publish an `_iroh` TXT via pkarr, then resolve it with this crate.
//!
//! Default iroh discovery publishes by HTTP PUT to `dns.iroh.link/pkarr`.
//! This does that same publish (without binding a QUIC endpoint) and checks
//! the TXT comes back over DNS.

#![cfg(all(transport_https, with_crypto_provider))]

use std::time::Duration;

use iroh_base::SecretKey;
use n0_future::time;
use simple_dns::{CLASS, Name, Packet, rdata::RData};

use crate::{DnsResolver, Error};

const PKARR_RELAY: &str = "https://dns.iroh.link/pkarr";
const DNS_ORIGIN: &str = "dns.iroh.link.";
const TXT_VALUE: &str = "relay=https://use1-1.relay.n0.iroh.link.";

/// Publishes a pkarr packet and resolves `_iroh.<z32>.dns.iroh.link` TXT.
#[tokio::test]
#[ignore = "publishes to dns.iroh.link and needs the network"]
async fn published_iroh_txt_resolves() {
    let secret = SecretKey::generate();
    let z32 = secret.public().to_z32();
    let name = format!("_iroh.{z32}.{DNS_ORIGIN}");

    let packet = signed_txt(&secret, TXT_VALUE);
    publish(&z32, &packet).await;

    // Recursive resolvers may still answer NXDOMAIN for a moment after the PUT.
    time::sleep(Duration::from_secs(1)).await;

    let resolver = DnsResolver::new();
    let records = wait_for_txt(&resolver, &name).await;
    assert!(
        records.iter().any(|r| r.contains(TXT_VALUE)),
        "expected {TXT_VALUE:?} in {records:?} for {name}"
    );
}

async fn wait_for_txt(resolver: &DnsResolver, name: &str) -> Vec<String> {
    let deadline = time::Instant::now() + Duration::from_secs(15);
    loop {
        match resolver.lookup_txt(name.to_string()).await {
            Ok(records) => {
                let records: Vec<String> = records.map(|txt| txt.to_string()).collect();
                if !records.is_empty() {
                    return records;
                }
            }
            Err(Error::NxDomain { .. }) => {}
            Err(err) => panic!("TXT lookup for {name} failed: {err:#}"),
        }
        if time::Instant::now() >= deadline {
            panic!("timed out waiting for TXT at {name}");
        }
        time::sleep(Duration::from_millis(250)).await;
    }
}

fn signed_txt(secret: &SecretKey, value: &str) -> Vec<u8> {
    let z32 = secret.public().to_z32();
    let owner = format!("_iroh.{z32}");
    let mut packet = Packet::new_reply(0);
    let mut txt = simple_dns::rdata::TXT::new();
    txt.add_string(value).expect("txt fits");
    packet.answers.push(simple_dns::ResourceRecord::new(
        Name::new_unchecked(&owner).into_owned(),
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

    let mut body = Vec::with_capacity(64 + 8 + encoded.len());
    body.extend_from_slice(&signature.to_bytes());
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&encoded);
    body
}

async fn publish(z32: &str, relay_payload: &[u8]) {
    use std::sync::Arc;

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
    let response = client
        .put(&url)
        .body(relay_payload.to_vec())
        .send()
        .await
        .unwrap_or_else(|err| panic!("pkarr PUT {url}: {err}"));
    assert!(
        response.status().is_success(),
        "pkarr PUT {url} failed: {}",
        response.status()
    );
}
