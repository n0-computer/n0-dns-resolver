//! DNS transport implementations: UDP, TCP, TLS, and HTTPS.

#[cfg(not(wasm_browser))]
use std::io;
use std::net::SocketAddr;
#[cfg(with_rustls)]
use std::sync::Arc;

use n0_error::{e, stack_error};
#[cfg(not(wasm_browser))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(not(wasm_browser))]
use super::pool::ConnPool;

/// A network or transport-level failure while querying a single nameserver.
///
/// The source of [`crate::Error::Transport`]; match on it for the specific cause.
#[stack_error(derive, add_meta, std_sources)]
#[non_exhaustive]
pub enum TransportError {
    /// A socket read or write failed.
    #[cfg(not(wasm_browser))]
    #[error("transport I/O failed")]
    Io {
        /// The underlying I/O error.
        #[error(from)]
        source: io::Error,
    },
    /// A UDP response arrived from an address other than the nameserver queried,
    /// so it was rejected (a spoofing defence).
    #[cfg(not(wasm_browser))]
    #[error("response from unexpected source {actual}, expected {expected}")]
    UnexpectedSource {
        /// The nameserver address the query was sent to.
        expected: SocketAddr,
        /// The address the response actually came from.
        actual: SocketAddr,
    },
    /// The query did not fit the 2-byte length prefix used for TCP and DoT.
    #[cfg(not(wasm_browser))]
    #[error("query too large for TCP framing")]
    QueryTooLarge {},
    /// The configured TLS server name is not a valid DNS name for SNI.
    #[cfg(transport_tls)]
    #[error("invalid TLS server name: {name}")]
    InvalidServerName {
        /// The rejected server name.
        name: String,
    },
    /// A DNS-over-HTTPS request failed at the HTTP layer.
    #[cfg(transport_https)]
    #[error("DNS-over-HTTPS request failed")]
    Http {
        /// The underlying reqwest error.
        #[error(from)]
        source: reqwest::Error,
    },
    /// The DNS-over-HTTPS client could not be constructed.
    #[cfg(transport_https)]
    #[error("failed to build HTTPS client")]
    BuildClient {
        /// The reqwest error from building the client.
        source: reqwest::Error,
    },
    /// UDP and TCP are unavailable on the browser wasm target, which has only
    /// DNS-over-HTTPS.
    #[cfg(wasm_browser)]
    #[error(
        "UDP and TCP DNS are unavailable on the browser wasm target; use a DNS-over-HTTPS nameserver"
    )]
    Unsupported {},
}

// TCP and DoT connections are pooled (see the `pool` module) and reused across
// queries, so a DNS-over-TLS handshake is paid once and amortized over repeated
// lookups to the same nameserver.
//
// UDP sockets are intentionally not reused (a new random source port per query
// helps prevent cache poisoning).

/// UDP receive buffer size.
///
/// Well above the advertised EDNS(0) payload of 1232 bytes, so a compliant
/// server's UDP response always fits and a larger answer arrives with the DNS TC
/// bit set (handled by retrying over TCP). A datagram that fills this buffer is
/// treated as possibly truncated and also retried over TCP.
#[cfg(not(wasm_browser))]
const UDP_RECV_BUFFER: usize = 4096;

/// Sends a DNS query over UDP and reads the response.
///
/// Each query uses a fresh socket with a random ephemeral source port to
/// prevent cache poisoning. The response source address is validated against
/// the target nameserver. The returned flag is set when the datagram filled the
/// receive buffer and may be truncated, so the caller can retry over TCP.
#[cfg(not(wasm_browser))]
pub(super) async fn udp_query(
    addr: SocketAddr,
    query: &[u8],
) -> Result<(Vec<u8>, bool), TransportError> {
    let unspecified: std::net::IpAddr = if addr.is_ipv6() {
        std::net::Ipv6Addr::UNSPECIFIED.into()
    } else {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    };
    let bind_addr = SocketAddr::new(unspecified, 0);
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
    socket.send_to(query, addr).await?;

    let mut buf = vec![0u8; UDP_RECV_BUFFER];
    let (len, src) = socket.recv_from(&mut buf).await?;
    if src != addr {
        return Err(e!(TransportError::UnexpectedSource {
            expected: addr,
            actual: src,
        }));
    }
    // A datagram that fills the whole buffer may have been truncated at the
    // socket by a sender that ignored our advertised EDNS payload size. The DNS
    // TC bit only covers server-side truncation, so flag this separately and let
    // the caller retry over TCP rather than parse a partial message.
    let maybe_truncated = len == buf.len();
    buf.truncate(len);
    Ok((buf, maybe_truncated))
}

/// Sends a length-prefixed DNS query on an established stream and reads the reply.
///
/// Uses the 2-byte length prefix framing from RFC 1035 Section 4.2.2. Shared by
/// TCP and DoT.
#[cfg(not(wasm_browser))]
async fn framed_query<S>(stream: &mut S, query: &[u8]) -> Result<Vec<u8>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let len = u16::try_from(query.len())
        .map_err(|_| e!(TransportError::QueryTooLarge))?
        .to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    let resp_len = stream.read_u16().await? as usize;
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Sends a DNS query over TCP, reusing a pooled connection when one is available.
///
/// A pooled connection may have been closed by the server while idle; that only
/// surfaces on the first read/write, so on failure we dial a fresh connection
/// and retry the query once.
#[cfg(not(wasm_browser))]
pub(super) async fn tcp_query(
    pool: &ConnPool,
    addr: SocketAddr,
    query: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if let Some(mut stream) = pool.checkout_tcp(addr)
        && let Ok(resp) = framed_query(&mut stream, query).await
    {
        pool.checkin_tcp(addr, stream);
        return Ok(resp);
    }
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let resp = framed_query(&mut stream, query).await?;
    pool.checkin_tcp(addr, stream);
    Ok(resp)
}

/// Sends a DNS query over TLS (DNS-over-TLS, RFC 7858).
///
/// With `server_name`, that name is used for the TLS handshake and certificate
/// validation; without it the certificate is validated against the IP address,
/// which works for providers that list the IP in their certificate (e.g. Google
/// `8.8.8.8`, Cloudflare `1.1.1.1`) but not for those whose certificates only
/// cover a hostname.
///
/// Reuses a pooled connection when one is available, retrying once on a fresh
/// connection if a pooled one turns out to have been closed while idle.
#[cfg(transport_tls)]
pub(super) async fn tls_query(
    pool: &ConnPool,
    addr: SocketAddr,
    query: &[u8],
    tls_config: &Arc<rustls::ClientConfig>,
    server_name: Option<&str>,
) -> Result<Vec<u8>, TransportError> {
    let key = (addr, server_name.map(str::to_string));
    if let Some(mut stream) = pool.checkout_tls(&key)
        && let Ok(resp) = framed_query(&mut stream, query).await
    {
        pool.checkin_tls(key, stream);
        return Ok(resp);
    }

    let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
    let tcp_stream = tokio::net::TcpStream::connect(addr).await?;
    // Use the explicit server name for SNI and validation if given, otherwise
    // validate against the IP the connection was made to.
    let sni = match server_name {
        Some(name) => rustls::pki_types::ServerName::try_from(name.to_string()).map_err(|_| {
            e!(TransportError::InvalidServerName {
                name: name.to_string()
            })
        })?,
        None => rustls::pki_types::ServerName::IpAddress(addr.ip().into()),
    };
    let mut stream = connector.connect(sni, tcp_stream).await?;
    let resp = framed_query(&mut stream, query).await?;
    pool.checkin_tls(key, stream);
    Ok(resp)
}

/// Builds a [`reqwest::Client`] for DNS-over-HTTPS queries.
///
/// `resolves` pins each named DoH host to a fixed address, so a hostname-based
/// DoH URL connects to that IP instead of being resolved recursively.
#[cfg(all(transport_https, not(wasm_browser)))]
pub(super) fn build_https_client(
    tls_config: &Arc<rustls::ClientConfig>,
    resolves: &[(String, SocketAddr)],
) -> Result<reqwest::Client, TransportError> {
    // reqwest wraps the argument in an `Option` and downcasts to
    // `Option<rustls::ClientConfig>`, so hand it a bare `ClientConfig` (not the
    // `Arc`), or it rejects it as an unknown backend at build time.
    let mut builder = reqwest::Client::builder().use_preconfigured_tls((**tls_config).clone());
    for (host, addr) in resolves {
        builder = builder.resolve(host, *addr);
    }
    builder
        .build()
        .map_err(|source| e!(TransportError::BuildClient { source }))
}

/// Builds a [`reqwest::Client`] for DNS-over-HTTPS on the browser wasm target.
///
/// The browser resolves DNS and performs TLS itself through the fetch backend,
/// so there is no address pinning or preconfigured TLS config to apply here.
#[cfg(all(transport_https, wasm_browser))]
pub(super) fn build_https_client() -> Result<reqwest::Client, TransportError> {
    reqwest::Client::builder()
        .build()
        .map_err(|source| e!(TransportError::BuildClient { source }))
}

/// Sends a DNS query over HTTPS (DNS-over-HTTPS, RFC 8484).
///
/// With `server_name`, the URL is addressed by hostname (the client pins it to
/// `addr`); without it the URL is addressed by IP (e.g.
/// `https://1.1.1.1/dns-query`), which works only for providers whose
/// certificates include the IP address.
#[cfg(transport_https)]
pub(super) async fn https_query(
    addr: SocketAddr,
    server_name: Option<&str>,
    query: &[u8],
    client: &reqwest::Client,
) -> Result<Vec<u8>, TransportError> {
    // With a server name, address the URL by hostname (the client pins it to
    // `addr`); otherwise address it by IP.
    let url = match server_name {
        Some(name) => format!("https://{name}:{}/dns-query", addr.port()),
        None => format!("https://{addr}/dns-query"),
    };
    let response = client
        .post(&url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .await?;

    let bytes = response.error_for_status()?.bytes().await?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use simple_dns::{
        CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, ResourceRecord, TYPE,
        rdata::{A, RData},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::Record;

    /// Parses the A records from a response and returns just the addresses and
    /// TTL, so the transport tests can compare against `Vec<Ipv4Addr>`.
    fn parse_a_addrs(data: &[u8]) -> (Vec<Ipv4Addr>, u32) {
        let (records, ttl) =
            super::super::query::parse_records(data, crate::RecordKind::A).unwrap();
        let addrs = records
            .into_iter()
            .filter_map(|r| match r {
                Record::A(ip) => Some(ip),
                _ => None,
            })
            .collect();
        (addrs, ttl)
    }

    fn build_a_response(id: u16, addrs: &[Ipv4Addr]) -> Vec<u8> {
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        // Echo the question section, as a real server does.
        packet.questions.push(Question::new(
            Name::new_unchecked("example.com"),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        for addr in addrs {
            let rdata = RData::A(A {
                address: u32::from(*addr),
            });
            packet.answers.push(ResourceRecord::new(
                Name::new_unchecked("example.com"),
                CLASS::IN,
                300,
                rdata,
            ));
        }
        packet.build_bytes_vec().unwrap()
    }

    /// Spawn a mock UDP server that echoes back an A response for any query.
    async fn mock_udp_server(addrs: &[Ipv4Addr]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let addrs = addrs.to_vec();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, client_addr) = server.recv_from(&mut buf).await.unwrap();
            let id = Packet::parse(&buf[..len]).unwrap().id();
            server
                .send_to(&build_a_response(id, &addrs), client_addr)
                .await
                .unwrap();
        });
        (server_addr, handle)
    }

    /// Spawn a mock TCP server that echoes back an A response for any query.
    async fn mock_tcp_server(addrs: &[Ipv4Addr]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let addrs = addrs.to_vec();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let query_len = stream.read_u16().await.unwrap() as usize;
            let mut query_buf = vec![0u8; query_len];
            stream.read_exact(&mut query_buf).await.unwrap();
            let id = Packet::parse(&query_buf).unwrap().id();
            let resp = build_a_response(id, &addrs);
            stream
                .write_all(&(resp.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&resp).await.unwrap();
            stream.flush().await.unwrap();
        });
        (server_addr, handle)
    }

    fn build_query() -> (u16, Vec<u8>) {
        super::super::query::build_query("example.com", TYPE::A).unwrap()
    }

    #[tokio::test]
    async fn test_udp_query() {
        let (addr, handle) = mock_udp_server(&[Ipv4Addr::new(93, 184, 216, 34)]).await;
        let (_, query) = build_query();
        let (addrs, _) = parse_a_addrs(&udp_query(addr, &query).await.unwrap().0);
        assert_eq!(addrs, [Ipv4Addr::new(93, 184, 216, 34)]);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_query() {
        let (addr, handle) = mock_tcp_server(&[Ipv4Addr::new(93, 184, 216, 34)]).await;
        let (_, query) = build_query();
        let pool = ConnPool::new();
        let (addrs, _) = parse_a_addrs(&tcp_query(&pool, addr, &query).await.unwrap());
        assert_eq!(addrs, [Ipv4Addr::new(93, 184, 216, 34)]);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_udp_multiple_records() {
        let expected = [
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            Ipv4Addr::new(9, 10, 11, 12),
        ];
        let (addr, handle) = mock_udp_server(&expected).await;
        let (_, query) = build_query();
        let (addrs, ttl) = parse_a_addrs(&udp_query(addr, &query).await.unwrap().0);
        assert_eq!(addrs, expected);
        assert_eq!(ttl, 300);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_large_response() {
        let expected: Vec<Ipv4Addr> = (0..50).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
        let (addr, handle) = mock_tcp_server(&expected).await;
        let (_, query) = build_query();
        let pool = ConnPool::new();
        let (addrs, _) = parse_a_addrs(&tcp_query(&pool, addr, &query).await.unwrap());
        assert_eq!(addrs, expected);
        handle.await.unwrap();
    }

    /// A datagram that exactly fills the receive buffer is flagged as possibly
    /// truncated, so the caller can retry over TCP.
    #[tokio::test]
    async fn udp_query_flags_full_buffer_as_maybe_truncated() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, peer) = server.recv_from(&mut buf).await.unwrap();
            server
                .send_to(&vec![0u8; UDP_RECV_BUFFER], peer)
                .await
                .unwrap();
        });
        let (resp, maybe_truncated) = udp_query(addr, b"query").await.unwrap();
        assert_eq!(resp.len(), UDP_RECV_BUFFER);
        assert!(maybe_truncated);
        handle.await.unwrap();
    }
}
