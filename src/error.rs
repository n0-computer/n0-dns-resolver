//! The error type returned by the resolver.

use n0_error::{AnyError, stack_error};

/// An error returned while resolving a DNS record.
#[allow(missing_docs)]
#[stack_error(derive, add_meta, std_sources)]
#[non_exhaustive]
pub enum Error {
    /// A nameserver did not respond within the per-attempt timeout.
    #[error("request timed out")]
    Timeout {},
    /// No nameserver returned a usable response.
    #[error("no nameserver responded")]
    NoResponse {},
    /// Reaching or talking to a nameserver failed at the transport layer.
    #[error("failed to reach nameserver")]
    Transport { source: AnyError },
    /// The query packet could not be built (for example, an invalid name).
    #[error("failed to build query")]
    InvalidQuery { source: AnyError },
    /// The response was malformed or did not match the query.
    #[error("invalid DNS response")]
    InvalidResponse {},
    /// The nameserver answered with an error RCODE other than NXDOMAIN.
    #[error("nameserver returned error: {rcode}")]
    ServerError { rcode: String },
    /// The domain name does not exist (NXDOMAIN).
    #[error("domain name does not exist (NXDOMAIN)")]
    NxDomain {},
    /// A DNS-over-TLS or DNS-over-HTTPS nameserver was configured without a TLS
    /// client config to validate it against.
    #[error("no TLS config provided for DNS-over-TLS or DNS-over-HTTPS")]
    MissingTlsConfig {},
}
