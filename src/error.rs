//! The error type returned by the resolver.

use std::fmt;

use n0_error::stack_error;

use crate::resolver::TransportError;

/// An error returned while resolving a DNS record.
///
/// Each variant is a distinct, matchable failure reason. A transport-level
/// failure carries a typed [`TransportError`] source you can match on for the
/// specific cause, rather than an opaque error.
#[stack_error(derive, add_meta, std_sources)]
#[non_exhaustive]
pub enum Error {
    /// No nameservers were configured or discovered to query.
    #[error("no nameservers configured to query")]
    NoNameservers {},
    /// A nameserver did not answer within the per-attempt timeout.
    #[error("request timed out")]
    Timeout {},
    /// Every nameserver was tried and none returned a usable response.
    #[error("no nameserver returned a usable response")]
    NoResponse {},
    /// The domain name does not exist (NXDOMAIN).
    #[error("domain name does not exist (NXDOMAIN)")]
    NxDomain {},
    /// A nameserver answered with an error response code.
    #[error("nameserver returned error response code: {code}")]
    ServerError {
        /// The response code the nameserver returned.
        code: ResponseCode,
    },
    /// The response was malformed, did not match the query, or could not be followed.
    #[error("invalid DNS response: {reason}")]
    InvalidResponse {
        /// Why the response was rejected.
        reason: InvalidResponseReason,
    },
    /// The hostname could not be built into a valid DNS query.
    #[error("invalid domain name: {name}")]
    InvalidName {
        /// The hostname that could not be used as a DNS name.
        name: String,
    },
    /// A DNS-over-TLS or DNS-over-HTTPS nameserver was configured without a TLS
    /// client config, and none could be built from a crypto provider.
    #[error("no TLS config for DNS-over-TLS or DNS-over-HTTPS")]
    MissingTlsConfig {},
    /// A network or transport-level failure while talking to a nameserver.
    #[error("transport failure")]
    Transport {
        /// The specific transport failure.
        source: TransportError,
    },
}

/// A DNS response code (RCODE) explaining why a nameserver could not answer.
///
/// Only error codes reach this type. A successful `NoError` response is not an
/// error, and a non-existent name is reported as [`Error::NxDomain`] rather than
/// as a response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseCode {
    /// The nameserver failed to process the query (SERVFAIL).
    ServerFailure,
    /// The nameserver refused to answer, for example by policy (REFUSED).
    Refused,
    /// The query was malformed (FORMERR).
    FormatError,
    /// The nameserver does not support the requested operation (NOTIMP).
    NotImplemented,
    /// Another response code, with the numeric RCODE from the packet.
    Other {
        /// The RCODE value from the DNS header.
        code: u16,
    },
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseCode::ServerFailure => f.write_str("SERVFAIL"),
            ResponseCode::Refused => f.write_str("REFUSED"),
            ResponseCode::FormatError => f.write_str("FORMERR"),
            ResponseCode::NotImplemented => f.write_str("NOTIMP"),
            ResponseCode::Other { code } => write!(f, "RCODE {code}"),
        }
    }
}

/// Why a DNS response was rejected as unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidResponseReason {
    /// The packet could not be parsed.
    Malformed,
    /// The QR bit was not set, so this is not a response.
    NotAResponse,
    /// The transaction ID did not match the query.
    IdMismatch,
    /// The question section did not echo the query name, type, or class.
    QuestionMismatch,
    /// The CNAME chain exceeded the follow limit.
    CnameLimit,
}

impl fmt::Display for InvalidResponseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            InvalidResponseReason::Malformed => "malformed packet",
            InvalidResponseReason::NotAResponse => "not a response",
            InvalidResponseReason::IdMismatch => "transaction id mismatch",
            InvalidResponseReason::QuestionMismatch => "question did not match query",
            InvalidResponseReason::CnameLimit => "CNAME chain too long",
        })
    }
}
