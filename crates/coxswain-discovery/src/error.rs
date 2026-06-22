//! Error type for the discovery control plane.

use thiserror::Error;

/// Errors raised by the discovery server, client, and wire codec.
///
/// Variants are seeded minimally here; subsequent tickets (T4 client, T5 server,
/// T6 mTLS) extend this set. The type is `#[non_exhaustive]` so additions are
/// not breaking changes for downstream crates.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The peer advertised a wire-protocol version this build cannot speak.
    ///
    /// The proxy backs off permanently on this error; operator action (image
    /// upgrade) is required to resolve the mismatch.
    #[error("discovery wire version mismatch: server={server}, client={client}")]
    WireVersionMismatch {
        /// Wire version advertised by the server (e.g. `"v1"`).
        server: String,
        /// Wire version this client speaks (e.g. `"v1"`).
        client: String,
    },
}

/// Errors produced by the wire codec when converting between proto DTOs and
/// compiled routing types (`to_wire` / `from_wire` in [`crate::wire`]).
///
/// `from_wire` is given untrusted bytes (coming over the gRPC stream) and must
/// validate every field; these variants cover the recoverable failure modes.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WireError {
    /// A regex pattern string could not be compiled.
    #[error("invalid regex: {0}")]
    InvalidRegex(#[from] regex::Error),

    /// A header name string is not a valid HTTP token.
    #[error("invalid header name: {0}")]
    InvalidHeaderName(#[from] http::header::InvalidHeaderName),

    /// A header value string contains characters forbidden by RFC 7230.
    #[error("invalid header value: {0}")]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),

    /// An HTTP method string is not a valid token.
    #[error("invalid HTTP method: {0}")]
    InvalidMethod(#[from] http::method::InvalidMethod),

    /// An IP network string (`CIDR`) could not be parsed.
    #[error("invalid CIDR: {0}")]
    InvalidCidr(#[from] ipnet::AddrParseError),

    /// A socket address string could not be parsed.
    #[error("invalid socket address: {0}")]
    InvalidAddr(#[from] std::net::AddrParseError),

    /// A rate-limit config carried `requests_per_second = 0`, which is invalid.
    #[error("rate-limit requests_per_second must be ≥ 1")]
    ZeroRps,

    /// A `Mirror` filter was nested beyond the allowed recursion limit.
    ///
    /// `from_wire` guards against unbounded recursion through `Mirror` backends
    /// that themselves embed `Mirror` filters (trees only, no cycle risk in
    /// practice, but the proto is untrusted).
    #[error("mirror backend nesting depth exceeds the limit of {limit}")]
    MirrorTooDeep {
        /// Maximum allowed nesting depth.
        limit: usize,
    },

    /// A required oneof or message field was absent in the DTO.
    #[error("required field missing: {field}")]
    MissingRequiredField {
        /// Dotted-path name of the missing field (e.g. `"backend_group.weighted"`).
        field: &'static str,
    },

    /// A proto enum value did not map to a known Rust variant.
    #[error("unknown proto enum value {value} for {field}")]
    InvalidEnumValue {
        /// Numeric value that could not be decoded.
        value: i32,
        /// Field path where the unrecognised value appeared.
        field: &'static str,
    },

    /// A `BackendProtocol` enum value did not map to a known variant.
    #[error("unknown BackendProtocol value {0}")]
    InvalidProtocolEnum(i32),

    /// A `LoadBalance` discriminator did not match any known algorithm.
    #[error("LoadBalance oneof missing or unknown")]
    InvalidLoadBalance,

    /// A path pattern string was rejected by the `matchit` router.
    ///
    /// Returned by [`crate::wire::ingress_from_wire`] / [`crate::wire::gateway_from_wire`]
    /// when a route path in the DTO contains characters or patterns that the router
    /// cannot insert (e.g. conflicting parameter syntax).
    #[error("invalid path pattern: {0}")]
    InvalidMatchitPath(String),
}
