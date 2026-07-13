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
        /// Wire version advertised by the server.
        server: u32,
        /// Wire version this client speaks (see [`crate::version::WIRE_VERSION`]).
        client: u32,
    },

    /// A configured discovery endpoint string is not a valid URI.
    ///
    /// Operator misconfiguration (a malformed `--discovery-endpoint` / Helm
    /// value). Surfaced at client construction so startup fails loudly rather
    /// than the reconnect supervisor panicking on every attempt.
    #[error("invalid discovery endpoint URI {uri:?}: {source}")]
    InvalidEndpoint {
        /// The endpoint string that failed to parse.
        uri: String,
        /// The underlying tonic transport parse error.
        #[source]
        source: tonic::transport::Error,
    },

    /// Building the mTLS channel config from the current cert material failed.
    ///
    /// Reachable at runtime when an SVID rotation writes malformed material into
    /// the cell. The reconnect supervisor degrades to the last-good snapshot and
    /// retries on the next rotation rather than crashing the data plane.
    #[error("discovery channel TLS config: {0}")]
    TlsConfig(#[from] AuthError),
}

/// Errors produced by the mTLS authentication layer during TLS config
/// construction.
///
/// These errors indicate misconfigured certificate material (bad PEM, wrong
/// SPIFFE URI pattern, etc.).  They surface at start-up time when building
/// the TLS acceptor or channel; runtime handshake rejections are signalled via
/// [`rustls::Error`] directly through the TLS stack.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// PEM-encoded certificate or key material could not be parsed.
    #[error("invalid PEM: {0}")]
    InvalidPem(String),

    /// DER-encoded certificate could not be parsed by x509-parser.
    #[error("invalid certificate: {0}")]
    InvalidCert(String),

    /// A required private key was absent from the PEM input.
    #[error("no private key found in PEM input")]
    MissingKey,

    /// rustls rejected the certificate or configuration.
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// The rustls verifier builder returned an error.
    #[error("rustls verifier build failed: {0}")]
    VerifierBuild(String),
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
    #[error("load-balance oneof missing or unknown")]
    InvalidLoadBalance,

    /// A path pattern string was rejected by the `matchit` router.
    ///
    /// Returned by `wire::build_route_table` when a route path in the DTO
    /// contains characters or patterns that the router cannot insert
    /// (e.g. conflicting parameter syntax).
    #[error("invalid path pattern: {0}")]
    InvalidMatchitPath(String),

    /// A `WeightedBackend.endpoint_ref` named an `EndpointResource` that is not
    /// present in the message's endpoint pool (a dangling reference).
    ///
    /// Referential integrity is a protocol invariant (#383): the server ships
    /// every newly-referenced endpoint resource in the same message. A miss means
    /// the peer sent an inconsistent world — fail the whole decode closed (Nack +
    /// last-good) rather than fabricating a `service_exists = false` group, which
    /// would silently drop traffic.
    #[error("dangling endpoint reference {namespace}/{service}/{port}")]
    UnknownEndpointRef {
        /// Referenced Service namespace.
        namespace: String,
        /// Referenced Service name.
        service: String,
        /// Referenced Service port, as it appeared on the wire.
        ///
        /// `u32` (the raw proto width, not the `u16` bind-port domain) so an
        /// out-of-range ref (e.g. 65616) is reported verbatim instead of as its
        /// truncated alias — the exact confusion this guard exists to prevent.
        port: u32,
    },

    /// A delta (`Snapshot.full = false`) arrived before any full snapshot on this
    /// stream.
    ///
    /// Protocol invariant (#383): the first message per stream is `full = true`.
    /// A delta-first message means the client has no baseline to apply upserts
    /// against — Nack so the server responds with a fresh full resync.
    #[error("delta snapshot received before any full snapshot")]
    DeltaBeforeFullSnapshot,

    /// A `Resource` payload carried an arm or identity this build cannot key.
    ///
    /// Either the `payload` oneof was absent, or a `RouteHostResource` carried an
    /// unspecified `table` / absent host pattern — a resource with no canonical
    /// key cannot be placed in the world. Also raised when a delta's
    /// `removed_resources` carries an unparsable canonical key, or when the same
    /// canonical key appears in both the upsert and the tombstone set of one
    /// delta (invariant 2: the two sets are disjoint). Fail the decode closed.
    #[error("resource carries no decodable canonical key: {reason}")]
    UnknownResourceKey {
        /// Human-readable reason the resource could not be keyed.
        reason: &'static str,
    },

    /// A delta tombstoned an `EndpointResource` still referenced by a resource
    /// that survives the same delta (a backend `EndpointRef`, directly or through
    /// a mirror filter).
    ///
    /// Referential integrity is a protocol invariant (#383): the server tombstones
    /// an endpoint only in the same message that drops its last referrer. A
    /// residual referrer means the peer sent an inconsistent world — fail the
    /// whole delta closed (Nack + last-good) rather than commit a cache whose
    /// reverse index points at a pool entry the apply just deleted, which the next
    /// recompile of that referrer would then reject as a dangling reference.
    #[error("removed endpoint {key} is still referenced after the delta")]
    RemovedEndpointStillReferenced {
        /// `namespace/service/port` of the still-referenced removed endpoint.
        key: String,
    },

    /// The global version the client recomputed from its post-apply per-resource
    /// digests did not match the `version` the server stamped on the message.
    ///
    /// The version is a content hash of the whole post-apply world (F6): the
    /// client recomputes it independently and compares. A mismatch means the two
    /// sides disagree on what the applied world is — a lost/duplicated resource,
    /// a coalescing bug, or wire corruption. Nack so the server self-heals with a
    /// fresh full resync rather than let the caches silently diverge.
    #[error("snapshot version self-check failed: server={expected}, computed={computed}")]
    VersionMismatch {
        /// Global version the server stamped on the message.
        expected: String,
        /// Global version the client recomputed from the post-apply world.
        computed: String,
    },
}
