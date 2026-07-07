//! Transport-agnostic external-auth and basic-auth configuration carried on
//! [`RouteEntry`][super::entry::RouteEntry].
//!
//! These types are **crypto-free** — the core crate has no bcrypt or SHA1
//! dependency.  All hashing and verification happens in `coxswain-proxy`;
//! `BasicCredential` stores the raw hash string and lets the proxy dispatch to
//! the right algorithm at runtime.  Transport-specific ext_authz wire details
//! (header forwarding, body opts) also live in the proxy to keep the core type
//! stable across future transport additions.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use zeroize::ZeroizeOnDrop;

/// Top-level authentication configuration for an Ingress route, resolved at
/// reconcile time from the `ingress.coxswain-labs.dev/auth-*` annotations.
///
/// Carried as `Option<Arc<IngressAuthConfig>>` on [`RouteEntry`][super::entry::RouteEntry]
/// so the common case (no auth annotation) has zero size impact on the hot
/// `RouteEntry` beyond an 8-byte niche pointer.
#[non_exhaustive]
#[derive(Debug)]
pub enum IngressAuthConfig {
    /// Forward a sub-request to an external authorization service.
    External(ExtAuthConfig),
    /// Validate `Authorization: Basic` against an htpasswd-style credential list.
    ///
    /// The list is pre-parsed at reconcile time; each element carries the
    /// username and hash type as plain (immutable) data.  Zero ready
    /// credentials (e.g. an empty or fully-unparseable Secret) produce an
    /// empty slice — the proxy treats that identically to `Unavailable`
    /// (fail-closed: 503).
    Basic(Arc<[BasicCredential]>),
    /// The referenced htpasswd Secret was absent, unlabeled, or had no
    /// parseable entries.  The proxy responds with 503 (fail-closed) and
    /// logs a loud `WARN` naming the missing label or secret.
    Unavailable,
}

/// External auth (ext_authz) configuration — the resolved auth-service
/// endpoints plus transport-independent knobs and a transport variant.
///
/// The auth service is always named by a Gateway API `backendRef`, resolved to
/// `endpoints` (pod `SocketAddr`s) at reconcile time — the same endpoint model
/// coxswain uses for every other backend, so the proxy connects to a pod
/// directly (no DNS). `timeout` and `fail_closed` are transport-independent and
/// live here; per-transport knobs live inside the [`ExtAuthTransport`] variant.
#[non_exhaustive]
#[derive(Debug)]
pub struct ExtAuthConfig {
    /// Maximum time to wait for the auth service to respond. Defaults to 2 s
    /// when the CRD `timeout` is absent or unparseable.
    pub timeout: Duration,
    /// Resolved auth-service `backendRef` endpoints (pod `SocketAddr`s). The
    /// proxy sends the check to one of these. **Never empty**: an unresolved or
    /// endpoint-less `backendRef` produces [`IngressAuthConfig::Unavailable`]
    /// (fail-closed 503) rather than an empty list.
    pub endpoints: Arc<[SocketAddr]>,
    /// Fail-closed (`true`, the default and only safe posture) denies with 503
    /// when the auth service is unreachable/errors/times out. `false`
    /// (`failClosed: false`) fails open — the request proceeds unauthorized.
    pub fail_closed: bool,
    /// Transport the auth service speaks — HTTP forward-auth or gRPC
    /// (`envoy.service.auth.v3`).
    pub transport: ExtAuthTransport,
}

impl ExtAuthConfig {
    /// Construct an [`ExtAuthConfig`] from resolved endpoints, timeout,
    /// fail-closed posture, and transport.
    #[must_use]
    pub fn new(
        timeout: Duration,
        endpoints: Arc<[SocketAddr]>,
        fail_closed: bool,
        transport: ExtAuthTransport,
    ) -> Self {
        Self {
            timeout,
            endpoints,
            fail_closed,
            transport,
        }
    }
}

/// Transport-specific ext_authz wiring.
///
/// `#[non_exhaustive]` so adding `Grpc(GrpcExtAuthConfig)` in #23 P4 is a
/// backwards-compatible change: existing `match` arms with `_ => …` continue
/// to compile.
#[non_exhaustive]
#[derive(Debug)]
pub enum ExtAuthTransport {
    /// HTTP forward-auth — Envoy `ext_authz`-HTTP semantics.
    ///
    /// Request replays the original method and path to a resolved auth endpoint,
    /// forwards client headers (Authorization, Cookie, …), sends no body.
    /// Three-bucket response contract mirrors Envoy / Istio `envoyExtAuthzHttp`:
    /// - 2xx → allow; copy `response_headers` allow-list onto upstream request.
    /// - non-2xx → deny; return auth status+body to client; `always_set_cookie`
    ///   adds `Set-Cookie` to the downstream response (enables `302 → IdP`).
    /// - timeout/connect error → fail-closed 503; backend never hit.
    Http(HttpExtAuthConfig),
}

/// HTTP forward-auth wiring: the response-header allow-list knobs. The check
/// target endpoints live on the parent [`ExtAuthConfig`].
#[non_exhaustive]
#[derive(Debug)]
pub struct HttpExtAuthConfig {
    /// Header names to copy from the auth *response* onto the upstream *request*
    /// when the auth service allows (Envoy `allowed_upstream_headers` / Istio
    /// `headersToUpstreamOnAllow`; GEP-1494 `allowedResponseHeaders`).
    pub response_headers: Arc<[Box<str>]>,
    /// When `true`, also copy `Set-Cookie` from the auth response onto the
    /// downstream *response* when the auth service denies (Envoy
    /// `allowed_client_headers` / Istio `headersToDownstreamOnDeny`). Enables
    /// IdP login-redirect flows (`302 + Set-Cookie`).
    pub always_set_cookie: bool,
}

impl HttpExtAuthConfig {
    /// Construct an [`HttpExtAuthConfig`] with the given allowed response
    /// headers and Set-Cookie forwarding flag.
    #[must_use]
    pub fn new(response_headers: Arc<[Box<str>]>, always_set_cookie: bool) -> Self {
        Self {
            response_headers,
            always_set_cookie,
        }
    }
}

/// One htpasswd entry: username (plaintext) + password hash.
///
/// Hash bytes are zeroed on drop via [`ZeroizeOnDrop`] so that bcrypt/SHA1
/// hashes do not linger in process memory after the credential list is
/// replaced at reconcile time.  The username is also zeroed as a precaution
/// (it is typically public information, but the operator may have used
/// sensitive values).
///
/// `Debug` is hand-implemented to redact both the hash and the username.
#[non_exhaustive]
#[derive(ZeroizeOnDrop)]
pub struct BasicCredential {
    /// Username from the htpasswd entry.
    pub username: Box<str>,
    /// One-way password hash.
    pub hash: PasswordHash,
}

impl BasicCredential {
    /// Construct a credential entry from a parsed htpasswd line.
    ///
    /// Both fields are owned; call sites in `coxswain-reflector` use this
    /// constructor because `#[non_exhaustive]` prevents struct literals from
    /// outside the defining crate.
    #[must_use]
    pub fn new(username: impl Into<Box<str>>, hash: PasswordHash) -> Self {
        Self {
            username: username.into(),
            hash,
        }
    }
}

impl std::fmt::Debug for BasicCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicCredential")
            .field("username", &"<redacted>")
            .field("hash", &"<redacted>")
            .finish()
    }
}

/// Supported htpasswd hash algorithms.
///
/// `#[non_exhaustive]` so future formats (MD5 `$apr1$`, etc.) can be added
/// without breaking callers.  Unknown formats are WARN+skipped at parse time.
///
/// Hash bytes are zeroed on drop via [`ZeroizeOnDrop`].
/// `Debug` is hand-implemented to redact the hash value.
#[non_exhaustive]
#[derive(ZeroizeOnDrop)]
pub enum PasswordHash {
    /// bcrypt hash (`$2a$`, `$2b$`, or `$2y$` prefix).
    ///
    /// Verification uses `bcrypt::verify` run inside
    /// `tokio::task::spawn_blocking` — never on the async executor.
    Bcrypt(Box<str>),
    /// Apache SHA-1 hash (`{SHA}` prefix followed by base64-encoded SHA1).
    ///
    /// Verification computes `SHA1(password)`, base64-encodes it, and compares
    /// to the stored value in constant time via `constant_time_eq`.
    Sha1(Box<str>),
}

impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordHash::Bcrypt(_) => f.write_str("Bcrypt(<redacted>)"),
            PasswordHash::Sha1(_) => f.write_str("Sha1(<redacted>)"),
        }
    }
}
