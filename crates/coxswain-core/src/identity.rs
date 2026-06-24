//! SPIFFE identity primitives and issuance/authentication traits.
//!
//! Lives in `coxswain-core` (the neutral dependency) so that `coxswain-discovery`
//! can define a generic `BootstrapService<I, A>` and `coxswain-controller` can
//! provide the concrete implementations — without creating a new crate edge.
//!
//! Key types:
//! - [`SpiffeId`] — a validated `spiffe://<trust-domain>/ns/<ns>/sa/<sa>` URI.
//! - [`CsrPem`] — a PEM-encoded PKCS#10 Certificate Signing Request.
//! - [`IssuedSvid`] — a signed SVID cert PEM + metadata returned by the CA.
//! - [`SvidIssuer`] — trait implemented by the controller CA.
//! - [`TokenAuthenticator`] — trait that validates a Kubernetes SA token and
//!   returns the corresponding [`SpiffeId`].

use std::fmt;

use thiserror::Error;

// ────────────────────────────────────────────────────────────────────────────
// SpiffeId
// ────────────────────────────────────────────────────────────────────────────

/// A validated SPIFFE identity URI.
///
/// Only the `spiffe://<trust-domain>/ns/<ns>/sa/<sa>` form (derived from a
/// Kubernetes ServiceAccount) is accepted.  The constructor rejects all other
/// shapes so downstream code can treat this as a proof-of-validation token.
///
/// Components are stored pre-parsed so getters are O(1) with no runtime failures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SpiffeId {
    /// The full canonical URI.
    uri: String,
    /// Byte offset of the trust-domain within `uri` (after `spiffe://`).
    trust_domain_start: usize,
    /// Byte offset one past the end of the trust-domain within `uri`.
    trust_domain_end: usize,
    /// Byte offset of the namespace value (after `/ns/`).
    ns_start: usize,
    /// Byte offset one past the end of the namespace.
    ns_end: usize,
    /// Byte offset of the service-account value (after `/sa/`).
    sa_start: usize,
}

impl SpiffeId {
    /// Construct a `SpiffeId` from a raw URI string.
    ///
    /// # Errors
    ///
    /// Returns [`SpiffeIdError`] if the string is not a valid
    /// `spiffe://<trust-domain>/ns/<ns>/sa/<sa>` URI.
    #[must_use = "parsing fails if the SPIFFE ID is malformed; use the result"]
    pub fn parse(s: impl Into<String>) -> Result<Self, SpiffeIdError> {
        let uri = s.into();
        let offsets = parse_spiffe_offsets(&uri)?;
        Ok(Self {
            uri,
            trust_domain_start: offsets.trust_domain_start,
            trust_domain_end: offsets.trust_domain_end,
            ns_start: offsets.ns_start,
            ns_end: offsets.ns_end,
            sa_start: offsets.sa_start,
        })
    }

    /// Build a `SpiffeId` from its components: trust domain, namespace, and SA name.
    ///
    /// This is a convenience constructor that always succeeds because all
    /// components are provided directly; formatting and parsing happen once.
    #[must_use]
    pub fn from_parts(trust_domain: &str, namespace: &str, sa: &str) -> Self {
        let uri = format!("spiffe://{trust_domain}/ns/{namespace}/sa/{sa}");
        // The URI we just built is always valid; `parse` can never fail here.
        // unwrap_or_else with a clear invariant message is acceptable: the bug
        // would be in this function's own string formatting.
        Self::parse(uri)
            .unwrap_or_else(|e| panic!("invariant: from_parts built an invalid SPIFFE URI: {e}"))
    }

    /// The raw URI string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// Extract the trust domain portion of the URI.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.uri[self.trust_domain_start..self.trust_domain_end]
    }

    /// Extract the Kubernetes namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.uri[self.ns_start..self.ns_end]
    }

    /// Extract the ServiceAccount name.
    #[must_use]
    pub fn service_account(&self) -> &str {
        &self.uri[self.sa_start..]
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)
    }
}

/// Byte offsets of the parsed components within a SPIFFE URI.
struct SpiffeOffsets {
    trust_domain_start: usize,
    trust_domain_end: usize,
    ns_start: usize,
    ns_end: usize,
    sa_start: usize,
}

/// Parse a `spiffe://…` URI and return byte offsets for each component.
///
/// Returns `Err` if the string is not a valid
/// `spiffe://<trust-domain>/ns/<ns>/sa/<sa>` URI.
fn parse_spiffe_offsets(s: &str) -> Result<SpiffeOffsets, SpiffeIdError> {
    const SCHEME: &str = "spiffe://";
    let rest = s.strip_prefix(SCHEME).ok_or(SpiffeIdError::InvalidFormat)?;

    // rest = "<trust-domain>/ns/<ns>/sa/<sa>"
    let (td, after_td) = rest.split_once('/').ok_or(SpiffeIdError::InvalidFormat)?;
    if td.is_empty() {
        return Err(SpiffeIdError::EmptyTrustDomain);
    }

    // after_td = "ns/<ns>/sa/<sa>"
    let after_ns_kw = after_td
        .strip_prefix("ns/")
        .ok_or(SpiffeIdError::InvalidFormat)?;

    let (ns, after_ns) = after_ns_kw
        .split_once('/')
        .ok_or(SpiffeIdError::InvalidFormat)?;
    if ns.is_empty() {
        return Err(SpiffeIdError::InvalidFormat);
    }

    let sa = after_ns
        .strip_prefix("sa/")
        .ok_or(SpiffeIdError::InvalidFormat)?;
    if sa.is_empty() {
        return Err(SpiffeIdError::InvalidFormat);
    }

    let trust_domain_start = SCHEME.len();
    let trust_domain_end = trust_domain_start + td.len();
    // after trust_domain comes '/ns/<ns>/sa/<sa>'
    let ns_start = trust_domain_end + "/ns/".len();
    let ns_end = ns_start + ns.len();
    let sa_start = ns_end + "/sa/".len();

    Ok(SpiffeOffsets {
        trust_domain_start,
        trust_domain_end,
        ns_start,
        ns_end,
        sa_start,
    })
}

/// Error returned when a SPIFFE ID string cannot be parsed.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpiffeIdError {
    /// String does not start with `spiffe://` or lacks the `/ns/<ns>/sa/<sa>` path.
    #[error("invalid SPIFFE ID format; expected spiffe://<trust-domain>/ns/<ns>/sa/<sa>")]
    InvalidFormat,
    /// The trust domain portion is empty.
    #[error("trust domain must not be empty")]
    EmptyTrustDomain,
}

// ────────────────────────────────────────────────────────────────────────────
// CsrPem
// ────────────────────────────────────────────────────────────────────────────

/// A PEM-encoded PKCS#10 Certificate Signing Request.
///
/// Validation (well-formed PEM block present) is deferred to the CA at signing
/// time; this type is an ownership wrapper used as a parameter type so callers
/// can't pass raw bytes into issuance functions by accident.
// intentionally open: callers need to construct this to call SvidIssuer::sign_csr
#[derive(Debug, Clone)]
pub struct CsrPem(pub Vec<u8>);

impl CsrPem {
    /// Wrap raw PEM bytes.
    #[must_use]
    pub fn new(pem: Vec<u8>) -> Self {
        Self(pem)
    }

    /// View the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ────────────────────────────────────────────────────────────────────────────
// IssuedSvid
// ────────────────────────────────────────────────────────────────────────────

/// A freshly signed SVID returned by [`SvidIssuer::sign_csr`].
// intentionally open: new fields (chain, serial, issuer) can be added without breaking callers
#[derive(Debug, Clone)]
pub struct IssuedSvid {
    /// PEM-encoded end-entity certificate with the SPIFFE URI-SAN.
    pub cert_pem: Vec<u8>,
    /// SVID expiry as Unix seconds (UTC).
    pub not_after_unix: i64,
}

// ────────────────────────────────────────────────────────────────────────────
// SvidIssuer trait
// ────────────────────────────────────────────────────────────────────────────

/// Signs a CSR into a short-lived SVID and returns the current trust bundle.
///
/// Implemented by the controller's `CertAuthority`.  Lives in `coxswain-core`
/// so `coxswain-discovery` can use `Arc<dyn SvidIssuer>` without depending on
/// `coxswain-controller`.
pub trait SvidIssuer: Send + Sync {
    /// Sign `csr` and issue an SVID for `id`.
    ///
    /// # Errors
    ///
    /// Returns [`IssuerError`] if the CSR is malformed or signing fails.
    fn sign_csr(&self, csr: &CsrPem, id: &SpiffeId) -> Result<IssuedSvid, IssuerError>;

    /// Return the current CA trust bundle (PEM-encoded, may contain multiple
    /// roots for overlap during CA rotation).
    #[must_use]
    fn trust_bundle(&self) -> Vec<u8>;
}

/// Error returned by [`SvidIssuer::sign_csr`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IssuerError {
    /// The supplied CSR bytes are not a valid PEM/DER PKCS#10 request.
    #[error("malformed CSR: {0}")]
    MalformedCsr(String),
    /// The CA is not yet initialised (e.g. waiting for the Secret to appear).
    #[error("CA not ready")]
    NotReady,
    /// An internal signing error (rcgen / ring failure).
    #[error("signing error: {0}")]
    Signing(String),
}

// ────────────────────────────────────────────────────────────────────────────
// TokenAuthenticator trait
// ────────────────────────────────────────────────────────────────────────────

/// Validates a Kubernetes ServiceAccount token and maps it to a [`SpiffeId`].
///
/// Implemented by `KubeTokenAuthenticator` in `coxswain-controller` (which
/// calls the Kubernetes TokenReview API).  Lives in `coxswain-core` for the
/// same isolation reason as [`SvidIssuer`].
pub trait TokenAuthenticator: Send + Sync {
    /// Validate `token` and return the caller's SPIFFE identity.
    ///
    /// # Errors
    ///
    /// Returns [`AuthnError`] if the token is missing, expired, not issued for
    /// the expected audience, or if the TokenReview API call fails.
    fn authenticate(
        &self,
        token: &str,
    ) -> impl std::future::Future<Output = Result<SpiffeId, AuthnError>> + Send;
}

/// Error returned by [`TokenAuthenticator::authenticate`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthnError {
    /// The token was rejected (expired, wrong audience, or not authenticated).
    #[error("token not authenticated: {0}")]
    Unauthenticated(String),
    /// The Kubernetes TokenReview API returned an unexpected response.
    #[error("TokenReview API error: {0}")]
    ApiError(String),
    /// The authenticated username does not have the expected SA form.
    #[error("unexpected principal format: {0}")]
    InvalidPrincipal(String),
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_spiffe_id() {
        let id = SpiffeId::parse("spiffe://cluster.local/ns/coxswain-system/sa/coxswain-proxy")
            .expect("should parse");
        assert_eq!(id.trust_domain(), "cluster.local");
        assert_eq!(id.namespace(), "coxswain-system");
        assert_eq!(id.service_account(), "coxswain-proxy");
        assert_eq!(
            id.as_str(),
            "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-proxy"
        );
    }

    #[test]
    fn from_parts_roundtrips() {
        let id = SpiffeId::from_parts("cluster.local", "default", "my-sa");
        assert_eq!(id.namespace(), "default");
        assert_eq!(id.service_account(), "my-sa");
    }

    #[test]
    fn parse_rejects_non_spiffe_scheme() {
        assert_eq!(
            SpiffeId::parse("https://cluster.local/ns/a/sa/b"),
            Err(SpiffeIdError::InvalidFormat)
        );
    }

    #[test]
    fn parse_rejects_empty_trust_domain() {
        assert_eq!(
            SpiffeId::parse("spiffe:///ns/a/sa/b"),
            Err(SpiffeIdError::EmptyTrustDomain)
        );
    }

    #[test]
    fn parse_rejects_missing_ns_sa_segments() {
        assert_eq!(
            SpiffeId::parse("spiffe://cluster.local/ns/a"),
            Err(SpiffeIdError::InvalidFormat)
        );
        assert_eq!(
            SpiffeId::parse("spiffe://cluster.local/ns/a/sa/"),
            Err(SpiffeIdError::InvalidFormat)
        );
    }

    #[test]
    fn display_roundtrips() {
        let raw = "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-controller";
        let id = SpiffeId::parse(raw).expect("valid");
        assert_eq!(id.to_string(), raw);
    }
}
