//! Cache for pre-parsed upstream TLS objects used by `BackendTLSPolicy` and GEP-3155.
//!
//! `X509::stack_from_pem` and `CertKey::new` are called at most once per distinct
//! `group_key`. Each cache is a [`GroupKeyCache`] over a `DashMap`, so the
//! per-request read on the upstream-TLS path takes only a sharded read-lock —
//! never one process-wide `Mutex` — and never crosses an `.await` point
//! (`upstream_peer` calls the getters synchronously).

use coxswain_core::routing::{SubjectAltName, UpstreamCa, UpstreamTls, san_set_matches};
use dashmap::DashMap;
use pingora_core::protocols::tls::CaType;
use pingora_core::protocols::tls::HandshakeCompleteHook;
use pingora_core::tls::{pkey::PKey, x509::X509};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::utils::tls::CertKey;
use pingora_core::{HTTPStatus, Result};
use std::any::Any;
use std::sync::Arc;

/// Lock-free-read cache keyed by `group_key`, shared by the three upstream-TLS
/// caches below.
///
/// Backed by a `DashMap`, so concurrent per-request reads hit sharded locks
/// instead of one global `Mutex`. Values are `Arc`-like clone handles; the
/// expensive build (PEM parse, closure allocation) is always done by the caller
/// *outside* any lock, then handed to [`GroupKeyCache::get_or_insert`], which
/// holds a shard write-lock only for the map insert.
struct GroupKeyCache<T>(DashMap<u64, T>);

// Manual `Default` (not derived): the derive would add a spurious `T: Default`
// bound, but the values (`Arc<dyn Fn…>`, `Arc<CertKey>`) are not `Default` and
// never need to be — an empty `DashMap` requires nothing of `T`.
impl<T> Default for GroupKeyCache<T> {
    fn default() -> Self {
        Self(DashMap::new())
    }
}

impl<T: Clone> GroupKeyCache<T> {
    /// Cached value for `group_key`, or `None` if not yet built.
    fn get(&self, group_key: u64) -> Option<T> {
        self.0.get(&group_key).map(|e| e.value().clone())
    }

    /// Store `value` for `group_key` and return it, unless another thread raced
    /// an insert between the caller's miss and this call — then return theirs.
    ///
    /// Not atomic (a plain `get` then `insert`, avoiding the write-locking
    /// `DashMap::entry`), which is fine here: every thread parses an *equivalent*
    /// value for a given `group_key`, so a benign race just does redundant parse
    /// work and the last writer wins with an identical object.
    fn get_or_insert(&self, group_key: u64, value: T) -> T {
        if let Some(existing) = self.get(group_key) {
            return existing;
        }
        self.0.insert(group_key, value.clone());
        value
    }
}

/// Zero-size type placed in a connection's `SslDigest.extension` when the
/// post-handshake SAN check fails.
///
/// `apply_upstream_tls` installs a [`HandshakeCompleteHook`] that returns
/// `Some(Arc::new(UpstreamSanMismatch))` on a mismatch.  The
/// `connected_to_upstream` hook reads the extension and returns a 502 before
/// any request bytes are sent upstream — the connection is never pooled.
pub(crate) struct UpstreamSanMismatch;

/// Thread-safe cache mapping `group_key` → pre-built [`HandshakeCompleteHook`]
/// for the backend SAN check (GEP-1897 `subjectAltNames`).
///
/// `upstream_peer` / `apply_upstream_tls` run once **per request/retry**, so
/// allocating a fresh `Arc<closure>` each time would hit the hot path.  This
/// cache ensures the `Arc` is built at most once per distinct SAN policy
/// (`group_key`).  Reads take only a `DashMap` shard lock, never across `.await`.
#[non_exhaustive]
#[derive(Default)]
pub struct SanCheckHookCache {
    inner: GroupKeyCache<HandshakeCompleteHook>,
}

impl SanCheckHookCache {
    /// Construct an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the cached hook for `group_key`, or build it from `sans` on first access.
    pub fn get_or_build(
        &self,
        group_key: u64,
        sans: Arc<[SubjectAltName]>,
    ) -> HandshakeCompleteHook {
        if let Some(hook) = self.inner.get(group_key) {
            return hook;
        }
        let hook: HandshakeCompleteHook = Arc::new(move |ssl| {
            // Pull the peer leaf cert from the completed handshake.
            let cert = match ssl.peer_certificate() {
                Some(c) => c,
                // No leaf — fail-closed (verify_cert=true normally rejects this
                // earlier, but the closure must not assume that).
                None => {
                    tracing::warn!(
                        "upstream SAN check: peer sent no certificate — marking mismatch"
                    );
                    return Some(Arc::new(UpstreamSanMismatch) as Arc<dyn Any + Send + Sync>);
                }
            };

            // Extract DNS and URI SANs from the leaf cert's SAN extension.
            let san_stack = cert.subject_alt_names();
            let mut dns_sans: Vec<&str> = Vec::new();
            let mut uri_sans: Vec<&str> = Vec::new();
            if let Some(ref stack) = san_stack {
                for name in stack {
                    if let Some(d) = name.dnsname() {
                        dns_sans.push(d);
                    } else if let Some(u) = name.uri() {
                        uri_sans.push(u);
                    }
                }
            }

            if san_stack.is_none() || (dns_sans.is_empty() && uri_sans.is_empty()) {
                // Cert has no usable SANs — fail-closed.
                tracing::warn!(
                    "upstream SAN check: peer cert has no DNS or URI SANs — marking mismatch"
                );
                return Some(Arc::new(UpstreamSanMismatch) as Arc<dyn Any + Send + Sync>);
            }

            if san_set_matches(&sans, &dns_sans, &uri_sans) {
                // Match — return None (no marker; connection proceeds normally).
                None
            } else {
                tracing::warn!(
                    dns_sans = ?dns_sans,
                    uri_sans = ?uri_sans,
                    "upstream SAN check: peer cert SANs do not match BackendTLSPolicy \
                     subjectAltNames — marking mismatch"
                );
                Some(Arc::new(UpstreamSanMismatch) as Arc<dyn Any + Send + Sync>)
            }
        });
        self.inner.get_or_insert(group_key, hook)
    }
}

/// Thread-safe cache mapping `group_key` → parsed `CaType`.
///
/// Entries accumulate until process restart; the number of distinct CA bundles is
/// bounded by the number of `BackendTLSPolicy` resources, which is small in practice.
#[non_exhaustive]
#[derive(Default)]
pub struct UpstreamCaCache {
    inner: GroupKeyCache<Arc<CaType>>,
}

impl UpstreamCaCache {
    /// Construct an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the cached bundle for `group_key`, or parse `pem` on first access.
    ///
    /// Returns `None` when the PEM is malformed — callers should respond with 502.
    pub fn get_or_parse(&self, group_key: u64, pem: &[u8]) -> Option<Arc<CaType>> {
        if let Some(cached) = self.inner.get(group_key) {
            return Some(cached);
        }
        // Parse outside the lock so we don't hold it during the crypto call.
        let stack = X509::stack_from_pem(pem)
            .map_err(|e| tracing::warn!(error = %e, "UpstreamCaCache: PEM parse failed"))
            .ok()?;
        let bundle: Arc<CaType> = Arc::new(stack.into_boxed_slice());
        Some(self.inner.get_or_insert(group_key, bundle))
    }
}

/// Thread-safe cache mapping `group_key` → parsed [`CertKey`] for GEP-3155 backend
/// client certificates.
///
/// `group_key` already encodes the cert identity (mixed in by
/// [`UpstreamTls::with_client_cert`]). Entries accumulate until process restart;
/// the number of distinct gateway client certs is bounded in practice.
///
/// Reads take only a `DashMap` shard lock, never across `.await` — `upstream_peer` is synchronous.
#[non_exhaustive]
#[derive(Default)]
pub struct BackendClientCertCache {
    inner: GroupKeyCache<Arc<CertKey>>,
}

impl BackendClientCertCache {
    /// Construct an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the cached [`CertKey`] for `group_key`, or parse the PEM pair on first
    /// access.
    ///
    /// Returns `None` when either PEM is malformed — callers should respond with 502.
    pub fn get_or_parse(
        &self,
        group_key: u64,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Option<Arc<CertKey>> {
        if let Some(cached) = self.inner.get(group_key) {
            return Some(cached);
        }
        // Parse outside the lock so we don't hold it during the crypto calls.
        let certs = X509::stack_from_pem(cert_pem)
            .map_err(
                |e| tracing::warn!(error = %e, "BackendClientCertCache: cert PEM parse failed"),
            )
            .ok()?;
        if certs.is_empty() {
            tracing::warn!("BackendClientCertCache: cert PEM contains no certificates");
            return None;
        }
        let pkey = PKey::private_key_from_pem(key_pem)
            .map_err(|e| tracing::warn!(error = %e, "BackendClientCertCache: key PEM parse failed"))
            .ok()?;
        let cert_key = Arc::new(CertKey::new(certs, pkey));
        Some(self.inner.get_or_insert(group_key, cert_key))
    }
}

/// Apply all upstream-TLS material to `peer` — the single site for upstream-TLS
/// peer mutation (CLAUDE.md). Sets `verify_cert` / `verify_hostname` / `group_key`,
/// then (when a `BackendTLSPolicy` is attached) the CA bundle, the GEP-3155 backend
/// client certificate, and the GEP-1897 `subjectAltNames` identity check.
///
/// `btls` is `None` for a cleartext upstream: hostname/cert verification is turned
/// off and the function returns early. The caller still builds the `HttpPeer` with
/// its SNI hostname, because the `HttpPeer::new` constructor takes ownership of it.
///
/// All three caches ensure the crypto work runs at most once per distinct
/// `group_key`; subsequent connections return the cached parsed objects.
///
/// When `subjectAltNames` is non-empty:
/// - Pingora's built-in hostname check is **disabled** (`verify_hostname=false`).
///   Chain validation (`verify_cert=true`) still runs via CA; `hostname` is used
///   only for SNI and cert selection per GEP-1897.
/// - A [`HandshakeCompleteHook`] is installed that inspects the peer leaf cert's
///   SAN extension and records [`UpstreamSanMismatch`] on failure. The
///   [`hooks::connected_to_upstream`](crate::hooks::connected_to_upstream) hook
///   reads the marker and returns a 502 before sending any request bytes upstream.
///
/// # Errors
///
/// Returns a `502` error when either PEM fails to parse.
pub(crate) fn apply_upstream_tls(
    peer: &mut HttpPeer,
    btls: Option<&UpstreamTls>,
    ca_cache: &UpstreamCaCache,
    client_cert_cache: &BackendClientCertCache,
    san_hook_cache: &SanCheckHookCache,
) -> Result<()> {
    // Verify TLS iff a BackendTLSPolicy originates it; cleartext upstreams turn
    // both checks off and return before touching any cache.
    let is_tls = btls.is_some();
    peer.options.verify_cert = is_tls;
    peer.options.verify_hostname = is_tls;
    let Some(btls) = btls else {
        return Ok(());
    };
    peer.group_key = btls.group_key;
    if let UpstreamCa::Bundle(pem) = &btls.ca {
        let ca = ca_cache.get_or_parse(btls.group_key, pem).ok_or_else(|| {
            pingora_core::Error::explain(HTTPStatus(502), "BackendTLSPolicy CA bundle parse failed")
        })?;
        peer.options.ca = Some(ca);
    }
    if let Some(cc) = btls.client_cert() {
        let cert_key = client_cert_cache
            .get_or_parse(btls.group_key, &cc.cert_pem, &cc.key_pem)
            .ok_or_else(|| {
                pingora_core::Error::explain(
                    HTTPStatus(502),
                    "gateway backend client cert PEM parse failed",
                )
            })?;
        peer.client_cert_key = Some(cert_key);
    }
    if !btls.subject_alt_names().is_empty() {
        // Disable hostname-based authentication — the SAN check handles identity.
        // Chain validation (`verify_cert`) remains on so the CA still validates.
        peer.options.verify_hostname = false;
        let sans = Arc::clone(&btls.subject_alt_names);
        let hook = san_hook_cache.get_or_build(btls.group_key, sans);
        peer.options.upstream_tls_handshake_complete_hook = Some(hook);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal RSA-2048 self-signed cert + matching private key for PEM parse tests.
    const TEST_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
MIIDHTCCAgWgAwIBAgIUNcCxsn46+scSDqj7uBhpT1CXxmUwDQYJKoZIhvcNAQEL\n\
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjA2MjUxNTQ3MjdaFw0zNjA2MjIxNTQ3\n\
MjdaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n\
AoIBAQDFwbiE6d/xyz4i+3Jo5YgB7zONYCua5x8AyqXyNxSP+ikQexUHnMjm06aZ\n\
VXpYJjtu75pjttXtp4r+jVMvSRDK9sJXPdy5N/iiFxOJg+0RjKHB2q7+sp4Oyyxr\n\
uIy4Kqbn+tAAzrqVBxZ+4F3tnFs2vdM/M12xWMEAUbFJbwMmA9VP1ZppD8T4IPr+\n\
1E/3UdNmVEhk9Foexy7fjIK6HhWrEaqGpPUzg1mjNj84/evHh3SBemR0S/BjadqI\n\
+RCotbhvS0J4ZZ4EvK9oM/cpk8e6sRW6LiqhBmL0iHElqqdg/VPRaFfCtC5djnc5\n\
hzgNtIdJZoWOo1P//zhAYfzi7oWLAgMBAAGjcTBvMB0GA1UdDgQWBBT1LoA7+Juk\n\
G4YLC+M2y1FR0iH6SjAfBgNVHSMEGDAWgBT1LoA7+JukG4YLC+M2y1FR0iH6SjAP\n\
BgNVHRMBAf8EBTADAQH/MBwGA1UdEQQVMBOCEXBsYWNlaG9sZGVyLmxvY2FsMA0G\n\
CSqGSIb3DQEBCwUAA4IBAQAd6j5WFN9yZxIPWr6Q1/HZXPByBGTWAeoNcbRRwvfc\n\
szNyOoKjgdL6SOoWIMWak8fv3QpBz06kElZGr0/lITUhMNGECtL84r3q0J37jCcL\n\
HcmREHbycfN1KTpC46NI9p3ZFH22PQtLEbcMpr10ZLNpOlayTUHqPEU3iEnjzddo\n\
QJJyZfYo5fpj5yeouEJH29FPOoTqgATzUNTfoQQCrAmkzE1iuW/TUUlqUJnQU+NO\n\
AqApV84MNiilS2OxClASve1Gnu18n89nctr0bvh1Cbh456i2ttFwQsAE6mm2rUgN\n\
Vh/2IxKNxmJFqwJVO179LHCHyWVI0BdeWR2Ewl7uhZdj\n\
-----END CERTIFICATE-----\n";

    const TEST_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFwbiE6d/xyz4i\n\
+3Jo5YgB7zONYCua5x8AyqXyNxSP+ikQexUHnMjm06aZVXpYJjtu75pjttXtp4r+\n\
jVMvSRDK9sJXPdy5N/iiFxOJg+0RjKHB2q7+sp4OyyxruIy4Kqbn+tAAzrqVBxZ+\n\
4F3tnFs2vdM/M12xWMEAUbFJbwMmA9VP1ZppD8T4IPr+1E/3UdNmVEhk9Foexy7f\n\
jIK6HhWrEaqGpPUzg1mjNj84/evHh3SBemR0S/BjadqI+RCotbhvS0J4ZZ4EvK9o\n\
M/cpk8e6sRW6LiqhBmL0iHElqqdg/VPRaFfCtC5djnc5hzgNtIdJZoWOo1P//zhA\n\
Yfzi7oWLAgMBAAECggEABm9jvz/vfc24XjANRYo8y5vDc03kdHiv4sBR21GkTmA1\n\
a/1fIBg8Du9KjtdY9K1DJmdH8kBkB6F5z1zZnPRaqe12evCe52WeJliWq1UugxwS\n\
XshBzBiFUryxeBOt0Qe4D3kBUBnb1XdPTUHBR2Gj+uJSkWql4JU71pDDwLyZG6+S\n\
+iZlxeb+5QgBP53bhDBsUkKgD1ZbkKgBpW5gkhMmDU31fy+vkyAulCyHVQTLcVFq\n\
p8BrGl+FSxQ//1HEq7FlMSXqrHODIjjdtW2A15RhRj6LdQU3c8dlfGwCWy1cJhsK\n\
r5mBcOEFlpTu1h5SalqfdPsdZPaAB4dQDFlAPMMlvQKBgQD4Pjm6yif1CGOHo3qB\n\
fWIBB0wOK+/cSW4b9pUKy/k/h8GmT6CTpB7uMvPGXeOd+mu106tx+Ti/wxgGLJrh\n\
frL+RmsG7jcP/2Di72Qvpiql9gTNtaCCoeQdsW292sePRZf69t3R9hLCbWRqcnDL\n\
CtP5rozIAJlca6ZgkJC6yoTsZwKBgQDL76Oa+Y6qm3asTuaJyZdNyn6z1BEMKO8w\n\
OjmGIleIIWdogThmlZ3tjZ3gKkfv9LZGEIhw1dFH73zohPFvbjZmAzyeWxH8/Yk1\n\
hNZBfcg4vAS2uIUkr6AHK2kBwAOekDZqjKNu0ZjBhyw/RMO1A7Z8/lQ10BnCkkkI\n\
3TQbpb2nPQKBgQDcf0j/5TiAqabegBL8mcZHa5ferqArZv3q0KeqI2uNRqR3eRsE\n\
iS8AHTny5MqdNCYgJ5eNcPU7P6tDMLORv9x1h07hpQ47o3cHm+O9fzc6mr/BiKa9\n\
4dahmUwE6yN+2y4XuNdm+8/F6yzacDRH5aJLkQNzUzTlpqjt9PrZL7HJ2QKBgDo7\n\
0cH9JQn+nqKRXS9XS0dBXXDIS53nSnXBCpAM2mXa9AZZb9uLOa+N0tkh+azBehMD\n\
wZJG3B3oewiCfdbN5+a1YefuJXLSiw2nQu8slbHtroLmqc5SACZL9Q404FO05nUC\n\
d+C7JR2OFcpzPldAGioTDcTYCaMP1p8bWzfR2hgZAoGBAKt01fInwN3htxcRMuTA\n\
vETnNl9yL+tJwZCVqD2/EYSYSS/cGKM2nh6ChY9ILlva0/HyQkcUlNSbBn5pAgau\n\
900Pbw8zk0nK5VU4XtY71USqo4mL9EQsIo/uIklU5tKQiI2G5e9OJafxQ+WW7fip\n\
wXjQFH8Mxs0ZjjX0/p7c1uxo\n\
-----END PRIVATE KEY-----\n";

    #[test]
    fn backend_client_cert_cache_parses_and_caches() {
        let cache = BackendClientCertCache::new();
        let first = cache.get_or_parse(1, TEST_CERT_PEM, TEST_KEY_PEM);
        assert!(first.is_some(), "valid PEM pair must parse");
        let second = cache.get_or_parse(1, TEST_CERT_PEM, TEST_KEY_PEM);
        assert!(
            Arc::ptr_eq(first.as_ref().unwrap(), second.as_ref().unwrap()),
            "second call must return the same Arc (cached)"
        );
    }

    #[test]
    fn backend_client_cert_cache_returns_none_for_malformed_cert() {
        let cache = BackendClientCertCache::new();
        let result = cache.get_or_parse(42, b"not a cert", TEST_KEY_PEM);
        assert!(result.is_none(), "malformed cert PEM must return None");
    }

    #[test]
    fn backend_client_cert_cache_returns_none_for_malformed_key() {
        let cache = BackendClientCertCache::new();
        let result = cache.get_or_parse(43, TEST_CERT_PEM, b"not a key");
        assert!(result.is_none(), "malformed key PEM must return None");
    }
}
