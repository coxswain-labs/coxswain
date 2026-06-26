//! Cache for pre-parsed upstream TLS objects used by `BackendTLSPolicy` and GEP-3155.
//!
//! `X509::stack_from_pem` and `CertKey::new` are called at most once per distinct
//! `group_key`. The Mutex is never held across an `.await` point — `upstream_peer`
//! calls `get_or_parse` synchronously.

use coxswain_core::routing::{UpstreamCa, UpstreamTls};
use parking_lot::Mutex;
use pingora_core::protocols::tls::CaType;
use pingora_core::tls::{pkey::PKey, x509::X509};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::utils::tls::CertKey;
use pingora_core::{HTTPStatus, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// Thread-safe cache mapping `group_key` → parsed `CaType`.
///
/// Entries accumulate until process restart; the number of distinct CA bundles is
/// bounded by the number of `BackendTLSPolicy` resources, which is small in practice.
#[non_exhaustive]
#[derive(Default)]
pub struct UpstreamCaCache {
    inner: Mutex<HashMap<u64, Arc<CaType>>>,
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
        {
            let guard = self.inner.lock();
            if let Some(cached) = guard.get(&group_key) {
                return Some(Arc::clone(cached));
            }
        }
        // Parse outside the lock so we don't hold it during the crypto call.
        let stack = X509::stack_from_pem(pem)
            .map_err(|e| tracing::warn!(error = %e, "UpstreamCaCache: PEM parse failed"))
            .ok()?;
        let bundle: Arc<CaType> = Arc::new(stack.into_boxed_slice());
        let mut guard = self.inner.lock();
        Some(Arc::clone(guard.entry(group_key).or_insert(bundle)))
    }
}

/// Thread-safe cache mapping `group_key` → parsed [`CertKey`] for GEP-3155 backend
/// client certificates.
///
/// `group_key` already encodes the cert identity (mixed in by
/// [`UpstreamTls::with_client_cert`]). Entries accumulate until process restart;
/// the number of distinct gateway client certs is bounded in practice.
///
/// The Mutex is never held across an `.await` point — `upstream_peer` is synchronous.
#[non_exhaustive]
#[derive(Default)]
pub struct BackendClientCertCache {
    inner: Mutex<HashMap<u64, Arc<CertKey>>>,
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
        {
            let guard = self.inner.lock();
            if let Some(cached) = guard.get(&group_key) {
                return Some(Arc::clone(cached));
            }
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
        let mut guard = self.inner.lock();
        Some(Arc::clone(guard.entry(group_key).or_insert(cert_key)))
    }
}

/// Apply all `BackendTLSPolicy`-driven TLS material to `peer`: CA bundle and
/// (when present) the GEP-3155 backend client certificate.
///
/// Both caches ensure the crypto work runs at most once per distinct
/// `group_key`; subsequent connections return the cached parsed objects.
///
/// # Errors
///
/// Returns a `502` error when either PEM fails to parse.
pub(crate) fn apply_upstream_tls(
    peer: &mut HttpPeer,
    btls: &UpstreamTls,
    ca_cache: &UpstreamCaCache,
    client_cert_cache: &BackendClientCertCache,
) -> Result<()> {
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
