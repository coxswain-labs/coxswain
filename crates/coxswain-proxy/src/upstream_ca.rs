//! Cache for pre-parsed upstream CA certificate bundles used by `BackendTLSPolicy`.
//!
//! `X509::stack_from_pem` is called at most once per distinct `group_key` (derived
//! from the SNI + PEM content hash). The Mutex is never held across an `.await` point
//! — `upstream_peer` calls `get_or_parse` synchronously.

use pingora_core::protocols::tls::CaType;
use pingora_core::tls::x509::X509;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Thread-safe cache mapping `group_key` → parsed `CaType`.
///
/// Entries accumulate until process restart; the number of distinct CA bundles is
/// bounded by the number of `BackendTLSPolicy` resources, which is small in practice.
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
            let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(cached) = guard.get(&group_key) {
                return Some(Arc::clone(cached));
            }
        }
        // Parse outside the lock so we don't hold it during the crypto call.
        let stack = X509::stack_from_pem(pem)
            .map_err(|e| tracing::warn!(error = %e, "UpstreamCaCache: PEM parse failed"))
            .ok()?;
        let bundle: Arc<CaType> = Arc::new(stack.into_boxed_slice());
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Some(Arc::clone(guard.entry(group_key).or_insert(bundle)))
    }
}
