use arc_swap::ArcSwap;
use coxswain_core::tls::TlsCert;
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::reflector;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Notify;

#[derive(Debug, Error)]
pub(crate) enum TlsLoadError {
    #[error("Secret not found in store")]
    NotFound,
    #[error("Secret has type {0:?}, expected 'kubernetes.io/tls'")]
    WrongType(String),
    #[error("Secret is missing 'tls.crt' key")]
    MissingCert,
    #[error("Secret is missing 'tls.key' key")]
    MissingKey,
}

/// Outcome of resolving one HTTPS listener's TLS configuration during a rebuild.
#[derive(Clone, Debug)]
pub enum ListenerTlsOutcome {
    /// Non-HTTPS listener — no TLS check performed.
    NotApplicable,
    /// HTTPS listener; certificate resolved and installed in the TLS store.
    Resolved,
    /// `certificateRefs[0].namespace` differs from the Gateway namespace and
    /// no matching `ReferenceGrant` was found.
    RefNotPermitted { message: String },
    /// Secret missing, wrong type, or missing `tls.crt` / `tls.key` keys.
    InvalidCertificateRef { message: String },
    /// Listener configuration is invalid (e.g. no `hostname`, unsupported mode).
    Invalid { message: String },
}

impl ListenerTlsOutcome {
    pub(crate) fn is_healthy(&self) -> bool {
        matches!(self, Self::NotApplicable | Self::Resolved)
    }

    pub(crate) fn ref_not_permitted_reason() -> &'static str {
        "RefNotPermitted"
    }
    pub(crate) fn invalid_cert_reason() -> &'static str {
        "InvalidCertificateRef"
    }
    pub(crate) fn invalid_reason() -> &'static str {
        "Invalid"
    }

    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::RefNotPermitted { .. } => Self::ref_not_permitted_reason(),
            Self::InvalidCertificateRef { .. } => Self::invalid_cert_reason(),
            Self::Invalid { .. } => Self::invalid_reason(),
            Self::NotApplicable | Self::Resolved => "Resolved",
        }
    }

    pub(crate) fn message(&self) -> &str {
        match self {
            Self::RefNotPermitted { message }
            | Self::InvalidCertificateRef { message }
            | Self::Invalid { message } => message.as_str(),
            Self::NotApplicable | Self::Resolved => "",
        }
    }
}

/// Per-listener TLS health for one Gateway, keyed by listener name.
#[derive(Clone, Debug, Default)]
pub struct GatewayListenerHealth {
    pub by_listener: BTreeMap<String, ListenerTlsOutcome>,
    /// Number of routes successfully attached to each listener, keyed by listener name.
    /// Populated by the reconciler's route-counting pass after the TLS walk.
    pub attached_routes: BTreeMap<String, i32>,
}

impl GatewayListenerHealth {
    pub(crate) fn is_fully_programmed(&self) -> bool {
        self.by_listener.values().all(|o| o.is_healthy())
    }

    /// Returns the first failure reason + message for use in the Gateway-level
    /// `Programmed: False` condition when `is_fully_programmed` is false.
    pub(crate) fn first_failure(&self) -> Option<(&ListenerTlsOutcome, &str)> {
        self.by_listener
            .values()
            .find(|o| !o.is_healthy())
            .map(|o| (o, o.message()))
    }
}

struct GatewayListenerHealthInner {
    map: ArcSwap<HashMap<(String, String), GatewayListenerHealth>>,
    notify: Notify,
}

/// Shared handle to the per-Gateway listener health map produced after each rebuild.
/// Written by `Reconciler::rebuild` (via `store_and_notify`); read by `Controller`.
/// Bundles the data map and a `Notify` so callers don't need to manage them separately.
#[derive(Clone)]
pub struct SharedGatewayListenerHealth(Arc<GatewayListenerHealthInner>);

impl Default for SharedGatewayListenerHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedGatewayListenerHealth {
    pub fn new() -> Self {
        Self(Arc::new(GatewayListenerHealthInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            notify: Notify::new(),
        }))
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<HashMap<(String, String), GatewayListenerHealth>>> {
        self.0.map.load()
    }

    /// Store a new health map and wake any `notified()` waiters.
    pub fn store_and_notify(&self, map: HashMap<(String, String), GatewayListenerHealth>) {
        self.0.map.store(Arc::new(map));
        self.0.notify.notify_one();
    }

    /// Returns a future that resolves once `store_and_notify` is called.
    pub async fn notified(&self) {
        self.0.notify.notified().await;
    }
}

/// Look up a `kubernetes.io/tls` Secret by namespace/name from the reflector
/// store and extract the PEM bytes. PEM validity is checked by the proxy's
/// SNI callback on each handshake; invalid bytes produce a warning there.
pub(crate) fn load_tls_cert(
    ns: &str,
    name: &str,
    store: &reflector::Store<Secret>,
) -> Result<TlsCert, TlsLoadError> {
    let key = reflector::ObjectRef::<Secret>::new(name).within(ns);
    let secret = store.get(&key).ok_or(TlsLoadError::NotFound)?;

    let secret_type = secret.type_.as_deref().unwrap_or("");
    if secret_type != "kubernetes.io/tls" {
        return Err(TlsLoadError::WrongType(secret_type.to_string()));
    }

    let data = secret.data.as_ref().ok_or(TlsLoadError::MissingCert)?;
    let cert_pem = data
        .get("tls.crt")
        .ok_or(TlsLoadError::MissingCert)?
        .0
        .clone();
    let key_pem = data
        .get("tls.key")
        .ok_or(TlsLoadError::MissingKey)?
        .0
        .clone();

    Ok(TlsCert::new(cert_pem, key_pem, format!("{ns}/{name}")))
}
