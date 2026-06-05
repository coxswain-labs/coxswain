use crate::keys::RouteParentKey;
use arc_swap::ArcSwap;
use coxswain_core::ownership::ObjectKey;
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
    #[error("Secret TLS data is not valid PEM")]
    InvalidPem,
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

    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::RefNotPermitted { .. } => "RefNotPermitted",
            Self::InvalidCertificateRef { .. } => "InvalidCertificateRef",
            Self::Invalid { .. } => "Invalid",
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
    /// Number of routes attached to each listener, keyed by listener name.
    /// Populated by the reconciler's route-counting pass after the TLS walk.
    pub attached_routes: BTreeMap<String, i32>,
    /// Hostname restriction for each listener (empty string = match all).
    /// Used by the route-counting pass to filter routes by hostname.
    pub listener_hostnames: BTreeMap<String, String>,
    /// Whether each listener allows routes from any namespace (true) or only
    /// from the same namespace as the Gateway (false, the default per spec).
    pub listener_allows_all_namespaces: BTreeMap<String, bool>,
    /// Port number for each listener, keyed by listener name.
    /// Used to validate parentRef.port against listener ports.
    pub listener_ports: BTreeMap<String, u16>,
}

struct GatewayListenerHealthInner {
    map: ArcSwap<HashMap<ObjectKey, GatewayListenerHealth>>,
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

    pub fn load(&self) -> arc_swap::Guard<Arc<HashMap<ObjectKey, GatewayListenerHealth>>> {
        self.0.map.load()
    }

    /// Store a new health map and wake any `notified()` waiters.
    pub fn store_and_notify(&self, map: HashMap<ObjectKey, GatewayListenerHealth>) {
        self.0.map.store(Arc::new(map));
        self.0.notify.notify_waiters();
    }

    /// Returns a future that resolves once `store_and_notify` is called.
    pub async fn notified(&self) {
        self.0.notify.notified().await;
    }
}

/// Health status for one (HTTPRoute, parent Gateway) pair.
#[derive(Clone, Debug)]
pub struct RouteParentHealth {
    /// True when all backend refs are valid and resolvable.
    pub resolved_refs: bool,
    /// Reason string for `ResolvedRefs=False` (ignored when `resolved_refs=true`).
    pub resolved_refs_reason: &'static str,
    /// True when the route's hostnames intersect with the listener's hostname,
    /// or there is no hostname restriction.
    pub accepted: bool,
    /// Reason string for `Accepted=False` (ignored when `accepted=true`).
    pub accepted_reason: &'static str,
}

impl Default for RouteParentHealth {
    fn default() -> Self {
        Self {
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs",
            accepted: true,
            accepted_reason: "Accepted",
        }
    }
}

pub type HttpRouteHealthMap = HashMap<RouteParentKey, RouteParentHealth>;

struct SharedHttpRouteHealthInner {
    map: ArcSwap<HttpRouteHealthMap>,
    notify: Notify,
}

/// Shared handle to per-(route, parent) health, produced after each reconciler rebuild.
/// The controller reads this to set accurate `Accepted` and `ResolvedRefs` conditions.
#[derive(Clone)]
pub struct SharedHttpRouteHealth(Arc<SharedHttpRouteHealthInner>);

impl Default for SharedHttpRouteHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedHttpRouteHealth {
    pub fn new() -> Self {
        Self(Arc::new(SharedHttpRouteHealthInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            notify: Notify::new(),
        }))
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<HttpRouteHealthMap>> {
        self.0.map.load()
    }

    /// Store a new health map and wake any `notified()` waiters.
    pub fn store_and_notify(&self, map: HttpRouteHealthMap) {
        self.0.map.store(Arc::new(map));
        self.0.notify.notify_one();
    }

    /// Returns a future that resolves once `store_and_notify` is called.
    pub async fn notified(&self) {
        self.0.notify.notified().await;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// BackendTLSPolicy health
// ──────────────────────────────────────────────────────────────────────────────

pub use crate::backend_tls::{PolicyHealthOutcome, PolicyKey};

/// Which managed Gateways are considered the ancestors of a BackendTLSPolicy.
/// A policy's Service is an ancestor's downstream iff at least one HTTPRoute
/// under that Gateway references the Service.
#[derive(Clone, Debug, Default)]
pub struct BackendTlsPolicyAncestorHealth {
    /// Keys of managed Gateways that have routes targeting the policy's Service.
    pub gateway_keys: Vec<ObjectKey>,
    pub outcome: Option<PolicyHealthOutcome>,
}

pub type BackendTlsPolicyHealthMap = HashMap<PolicyKey, BackendTlsPolicyAncestorHealth>;

struct SharedBackendTlsPolicyHealthInner {
    map: ArcSwap<BackendTlsPolicyHealthMap>,
    notify: Notify,
}

/// Shared handle to per-policy health, produced after each reconciler rebuild.
/// The controller reads this to write `BackendTLSPolicy.status.ancestors`.
#[derive(Clone)]
pub struct SharedBackendTlsPolicyHealth(Arc<SharedBackendTlsPolicyHealthInner>);

impl Default for SharedBackendTlsPolicyHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedBackendTlsPolicyHealth {
    pub fn new() -> Self {
        Self(Arc::new(SharedBackendTlsPolicyHealthInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            notify: Notify::new(),
        }))
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<BackendTlsPolicyHealthMap>> {
        self.0.map.load()
    }

    pub fn store_and_notify(&self, map: BackendTlsPolicyHealthMap) {
        self.0.map.store(Arc::new(map));
        self.0.notify.notify_one();
    }

    pub async fn notified(&self) {
        self.0.notify.notified().await;
    }
}

/// Look up a `kubernetes.io/tls` Secret by namespace/name from the reflector
/// store and extract the PEM bytes. Both cert and key data must contain a PEM
/// header (`-----BEGIN`) to be considered valid.
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

    if !cert_pem.windows(10).any(|w| w == b"-----BEGIN") {
        return Err(TlsLoadError::InvalidPem);
    }
    if !key_pem.windows(10).any(|w| w == b"-----BEGIN") {
        return Err(TlsLoadError::InvalidPem);
    }

    Ok(TlsCert::new(cert_pem, key_pem, format!("{ns}/{name}")))
}
