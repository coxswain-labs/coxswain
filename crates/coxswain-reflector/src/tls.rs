//! TLS load helpers and shared health-map types for Gateway listeners, HTTPRoutes, and BackendTLSPolicies.

use crate::keys::RouteParentKey;
use arc_swap::ArcSwap;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::tls::{KeyAlgorithm, TlsCert};
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::reflector;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::watch;

// Pure data types and the shared wrapper live in coxswain-core so the
// discovery wire layer can import them without pulling in the reflector crate.
pub use coxswain_core::listener_health::SharedGatewayListenerHealth;
pub use coxswain_core::listener_health::{
    BackendClientCertOutcome, FrontendValidationHealth, FrontendValidationOutcome,
    GatewayListenerHealth, ListenerHealthKey, ListenerInfo, ListenerSource, ListenerTlsOutcome,
};

#[derive(Debug, Error)]
pub(crate) enum TlsLoadError {
    #[error("secret not found in store")]
    NotFound,
    #[error("secret has type {0:?}, expected 'kubernetes.io/tls'")]
    WrongType(String),
    #[error("secret is missing 'tls.crt' key")]
    MissingCert,
    #[error("secret is missing 'tls.key' key")]
    MissingKey,
    #[error("secret TLS data is not valid PEM")]
    InvalidPem,
}

/// Health status for one (HTTPRoute, parent Gateway) pair.
#[non_exhaustive]
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

/// Map from `(route, parent)` key to per-parent health status.
pub type RouteHealthMap = HashMap<RouteParentKey, RouteParentHealth>;

struct SharedRouteHealthInner {
    map: ArcSwap<RouteHealthMap>,
    tx: watch::Sender<u64>,
}

/// Shared handle to per-(route, parent) health, produced after each reconciler rebuild.
/// The controller reads this to set accurate `Accepted` and `ResolvedRefs` conditions.
///
/// See [`SharedGatewayListenerHealth`] for the rationale behind the `watch`-based
/// notification scheme.
#[non_exhaustive]
#[derive(Clone)]
pub struct SharedRouteHealth(Arc<SharedRouteHealthInner>);

impl Default for SharedRouteHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedRouteHealth {
    /// Construct a new shared route health map (initially empty, generation 0).
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0u64);
        Self(Arc::new(SharedRouteHealthInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            tx,
        }))
    }

    /// Load the current route health map snapshot.
    pub fn load(&self) -> arc_swap::Guard<Arc<RouteHealthMap>> {
        self.0.map.load()
    }

    /// Store a new health map and notify subscribers via the generation counter.
    pub fn store_and_notify(&self, map: RouteHealthMap) {
        self.0.map.store(Arc::new(map));
        self.0.tx.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Returns a `watch::Receiver` for subscribing to change notifications.
    /// See [`SharedGatewayListenerHealth::subscribe`].
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.tx.subscribe()
    }
}

/// Health status for one `BackendTLSPolicy`.
///
/// Produced during each reconciler rebuild and consumed by the controller's
/// leader-gated status writer.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct BackendTlsPolicyHealth {
    /// Owned Gateways that reference the policy's target Service via an HTTPRoute.
    /// Each becomes one entry in `status.ancestors[]`.
    pub ancestors: Vec<ObjectKey>,
    /// `true` when this policy wins conflict resolution for its target Service.
    pub accepted: bool,
    /// Reason string for the `Accepted` condition.
    pub accepted_reason: &'static str,
    /// `true` when all CA cert refs are valid and resolvable.
    pub resolved_refs: bool,
    /// Reason string for the `ResolvedRefs` condition.
    pub resolved_refs_reason: &'static str,
}

impl Default for BackendTlsPolicyHealth {
    fn default() -> Self {
        Self {
            ancestors: Vec::new(),
            accepted: true,
            accepted_reason: "Accepted",
            resolved_refs: true,
            resolved_refs_reason: "ResolvedRefs",
        }
    }
}

/// Map from `(policy_namespace, policy_name)` to its health status.
pub type BackendTlsPolicyHealthMap = HashMap<ObjectKey, BackendTlsPolicyHealth>;

struct SharedBackendTlsPolicyHealthInner {
    map: ArcSwap<BackendTlsPolicyHealthMap>,
    tx: watch::Sender<u64>,
}

/// Shared handle to per-`BackendTLSPolicy` health, produced after each reconciler rebuild.
/// The controller reads this to write `status.ancestors[]` when leader.
///
/// See [`SharedGatewayListenerHealth`] for the rationale behind the `watch`-based
/// notification scheme.
#[non_exhaustive]
#[derive(Clone)]
pub struct SharedBackendTlsPolicyHealth(Arc<SharedBackendTlsPolicyHealthInner>);

impl Default for SharedBackendTlsPolicyHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedBackendTlsPolicyHealth {
    /// Construct a new shared policy health map (initially empty, generation 0).
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0u64);
        Self(Arc::new(SharedBackendTlsPolicyHealthInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            tx,
        }))
    }

    /// Load the current policy health map snapshot.
    pub fn load(&self) -> arc_swap::Guard<Arc<BackendTlsPolicyHealthMap>> {
        self.0.map.load()
    }

    /// Store a new health map and notify subscribers via the generation counter.
    pub fn store_and_notify(&self, map: BackendTlsPolicyHealthMap) {
        self.0.map.store(Arc::new(map));
        self.0.tx.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Returns a `watch::Receiver` for subscribing to change notifications.
    /// See [`SharedGatewayListenerHealth::subscribe`].
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.tx.subscribe()
    }
}

/// Look up a `kubernetes.io/tls` Secret by namespace/name from the reflector
/// store and extract the PEM bytes. Both cert and key data must contain a PEM
/// header (`-----BEGIN`) to be considered valid.
///
/// # Errors
///
/// Returns [`TlsLoadError::NotFound`] if the Secret is not in the store,
/// [`TlsLoadError::WrongType`] if its `type` is not `kubernetes.io/tls`,
/// [`TlsLoadError::MissingCert`] if `tls.crt` is absent,
/// [`TlsLoadError::MissingKey`] if `tls.key` is absent, or
/// [`TlsLoadError::InvalidPem`] if either field lacks a `-----BEGIN` header.
#[must_use = "TLS certificate load result must be handled"]
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

    let (not_after, key_algorithm) = parse_leaf_cert_metadata(&cert_pem).unwrap_or_else(|e| {
        tracing::warn!(
            ns,
            name,
            error = %e,
            "TLS cert parse failed — expiry metric will omit this cert, algorithm defaults to Other"
        );
        (None, KeyAlgorithm::Other)
    });

    Ok(TlsCert::new(cert_pem, key_pem, format!("{ns}/{name}"))
        .with_not_after(not_after)
        .with_key_algorithm(key_algorithm))
}

/// Parse the leaf certificate's `notAfter` field and SPKI key algorithm in a
/// single parse pass.
///
/// Returns `Ok((None, Other))` if the chain parsed but contained no certificate
/// (a degenerate case — the expected shape for any well-formed
/// `kubernetes.io/tls` Secret is `Ok((Some(_), Rsa | Ecdsa))`). Returns `Err`
/// on PEM/ASN.1 parse failure.
fn parse_leaf_cert_metadata(
    cert_pem: &[u8],
) -> Result<(Option<std::time::SystemTime>, KeyAlgorithm), String> {
    use x509_parser::pem::Pem;
    use x509_parser::prelude::*;
    let mut reader = std::io::Cursor::new(cert_pem);
    let pem = Pem::read(&mut reader)
        .map_err(|e| format!("PEM parse: {e}"))?
        .0;
    let (_, cert) =
        parse_x509_certificate(&pem.contents).map_err(|e| format!("X509 parse: {e}"))?;

    // notAfter
    let not_after_unix = cert.validity().not_after.timestamp();
    let not_after = if not_after_unix < 0 {
        None
    } else {
        // `timestamp()` is a Unix epoch i64; convert to SystemTime via Duration.
        u64::try_from(not_after_unix)
            .ok()
            .map(|s| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s))
    };

    // SPKI key algorithm — match well-known OIDs by their dotted-decimal string.
    //
    // OIDs:
    //   rsaEncryption   1.2.840.113549.1.1.1  (RFC 3279)
    //   id-ecPublicKey  1.2.840.10045.2.1      (RFC 5480)
    let key_algorithm = match cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_string()
        .as_str()
    {
        "1.2.840.113549.1.1.1" => KeyAlgorithm::Rsa,
        "1.2.840.10045.2.1" => KeyAlgorithm::Ecdsa,
        _ => KeyAlgorithm::Other,
    };

    Ok((not_after, key_algorithm))
}
