//! Per-listener health data types shared by the reflector and discovery wire layer.
//!
//! Pure data types ([`GatewayListenerHealth`], [`ListenerInfo`],
//! [`ListenerTlsOutcome`]) are kept here so the discovery wire layer can import
//! them without pulling in the reflector crate.
//!
//! [`SharedGatewayListenerHealth`] is the `ArcSwap` + `watch` wrapper that the
//! controller writes into and the proxy reads from. It lives here so
//! `coxswain-discovery` can implement [`crate::RoutingSource`] without
//! depending on `coxswain-reflector`.

use arc_swap::ArcSwap;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::watch;

/// Outcome of resolving one HTTPS listener's TLS configuration during a rebuild.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub enum ListenerTlsOutcome {
    /// Non-HTTPS listener — no TLS check performed.
    #[default]
    NotApplicable,
    /// HTTPS listener; certificate resolved and installed in the TLS store.
    Resolved,
    /// `certificateRefs[0].namespace` differs from the Gateway namespace and
    /// no matching `ReferenceGrant` was found.
    RefNotPermitted {
        /// Human-readable description of why the ref was not permitted.
        message: String,
    },
    /// Secret missing, wrong type, or missing `tls.crt` / `tls.key` keys.
    InvalidCertificateRef {
        /// Human-readable description of the certificate error.
        message: String,
    },
    /// Listener configuration is invalid (e.g. no `hostname`, unsupported mode).
    Invalid {
        /// Human-readable description of the configuration error.
        message: String,
    },
}

impl ListenerTlsOutcome {
    /// Returns `true` for outcomes the controller should treat as healthy.
    ///
    /// `NotApplicable` (non-HTTPS listener) and `Resolved` are healthy; every
    /// failure variant is unhealthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::NotApplicable | Self::Resolved)
    }

    /// Stable reason string for the `Programmed` listener condition.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::RefNotPermitted { .. } => "RefNotPermitted",
            Self::InvalidCertificateRef { .. } => "InvalidCertificateRef",
            Self::Invalid { .. } => "Invalid",
            Self::NotApplicable | Self::Resolved => "Resolved",
        }
    }

    /// Human-readable message attached to the `Programmed` listener condition.
    /// Empty for healthy outcomes.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::RefNotPermitted { message }
            | Self::InvalidCertificateRef { message }
            | Self::Invalid { message } => message.as_str(),
            Self::NotApplicable | Self::Resolved => "",
        }
    }
}

/// Consolidated per-listener metadata for one Gateway listener.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct ListenerInfo {
    /// TLS resolution outcome for this listener.
    pub tls_outcome: ListenerTlsOutcome,
    /// Number of routes attached to this listener.
    ///
    /// Populated by the reconciler's route-counting pass after the TLS walk.
    pub attached_routes: i32,
    /// Hostname restriction (empty string = match all).
    ///
    /// Used by the route-counting pass to filter routes by hostname.
    pub hostname: String,
    /// Whether routes from any namespace are allowed (`true`) or only from
    /// the same namespace as the Gateway (`false`, the spec default).
    pub allows_all_namespaces: bool,
    /// Listener port number.
    pub port: u16,
}

/// Per-listener health for one Gateway, keyed by listener name.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct GatewayListenerHealth {
    /// All listeners for this Gateway. Keyed by listener name.
    pub listeners: BTreeMap<String, ListenerInfo>,
}

// ── SharedGatewayListenerHealth ───────────────────────────────────────────────

use crate::ownership::ObjectKey;

struct GatewayListenerHealthInner {
    map: ArcSwap<HashMap<ObjectKey, GatewayListenerHealth>>,
    tx: watch::Sender<u64>,
}

/// Shared handle to the per-Gateway listener health map.
///
/// Written by the controller's reconciler (via `store_and_notify`) after each
/// routing-table rebuild; read by the proxy's `ListenerSpecsAdapter` background
/// service to drive dynamic Gateway listener port bind/unbind.
///
/// Backed by a `tokio::sync::watch` channel carrying a monotonic generation
/// counter: each consumer holds its own `Receiver` and awaits `changed()`. This
/// is robust to `select!` cancellation (a missed wake is recovered by the next
/// `changed()` call, which compares the receiver's last-seen generation to the
/// sender's current one) and supports any number of consumers without starving —
/// both requirements that `tokio::sync::Notify` cannot meet simultaneously.
#[non_exhaustive]
#[derive(Clone)]
pub struct SharedGatewayListenerHealth(Arc<GatewayListenerHealthInner>);

impl Default for SharedGatewayListenerHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedGatewayListenerHealth {
    /// Construct a new shared health map (initially empty, generation 0).
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0u64);
        Self(Arc::new(GatewayListenerHealthInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            tx,
        }))
    }

    /// Load the current health map snapshot.
    pub fn load(&self) -> arc_swap::Guard<Arc<HashMap<ObjectKey, GatewayListenerHealth>>> {
        self.0.map.load()
    }

    /// Store a new health map and notify every subscribed `Receiver` that the
    /// generation has advanced.
    pub fn store_and_notify(&self, map: HashMap<ObjectKey, GatewayListenerHealth>) {
        self.0.map.store(Arc::new(map));
        self.0.tx.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Returns a `watch::Receiver` over the generation counter. The caller polls
    /// `rx.changed().await` to await the next `store_and_notify` call.
    ///
    /// Subscribing returns a receiver whose "seen" generation equals the current
    /// sender generation. Call `rx.mark_changed()` immediately after if you want
    /// the first `changed()` to fire even when no publish has happened yet.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.tx.subscribe()
    }
}
