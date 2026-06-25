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
    /// HTTPS listener; at least one `certificateRef` resolved but at least one
    /// failed (e.g. Secret missing, wrong type, or a denied `ReferenceGrant`).
    ///
    /// The listener **continues serving** the successfully-resolved certificates
    /// so traffic is not interrupted when one cert in a dual-algorithm or
    /// rotation-overlap set breaks. The degraded state is surfaced via a
    /// `ResolvedRefs=False / InvalidCertificateRef` condition so operators can
    /// detect and fix the broken ref. This mirrors the graceful-degradation
    /// approach used by Envoy-based implementations (GEP-851).
    ResolvedPartial {
        /// Human-readable description naming the failed ref(s) and why they failed.
        message: String,
    },
}

impl ListenerTlsOutcome {
    /// Returns `true` when this listener is an HTTPS listener that is serving
    /// at least one certificate.
    ///
    /// Both `Resolved` and `ResolvedPartial` return `true` — the listener is
    /// operational even when some refs failed. Used to decide which listeners
    /// contribute to the per-port listener-hostname snapshot for
    /// misdirected-request detection (GEP-3567, #96).
    #[must_use]
    pub fn is_https_terminate(&self) -> bool {
        matches!(self, Self::Resolved | Self::ResolvedPartial { .. })
    }

    /// Returns `true` for outcomes the controller should treat as healthy.
    ///
    /// `NotApplicable` (non-HTTPS listener) and `Resolved` (all refs resolved)
    /// are healthy. `ResolvedPartial` is **not** healthy — it carries a degraded
    /// `ResolvedRefs=False` condition — even though the listener is still serving.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::NotApplicable | Self::Resolved)
    }

    /// Stable reason string for the `Programmed` listener condition.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::RefNotPermitted { .. } => "RefNotPermitted",
            Self::InvalidCertificateRef { .. } | Self::ResolvedPartial { .. } => {
                "InvalidCertificateRef"
            }
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
            | Self::Invalid { message }
            | Self::ResolvedPartial { message } => message.as_str(),
            Self::NotApplicable | Self::Resolved => "",
        }
    }
}

/// Outcome of resolving one HTTPS listener's GEP-91 frontend client-certificate
/// validation CA ref (`spec.tls.frontend.{default,perPort}.validation`).
///
/// Frontend validation is resolved **per listener**: the effective config is the
/// `perPort[listener.port]` override if present, else the gateway-wide `default`.
/// Each variant drives the listener's `ResolvedRefs`/`Accepted`/`Programmed`
/// status conditions to the exact reasons the GEP-91 conformance suite asserts.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub enum FrontendValidationOutcome {
    /// Non-HTTPS listener, or no frontend validation applies to it.
    #[default]
    NotApplicable,
    /// CA ref resolved; the listener validates client certs against it.
    Resolved,
    /// The referenced ConfigMap is missing, has no `ca.crt`, or isn't PEM —
    /// `ResolvedRefs=False/InvalidCACertificateRef`.
    InvalidCACertificateRef {
        /// Human-readable description of the resolution failure.
        message: String,
    },
    /// The CA ref kind is not `core/ConfigMap` —
    /// `ResolvedRefs=False/InvalidCACertificateKind`.
    InvalidCACertificateKind {
        /// Human-readable description naming the unsupported kind.
        message: String,
    },
    /// A cross-namespace CA ref with no permitting `ReferenceGrant` —
    /// `ResolvedRefs=False/RefNotPermitted`.
    RefNotPermitted {
        /// Human-readable description of the denied cross-namespace ref.
        message: String,
    },
}

impl FrontendValidationOutcome {
    /// `true` when frontend validation was configured for this listener but its
    /// CA ref could not be resolved — the listener fails closed and surfaces a
    /// `False` condition triplet.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(
            self,
            Self::InvalidCACertificateRef { .. }
                | Self::InvalidCACertificateKind { .. }
                | Self::RefNotPermitted { .. }
        )
    }

    /// Stable reason string for the `ResolvedRefs` listener condition when failed.
    #[must_use]
    pub fn resolved_refs_reason(&self) -> &'static str {
        match self {
            Self::InvalidCACertificateRef { .. } => "InvalidCACertificateRef",
            Self::InvalidCACertificateKind { .. } => "InvalidCACertificateKind",
            Self::RefNotPermitted { .. } => "RefNotPermitted",
            Self::NotApplicable | Self::Resolved => "ResolvedRefs",
        }
    }

    /// Human-readable message attached to the failed conditions; empty otherwise.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::InvalidCACertificateRef { message }
            | Self::InvalidCACertificateKind { message }
            | Self::RefNotPermitted { message } => message.as_str(),
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
    /// GEP-91 frontend client-cert validation outcome for this listener (#86).
    ///
    /// Computed in the controller's reconcile (not transported over the
    /// discovery wire — the proxy never reads it); consumed by the status
    /// writer to set the listener's `ResolvedRefs`/`Accepted`/`Programmed`
    /// conditions when a frontend CA ref fails to resolve.
    pub frontend_outcome: FrontendValidationOutcome,
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

/// Outcome of resolving the Gateway-wide frontend client-certificate validation
/// config (GEP-91, `spec.tls.frontend.default.validation`).
///
/// Produced during each reconciler rebuild and consumed by the controller's
/// status writer to emit the `InsecureFrontendValidationMode` condition.
/// `None` on a [`GatewayListenerHealth`] means no frontend validation is configured.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct FrontendValidationHealth {
    /// `true` when the effective mode is `AllowInsecureFallback`.
    ///
    /// Triggers a `InsecureFrontendValidationMode=True/ConfigurationChanged` top-level
    /// condition on the Gateway (GEP-91 requirement).
    pub insecure_fallback: bool,
    /// `true` when all CA ConfigMap refs resolved successfully; `false` when any ref
    /// was missing, held no `ca.crt` key, or lacked a valid PEM header.
    ///
    /// A `false` value here means the proxy fail-closed (every handshake rejected for
    /// the affected hostnames) and the controller should log a warning and emit an Event.
    pub resolved_refs: bool,
    /// Human-readable description for the `resolved_refs=false` case.
    pub message: String,
}

/// Per-listener health for one Gateway, keyed by listener name.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct GatewayListenerHealth {
    /// All listeners for this Gateway. Keyed by listener name.
    pub listeners: BTreeMap<String, ListenerInfo>,
    /// Frontend client-certificate validation health for this Gateway (GEP-91, #86).
    ///
    /// `None` when `spec.tls.frontend.default.validation` is absent.
    /// `Some` when the field is present, regardless of whether refs resolved.
    pub frontend_validation: Option<FrontendValidationHealth>,
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

    /// Atomically merge a single writer's `updates` into the shared map without
    /// clobbering entries owned by OTHER writers.
    ///
    /// Several reconcilers publish into one cell — the shared-pool reconciler
    /// (all non-cut-over Gateways) and each dedicated-proxy reconciler (its one
    /// cut-over Gateway) — but each only computes a SUBSET of Gateways. A plain
    /// [`Self::store_and_notify`] replaces the whole map with that subset,
    /// transiently dropping the others' entries; under concurrent reconciles a
    /// dedicated proxy then briefly loses (and unbinds) its own listener. This
    /// instead, atomically via `rcu`:
    ///   - keeps every entry this writer does **not** own (`owns(k) == false`)
    ///     exactly as-is, and
    ///   - replaces the entries it **does** own with `updates` — so an owned
    ///     Gateway that vanished from `updates` (deleted/migrated) is removed.
    ///
    /// Consumers are notified after the swap.
    pub fn update_scoped(
        &self,
        updates: HashMap<ObjectKey, GatewayListenerHealth>,
        owns: impl Fn(&ObjectKey) -> bool,
    ) {
        self.0.map.rcu(|current| {
            let mut next: HashMap<ObjectKey, GatewayListenerHealth> = current
                .iter()
                .filter(|(k, _)| !owns(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            next.extend(updates.iter().map(|(k, v)| (k.clone(), v.clone())));
            Arc::new(next)
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_outcome_reason_and_failed_flags() {
        let msg = || "boom".to_string();
        let cases = [
            (
                FrontendValidationOutcome::NotApplicable,
                false,
                "ResolvedRefs",
            ),
            (FrontendValidationOutcome::Resolved, false, "ResolvedRefs"),
            (
                FrontendValidationOutcome::InvalidCACertificateRef { message: msg() },
                true,
                "InvalidCACertificateRef",
            ),
            (
                FrontendValidationOutcome::InvalidCACertificateKind { message: msg() },
                true,
                "InvalidCACertificateKind",
            ),
            (
                FrontendValidationOutcome::RefNotPermitted { message: msg() },
                true,
                "RefNotPermitted",
            ),
        ];
        for (outcome, failed, reason) in cases {
            assert_eq!(outcome.is_failed(), failed, "is_failed for {outcome:?}");
            assert_eq!(
                outcome.resolved_refs_reason(),
                reason,
                "reason for {outcome:?}"
            );
        }
    }

    #[test]
    fn frontend_outcome_message_only_on_failures() {
        assert_eq!(FrontendValidationOutcome::Resolved.message(), "");
        assert_eq!(FrontendValidationOutcome::NotApplicable.message(), "");
        assert_eq!(
            FrontendValidationOutcome::RefNotPermitted {
                message: "denied".to_string()
            }
            .message(),
            "denied"
        );
    }
}
