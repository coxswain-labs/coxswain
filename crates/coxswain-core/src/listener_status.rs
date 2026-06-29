//! Per-listener status data types shared by the reflector and discovery wire layer.
//!
//! Pure data types ([`GatewayListenerStatus`], [`ListenerInfo`],
//! [`ListenerReadiness`]) are kept here so the discovery wire layer can import
//! them without pulling in the reflector crate.
//!
//! [`SharedGatewayListenerStatus`] is the `ArcSwap` + `watch` wrapper that the
//! controller writes into and the proxy reads from. It lives here so
//! `coxswain-discovery` can implement [`crate::RoutingSource`] without
//! depending on `coxswain-reflector`.

use crate::ownership::ObjectKey;
use arc_swap::ArcSwap;
use ipnet::IpNet;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;

/// Origin of a listener in a Gateway's effective listener set (GEP-1713).
///
/// A Gateway's effective listeners concatenate its own `spec.listeners` with the
/// listeners contributed by attached `ListenerSet`s. The spec permits the same
/// listener *name* on a Gateway and on its ListenerSets, and requires both to be
/// programmed — so per-listener status is keyed by source+name (see [`ListenerStatusKey`])
/// rather than name alone. The source also lets the controller attribute each
/// per-listener status back to the resource that declared it.
///
/// This is deliberately a closed two-variant enum: it is constructed via literal
/// by the reflector merge and the controller status writer and matched
/// exhaustively in both, so a third origin would be a deliberate, breaking model
/// change — never a silently-added variant. Hence the `// intentionally open:`
/// opt-out below rather than `#[non_exhaustive]` (which would force wildcard arms
/// and defeat the cross-crate exhaustiveness this relies on).
// intentionally open: closed enum matched exhaustively cross-crate; see doc above.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ListenerSource {
    /// Declared in the parent Gateway's own `spec.listeners`.
    Gateway,
    /// Contributed by a `ListenerSet`, identified by its `{namespace}/{name}` key.
    ListenerSet(ObjectKey),
}

/// Provenance-aware identity of one listener within a [`GatewayListenerStatus`].
///
/// Replaces a bare listener-name key: `(source, name)` is unique across a Gateway
/// and all its attached ListenerSets even when names collide. The derived `Ord`
/// (Gateway before ListenerSet, then by [`ObjectKey`], then by name) only fixes a
/// deterministic map/wire iteration order — it is **not** the GEP-1713 merge
/// precedence (creationTimestamp-first), which is computed explicitly in the merge.
// intentionally open: constructed via field literal at every producer/lookup site; no invariant to enforce.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenerStatusKey {
    /// The resource that declared this listener.
    pub source: ListenerSource,
    /// The listener's `name`, unique only within its own `source`.
    pub name: String,
}

impl ListenerStatusKey {
    /// Key for a listener declared directly on the parent Gateway.
    #[must_use]
    pub fn gateway(name: impl Into<String>) -> Self {
        Self {
            source: ListenerSource::Gateway,
            name: name.into(),
        }
    }

    /// Key for a listener contributed by the `ListenerSet` identified by `key`.
    #[must_use]
    pub fn listener_set(key: ObjectKey, name: impl Into<String>) -> Self {
        Self {
            source: ListenerSource::ListenerSet(key),
            name: name.into(),
        }
    }
}

/// A listener's readiness outcome, computed during a rebuild.
///
/// Despite the variants' TLS-specific failure causes, this models whether a
/// listener of ANY protocol is ready to serve — not just TLS. A plain HTTP
/// listener has nothing to resolve and is [`Self::NotApplicable`] (healthy); the
/// remaining variants record the TLS/certificate states that are the only way a
/// listener fails readiness today. [`Self::is_healthy`] gates the per-listener
/// `Programmed` condition for every listener, HTTP included.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub enum ListenerReadiness {
    /// Non-HTTPS listener (or otherwise nothing to resolve) — ready by default.
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
    /// Listener uses an unsupported protocol/mode combination.
    ///
    /// Surfaces `Accepted=False, reason=UnsupportedValue` on the Gateway listener.
    /// Currently emitted for `protocol: TLS, tls.mode: Terminate` listeners — only
    /// `tls.mode: Passthrough` is supported for TLS listeners (GEP-2643).
    Unsupported {
        /// Human-readable description of what is not supported.
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
    /// `protocol: TLS, tls.mode: Passthrough` listener (GEP-2643 / TLSRoute).
    ///
    /// The proxy peeks the ClientHello SNI and forwards the raw encrypted stream
    /// to the backend — no TLS is terminated at the proxy. The data plane creates
    /// a `ListenerProtocol::TlsL4` listener on this port.
    TlsPassthrough,
    /// `protocol: TLS, tls.mode: Terminate` listener (TLSRouteModeMixed / TLSRouteModeTerminate).
    ///
    /// The proxy terminates TLS using the listener cert selected by SNI, then
    /// L4-splices the decrypted plaintext stream to the backend over plain TCP —
    /// no HTTP parsing. The certificate is resolved into the per-port TLS store
    /// exactly as for HTTPS; routing is by SNI hostname, not HTTP headers.
    TlsTerminate,
}

impl ListenerReadiness {
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
    /// `NotApplicable` (non-HTTPS listener), `Resolved` (all refs resolved),
    /// `TlsPassthrough`, and `TlsTerminate` are healthy. `ResolvedPartial` is
    /// **not** healthy — it carries a degraded `ResolvedRefs=False` condition —
    /// even though the listener is still serving.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(
            self,
            Self::NotApplicable | Self::Resolved | Self::TlsPassthrough | Self::TlsTerminate
        )
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
            Self::Unsupported { .. } => "UnsupportedValue",
            Self::NotApplicable | Self::Resolved | Self::TlsPassthrough | Self::TlsTerminate => {
                "Resolved"
            }
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
            | Self::Unsupported { message }
            | Self::ResolvedPartial { message } => message.as_str(),
            Self::NotApplicable | Self::Resolved | Self::TlsPassthrough | Self::TlsTerminate => "",
        }
    }

    /// Returns `true` when this is a `TLS/Passthrough` listener (GEP-2643).
    ///
    /// Used by the bin layer to drive a `TlsL4`-protocol listener on this port.
    #[must_use]
    pub fn is_tls_passthrough(&self) -> bool {
        matches!(self, Self::TlsPassthrough)
    }

    /// Returns `true` when this is a `TLS/Terminate` listener (TLSRouteModeTerminate).
    ///
    /// Used by the bin layer to drive a `TlsL4`-protocol listener on this port
    /// alongside or instead of passthrough listeners.
    #[must_use]
    pub fn is_tls_terminate(&self) -> bool {
        matches!(self, Self::TlsTerminate)
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

/// Why a listener in the effective set did not program — its port-compatibility
/// conflict reason (GEP-1713).
///
/// Used as a single field replacing the former `(conflicted: bool, protocol_conflict:
/// bool)` pair so the three-way state is expressed as a closed enum rather than two
/// independent booleans. The enum is matched exhaustively cross-crate; a future variant
/// would be a deliberate, breaking model change (hence the opt-out below rather than
/// `#[non_exhaustive]`).
// intentionally open: closed enum matched exhaustively cross-crate; adding a variant is a model change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ConflictReason {
    /// No conflict — listener is programmed normally (the common case / proto zero-value).
    #[default]
    None,
    /// Two listeners on the same port whose hostnames overlap (empty or identical),
    /// mapped to the spec condition reason `HostnameConflict`.
    HostnameConflict,
    /// Two listeners on the same port with incompatible protocols,
    /// mapped to the spec condition reason `ProtocolConflict`.
    ProtocolConflict,
}

impl ConflictReason {
    /// Returns `true` when the listener lost a conflict (any variant other than `None`).
    #[must_use]
    pub fn is_conflicted(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// The Gateway API condition reason string for this conflict (e.g. `"HostnameConflict"`).
    ///
    /// Returns `"NoConflicts"` for [`Self::None`]; callers that already guard on
    /// [`Self::is_conflicted`] will never see that value from this method.
    #[must_use]
    pub fn reason_str(&self) -> &'static str {
        match self {
            Self::None => "NoConflicts",
            Self::HostnameConflict => "HostnameConflict",
            Self::ProtocolConflict => "ProtocolConflict",
        }
    }

    /// Human-readable message for condition bodies.
    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::HostnameConflict => {
                "listener lost a port-compatibility conflict to a higher-precedence listener"
            }
            Self::ProtocolConflict => {
                "listener lost a port-compatibility conflict due to protocol mismatch"
            }
        }
    }
}

/// A listener's resolved `allowedRoutes.namespaces` policy — which namespaces'
/// routes may attach to it.
///
/// The selector is resolved to a concrete set of namespace names **at merge
/// time** (where the cluster Namespace store is available), so every routing-path
/// gate — the attached-routes count, the HTTP/GRPC/TLS routing-table attach, and
/// the route `Accepted` computation — is a pure set-membership check needing no
/// namespace store. Mapping from `allowedRoutes.namespaces.from`:
/// `All` → [`Self::All`]; `Same` → `Only({owning_ns})`; `Selector` → `Only(matched)`;
/// `None`/absent-restrictive → `Only({})`.
///
/// NOT carried losslessly on the discovery wire: the proxy receives a pre-built
/// routing table and never matches namespaces, so the wire collapses this to a
/// single "all" bit (`Only(_)` → not-all). The reflector always holds the full set
/// in-process — it never reconstructs this from the wire.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteNamespaceSet {
    /// `from: All` — routes from any namespace attach.
    All,
    /// Routes only from these (already-resolved) namespace names attach.
    Only(std::collections::BTreeSet<String>),
}

impl Default for RouteNamespaceSet {
    /// `All` — a bare `ListenerInfo::default()` carries no namespace restriction.
    /// Production listeners ALWAYS get the resolved policy from the merge; the wire
    /// `from_wire` path maps a non-all listener to `Only({})` explicitly (fail
    /// closed), so this permissive default only affects test/defensive defaults.
    fn default() -> Self {
        Self::All
    }
}

impl RouteNamespaceSet {
    /// Whether a route in namespace `ns` is permitted to attach.
    #[must_use]
    pub fn allows(&self, ns: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(set) => set.contains(ns),
        }
    }

    /// Whether this policy admits routes from every namespace (`from: All`).
    #[must_use]
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }
}

/// Resolved PROXY protocol configuration for one listener.
///
/// Produced by the reflector from a `ClientTrafficPolicy` (Gateway listeners)
/// or from the `--ingress-accept-proxy-protocol` flag (Ingress-origin listeners).
/// Consumed by the acceptor in `coxswain-proxy` to decide whether to parse and
/// strip a PROXY v1/v2 header before dispatching each connection.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProxyProtocolListenerConfig {
    /// When `true`, every accepted connection must carry a valid PROXY v1/v2 header.
    /// Connections without a valid header (or from untrusted peers) are dropped.
    pub enabled: bool,
    /// CIDR allow-list of peers permitted to send PROXY headers. Connections from
    /// peers outside this list are dropped immediately, before the header is read.
    /// Should be non-empty when `enabled` is `true`; an empty list rejects all
    /// connections.
    pub trusted_sources: Vec<IpNet>,
}

impl ProxyProtocolListenerConfig {
    /// Construct a resolved per-listener PROXY protocol config.
    ///
    /// `enabled` gates whether the proxy expects a PROXY header; `trusted_sources`
    /// is the CIDR allow-list of peers permitted to send one.
    pub fn new(enabled: bool, trusted_sources: Vec<IpNet>) -> Self {
        Self {
            enabled,
            trusted_sources,
        }
    }

    /// Returns `true` if `ip` falls within at least one of the trusted CIDR ranges.
    #[must_use]
    pub fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.trusted_sources.iter().any(|n| n.contains(ip))
    }
}

/// Consolidated per-listener metadata for one Gateway listener.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct ListenerInfo {
    /// Readiness outcome for this listener — gates its `Programmed` condition.
    /// `NotApplicable` for listeners with nothing to resolve (e.g. plain HTTP);
    /// see [`ListenerReadiness`].
    pub readiness: ListenerReadiness,
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
    /// Resolved `allowedRoutes.namespaces` policy: which namespaces' routes may
    /// attach to this listener. Resolved from the listener's `from`(+`selector`)
    /// at merge time; see [`RouteNamespaceSet`].
    pub route_namespaces: RouteNamespaceSet,
    /// Listener spec port number — what clients connect to and what
    /// `status.addresses`/listener conditions report.
    pub port: u16,
    /// Internal `targetPort` the shared proxy binds and keys its routing,
    /// passthrough, and TLS tables on (#472).
    ///
    /// In shared mode every owned Gateway gets its own Service/VIP that maps the
    /// advertised [`Self::port`] to a distinct internal port on the one shared
    /// proxy pod; the proxy distinguishes Gateways by the local port it accepted
    /// on, so isolation falls out of the existing port-keyed structures. `0`
    /// (the default) means "not separately allocated; bind the spec port" —
    /// dedicated mode and Ingress-derived listeners keep spec == bind. Read
    /// through [`Self::bind_port`], never directly, so the fallback is honoured.
    pub internal_port: u16,
    /// GEP-1713: why (if at all) this listener lost a port-compatibility conflict to
    /// a higher-precedence listener in the Gateway's effective set.
    ///
    /// [`ConflictReason::None`] means no conflict — the listener is programmed normally.
    /// Any other variant means the listener was NOT programmed and drives the
    /// `Conflicted=True` condition with the matching reason string on the owning
    /// resource (Gateway or `ListenerSet`). Always `None` for Gateways without attached
    /// ListenerSets.
    pub conflict: ConflictReason,
    /// PROXY protocol configuration resolved for this listener from a `ClientTrafficPolicy`.
    ///
    /// `None` means no policy targets this listener; the acceptor defaults to off.
    /// Transported over the discovery wire so the data-plane proxy can enforce it.
    pub proxy_protocol: Option<ProxyProtocolListenerConfig>,
}

impl ListenerInfo {
    /// Port the proxy actually binds and keys routing on: the allocated
    /// [`Self::internal_port`] when non-zero, else the spec [`Self::port`].
    ///
    /// The `0 → port` fallback keeps dedicated mode and Ingress-derived
    /// listeners (which never allocate an internal port) binding their spec
    /// port unchanged.
    #[must_use]
    pub fn bind_port(&self) -> u16 {
        if self.internal_port != 0 {
            self.internal_port
        } else {
            self.port
        }
    }
}

/// Outcome of resolving the Gateway-wide frontend client-certificate validation
/// config (GEP-91, `spec.tls.frontend.default.validation`).
///
/// Produced during each reconciler rebuild and consumed by the controller's
/// status writer to emit the `InsecureFrontendValidationMode` condition.
/// `None` on a [`GatewayListenerStatus`] means no frontend validation is configured.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct FrontendValidationStatus {
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

/// Outcome of resolving the Gateway-wide backend client-certificate ref
/// (GEP-3155, `spec.tls.backend.clientCertificateRef`).
///
/// Produced during each reconciler rebuild and consumed by the controller's status
/// writer to emit the **gateway-level** `ResolvedRefs` condition. This is a single
/// gateway-scoped outcome (not per-listener): the ref applies to all backend TLS
/// connections the Gateway makes. The group/kind/missing/malformed failures all map
/// to the spec's `InvalidClientCertificateRef`; a denied cross-namespace ref maps to
/// `RefNotPermitted`. `None` on a [`GatewayListenerStatus`] means the ref is absent and
/// no `ResolvedRefs` condition is emitted.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum BackendClientCertOutcome {
    /// The ref is absent — no condition. (Default so the enum has a sensible zero.)
    #[default]
    NotApplicable,
    /// The Secret resolved with `tls.crt` + `tls.key` — `ResolvedRefs=True/ResolvedRefs`.
    Resolved,
    /// Unsupported group/kind, missing Secret, or a Secret without `tls.crt`/`tls.key` —
    /// `ResolvedRefs=False/InvalidClientCertificateRef`.
    InvalidClientCertificateRef {
        /// Human-readable description of why the ref is invalid.
        message: String,
    },
    /// A cross-namespace ref with no permitting `ReferenceGrant` —
    /// `ResolvedRefs=False/RefNotPermitted`.
    RefNotPermitted {
        /// Human-readable description of the denied cross-namespace ref.
        message: String,
    },
}

impl BackendClientCertOutcome {
    /// `true` when the ref was configured but could not be resolved — the Gateway
    /// surfaces `ResolvedRefs=False`.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(
            self,
            Self::InvalidClientCertificateRef { .. } | Self::RefNotPermitted { .. }
        )
    }

    /// Status string for the `ResolvedRefs` condition (`"True"` / `"False"`).
    #[must_use]
    pub fn resolved_refs_status(&self) -> &'static str {
        if self.is_failed() { "False" } else { "True" }
    }

    /// Stable reason string for the `ResolvedRefs` condition.
    #[must_use]
    pub fn resolved_refs_reason(&self) -> &'static str {
        match self {
            Self::InvalidClientCertificateRef { .. } => "InvalidClientCertificateRef",
            Self::RefNotPermitted { .. } => "RefNotPermitted",
            Self::NotApplicable | Self::Resolved => "ResolvedRefs",
        }
    }

    /// Human-readable message attached to the failed condition; empty otherwise.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::InvalidClientCertificateRef { message } | Self::RefNotPermitted { message } => {
                message.as_str()
            }
            Self::NotApplicable | Self::Resolved => "",
        }
    }
}

/// Per-listener status for one Gateway, keyed by [`ListenerStatusKey`] (source + name).
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct GatewayListenerStatus {
    /// The Gateway's effective listeners (its own plus those merged from attached
    /// ListenerSets), keyed by [`ListenerStatusKey`] so same-named listeners from
    /// different sources stay distinct (GEP-1713).
    pub listeners: BTreeMap<ListenerStatusKey, ListenerInfo>,
    /// Frontend client-certificate validation status for this Gateway (GEP-91, #86).
    ///
    /// `None` when `spec.tls.frontend.default.validation` is absent.
    /// `Some` when the field is present, regardless of whether refs resolved.
    pub frontend_validation: Option<FrontendValidationStatus>,
    /// Backend client-certificate resolution outcome for this Gateway (GEP-3155, #87).
    ///
    /// `None` when `spec.tls.backend.clientCertificateRef` is absent (no condition).
    /// `Some` when the ref is present — the controller emits a gateway-level
    /// `ResolvedRefs` condition from it. Like [`ListenerInfo::frontend_outcome`] it is
    /// controller-only (never transported over the discovery wire).
    pub backend_client_cert: Option<BackendClientCertOutcome>,
}

// ── SharedGatewayListenerStatus ───────────────────────────────────────────────

struct GatewayListenerStatusInner {
    map: ArcSwap<HashMap<ObjectKey, GatewayListenerStatus>>,
    tx: watch::Sender<u64>,
}

/// Shared handle to the per-Gateway listener status map.
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
pub struct SharedGatewayListenerStatus(Arc<GatewayListenerStatusInner>);

impl Default for SharedGatewayListenerStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedGatewayListenerStatus {
    /// Construct a new shared status map (initially empty, generation 0).
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0u64);
        Self(Arc::new(GatewayListenerStatusInner {
            map: ArcSwap::from_pointee(HashMap::new()),
            tx,
        }))
    }

    /// Load the current listener status map snapshot.
    pub fn load(&self) -> arc_swap::Guard<Arc<HashMap<ObjectKey, GatewayListenerStatus>>> {
        self.0.map.load()
    }

    /// Store a new listener status map and notify every subscribed `Receiver` that
    /// the generation has advanced.
    pub fn store_and_notify(&self, map: HashMap<ObjectKey, GatewayListenerStatus>) {
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
        updates: HashMap<ObjectKey, GatewayListenerStatus>,
        owns: impl Fn(&ObjectKey) -> bool,
    ) {
        self.0.map.rcu(|current| {
            let mut next: HashMap<ObjectKey, GatewayListenerStatus> = current
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

    #[test]
    fn backend_client_cert_outcome_reason_and_failed_flags() {
        let msg = || "bad".to_string();
        let cases = [
            (
                BackendClientCertOutcome::NotApplicable,
                false,
                "ResolvedRefs",
            ),
            (BackendClientCertOutcome::Resolved, false, "ResolvedRefs"),
            (
                BackendClientCertOutcome::InvalidClientCertificateRef { message: msg() },
                true,
                "InvalidClientCertificateRef",
            ),
            (
                BackendClientCertOutcome::RefNotPermitted { message: msg() },
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
            assert_eq!(
                outcome.resolved_refs_status(),
                if failed { "False" } else { "True" },
                "status for {outcome:?}"
            );
        }
    }

    #[test]
    fn backend_client_cert_outcome_message_only_on_failures() {
        assert_eq!(BackendClientCertOutcome::Resolved.message(), "");
        assert_eq!(BackendClientCertOutcome::NotApplicable.message(), "");
        assert_eq!(
            BackendClientCertOutcome::InvalidClientCertificateRef {
                message: "bad ref".to_string()
            }
            .message(),
            "bad ref"
        );
        assert_eq!(
            BackendClientCertOutcome::RefNotPermitted {
                message: "denied".to_string()
            }
            .message(),
            "denied"
        );
    }
}
