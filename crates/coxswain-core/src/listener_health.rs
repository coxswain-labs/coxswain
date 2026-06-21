//! Per-listener health data types shared by the reflector and discovery wire layer.
//!
//! These are pure data types — no `ArcSwap`, no `watch`, no Kubernetes API imports.
//! `SharedGatewayListenerHealth` (the watch-channel wrapper) stays in
//! `coxswain-reflector` because it depends on `arc_swap` and `tokio`.
//!
//! The discovery wire layer reads these types to serialise the listener-health
//! DTO in `to_wire`; the proxy deserialises them in `from_wire` so it can apply
//! TLS termination configuration without talking to the Kubernetes API.

use std::collections::BTreeMap;

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
