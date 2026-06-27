//! Wire-DTO conversions between compiled routing types and proto3 messages.
//!
//! # Overview
//!
//! The controller calls `to_wire` to serialise a compiled [`RoutingTable`] into
//! a proto message and then embeds it in a [`Snapshot`].  The proxy
//! calls `from_wire` on arrival and replays the builder API — exactly the same
//! public constructors the reflector uses — to produce a freshly-compiled table
//! without ever touching the Kubernetes API.
//!
//! # Determinism
//!
//! All `to_wire` functions emit data in deterministic canonical order:
//! - Ports: ascending by port number.
//! - Hosts per port: exact entries first (sorted by hostname), then wildcard
//!   (sorted by suffix), then catchall.
//! - Routes per host: in `wire_entries()` insertion order — the order the
//!   reflector registered them, which is stable across reconcile cycles for the
//!   same set of Ingress/HTTPRoute objects.
//! - Addresses inside a backend: sorted for hash stability.
//! - CIDRs: sorted string representation.
//! - TLS/mTLS entries: sorted by host pattern.
//! - Listener health entries: sorted by `ObjectKey` string.
//!
//! No `map<>` fields appear anywhere in the proto; all maps are `repeated Entry`
//! emitted in sorted order.  This makes the serialised bytes byte-identical
//! across reconcile cycles for the same routing world, which keeps the
//! `ContentHash` oracle stable.
//!
//! # Recursion guard
//!
//! `FilterAction::Mirror` embeds an `Arc<BackendGroup>`, which itself may carry
//! `per_backend_filters` containing further `Mirror` actions.  In practice the
//! graph is a tree (no cycles), but the proto is untrusted: `from_wire` limits
//! recursion through Mirror backends to [`MAX_MIRROR_DEPTH`].
//!
//! [`RoutingTable`]: coxswain_core::routing::RoutingTable
//! [`Snapshot`]: crate::proto::v1::Snapshot

use coxswain_core::listener_health::{ListenerInfo, ListenerTlsOutcome};

use crate::error::WireError;
use crate::proto::v1 as p;
use crate::subscription::Scope;

// ────────────────────────────────────────────────────────────────────────────
// Scope: to_wire / from_wire
// ────────────────────────────────────────────────────────────────────────────

/// Serialise a [`Scope`] to its wire DTO.
///
/// `SharedPool` → `shared_pool` oneof arm; `Gateway` → `gateway` arm.
/// Infallible: every variant has a canonical encoding.
#[must_use = "wire DTO must be embedded in a Subscribe to reach the server"]
pub fn scope_to_wire(scope: &Scope) -> p::Scope {
    let kind = match scope {
        Scope::SharedPool => p::scope::Kind::SharedPool(p::SharedPoolScope {}),
        Scope::Gateway { name, namespace } => p::scope::Kind::Gateway(p::GatewayScope {
            namespace: namespace.clone(),
            name: name.clone(),
        }),
    };
    p::Scope { kind: Some(kind) }
}

/// Deserialise a [`p::Scope`] proto DTO into a [`Scope`].
///
/// Returns `Err(WireError::MissingRequiredField)` when the `kind` discriminator
/// is absent — a `Scope {}` with no oneof arm is malformed and must not be
/// silently promoted to `SharedPool` (which would be a privilege escalation).
///
/// # Errors
///
/// Returns [`WireError::MissingRequiredField`] if `dto.kind` is `None`.
#[must_use = "wire decode failure must be handled; discarding the error silently promotes to SharedPool"]
pub fn scope_from_wire(dto: &p::Scope) -> Result<Scope, WireError> {
    match &dto.kind {
        Some(p::scope::Kind::SharedPool(_)) => Ok(Scope::SharedPool),
        Some(p::scope::Kind::Gateway(g)) => Ok(Scope::Gateway {
            name: g.name.clone(),
            namespace: g.namespace.clone(),
        }),
        None => Err(WireError::MissingRequiredField {
            field: "scope.kind",
        }),
    }
}

pub(crate) fn listener_info_from_wire(dto: &p::ListenerInfo) -> Result<ListenerInfo, WireError> {
    let tls_outcome = match p::ListenerTlsOutcome::try_from(dto.tls_outcome)
        .unwrap_or(p::ListenerTlsOutcome::Unspecified)
    {
        p::ListenerTlsOutcome::Unspecified | p::ListenerTlsOutcome::NotApplicable => {
            ListenerTlsOutcome::NotApplicable
        }
        p::ListenerTlsOutcome::Resolved => ListenerTlsOutcome::Resolved,
        p::ListenerTlsOutcome::RefNotPermitted => ListenerTlsOutcome::RefNotPermitted {
            message: dto.tls_message.clone(),
        },
        p::ListenerTlsOutcome::InvalidCertificateRef => ListenerTlsOutcome::InvalidCertificateRef {
            message: dto.tls_message.clone(),
        },
        p::ListenerTlsOutcome::Invalid => ListenerTlsOutcome::Invalid {
            message: dto.tls_message.clone(),
        },
        p::ListenerTlsOutcome::ResolvedPartial => ListenerTlsOutcome::ResolvedPartial {
            message: dto.tls_message.clone(),
        },
        p::ListenerTlsOutcome::TlsPassthrough => ListenerTlsOutcome::TlsPassthrough,
        p::ListenerTlsOutcome::Unsupported => ListenerTlsOutcome::Unsupported {
            message: dto.tls_message.clone(),
        },
    };

    let mut li = ListenerInfo::default();
    li.tls_outcome = tls_outcome;
    li.attached_routes = dto.attached_routes;
    li.hostname = dto.hostname.clone();
    li.allows_all_namespaces = dto.allows_all_namespaces;
    li.port = dto.port as u16;
    li.internal_port = dto.internal_port as u16;
    li.conflicted = dto.conflicted;
    Ok(li)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── scope round-trips ────────────────────────────────────────────────────

    #[test]
    fn scope_shared_pool_round_trips() {
        let scope = Scope::SharedPool;
        let wire = scope_to_wire(&scope);
        let back = scope_from_wire(&wire).expect("SharedPool round-trip");
        assert_eq!(scope, back, "SharedPool round-trip");
    }

    #[test]
    fn scope_gateway_round_trips() {
        let scope = Scope::Gateway {
            name: "my-gateway".to_owned(),
            namespace: "production".to_owned(),
        };
        let wire = scope_to_wire(&scope);
        let back = scope_from_wire(&wire).expect("Gateway round-trip");
        assert_eq!(scope, back, "Gateway round-trip");
    }

    #[test]
    fn scope_absent_kind_returns_error() {
        // A `Scope {}` with no `kind` discriminator is malformed — promoting it to
        // SharedPool would be a privilege escalation for a client that omits the field.
        let wire = p::Scope { kind: None };
        let err = scope_from_wire(&wire).expect_err("absent kind must be rejected");
        assert!(
            matches!(
                err,
                WireError::MissingRequiredField {
                    field: "scope.kind"
                }
            ),
            "expected MissingRequiredField(scope.kind), got {err:?}",
        );
    }
}
