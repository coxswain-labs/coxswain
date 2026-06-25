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

use coxswain_core::listener_health::{GatewayListenerHealth, ListenerInfo, ListenerTlsOutcome};
use coxswain_core::ownership::ObjectKey;

use crate::error::WireError;
use crate::proto::v1 as p;

// ────────────────────────────────────────────────────────────────────────────
// Listener health: to_wire
// ────────────────────────────────────────────────────────────────────────────

/// Serialise a map of `ObjectKey → GatewayListenerHealth` to its wire DTO.
///
/// Entries are sorted by `ObjectKey` string representation for hash determinism.
#[must_use = "wire DTO must be embedded in a Snapshot to reach the proxy"]
pub fn listener_health_to_wire(
    map: &std::collections::HashMap<ObjectKey, GatewayListenerHealth>,
) -> p::GatewayListenerHealth {
    let mut entries: Vec<(&ObjectKey, &GatewayListenerHealth)> = map.iter().collect();
    entries.sort_by_key(|(k, _)| k.to_string());

    p::GatewayListenerHealth {
        entries: entries
            .into_iter()
            .map(|(key, health)| p::GatewayHealthEntry {
                object_key: key.to_string(),
                health: Some(p::ListenerHealth {
                    // BTreeMap<String, ListenerInfo> is already sorted by key.
                    listeners: health
                        .listeners
                        .iter()
                        .map(|(name, info)| p::ListenerInfoEntry {
                            name: name.clone(),
                            info: Some(listener_info_to_wire(info)),
                        })
                        .collect(),
                }),
            })
            .collect(),
    }
}

fn listener_info_to_wire(info: &ListenerInfo) -> p::ListenerInfo {
    let (outcome, message) = match &info.tls_outcome {
        ListenerTlsOutcome::NotApplicable => (p::ListenerTlsOutcome::NotApplicable, String::new()),
        ListenerTlsOutcome::Resolved => (p::ListenerTlsOutcome::Resolved, String::new()),
        ListenerTlsOutcome::RefNotPermitted { message } => {
            (p::ListenerTlsOutcome::RefNotPermitted, message.clone())
        }
        ListenerTlsOutcome::InvalidCertificateRef { message } => (
            p::ListenerTlsOutcome::InvalidCertificateRef,
            message.clone(),
        ),
        ListenerTlsOutcome::Invalid { message } => {
            (p::ListenerTlsOutcome::Invalid, message.clone())
        }
        // ResolvedPartial: listener serves the good certs (is HTTPS-terminating)
        // but some refs failed.  Wire as Resolved so the proxy correctly includes
        // this listener in misdirected-request detection.  The partial-failure
        // detail is surfaced by the controller via K8s conditions; the proxy has
        // no use for it.  A dedicated proto enum value will be added in a follow-up
        // commit when the multi-cert wire format is extended.
        ListenerTlsOutcome::ResolvedPartial { .. } => {
            (p::ListenerTlsOutcome::Resolved, String::new())
        }
        &_ => unreachable!(
            "invariant: all ListenerTlsOutcome variants handled; \
             add a new arm when the core type gains a variant"
        ),
    };
    p::ListenerInfo {
        tls_outcome: outcome as i32,
        tls_message: message,
        attached_routes: info.attached_routes,
        hostname: info.hostname.clone(),
        allows_all_namespaces: info.allows_all_namespaces,
        port: u32::from(info.port),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Listener health: from_wire
// ────────────────────────────────────────────────────────────────────────────

/// Reconstruct a `HashMap<ObjectKey, GatewayListenerHealth>` from its wire DTO.
///
/// # Errors
///
/// Returns [`WireError`] if any required field is missing.
#[must_use = "the rebuilt listener-health map must be stored for the proxy to use it"]
pub fn listener_health_from_wire(
    dto: &p::GatewayListenerHealth,
) -> Result<std::collections::HashMap<ObjectKey, GatewayListenerHealth>, WireError> {
    dto.entries
        .iter()
        .map(|e| {
            let key =
                e.object_key
                    .parse::<ObjectKey>()
                    .map_err(|_| WireError::MissingRequiredField {
                        field: "gateway_health_entry.object_key",
                    })?;
            let health_dto = e.health.as_ref().ok_or(WireError::MissingRequiredField {
                field: "gateway_health_entry.health",
            })?;
            let health = listener_health_from_dto(health_dto)?;
            Ok((key, health))
        })
        .collect()
}

fn listener_health_from_dto(dto: &p::ListenerHealth) -> Result<GatewayListenerHealth, WireError> {
    let mut glh = GatewayListenerHealth::default();
    for entry in &dto.listeners {
        let info = entry.info.as_ref().ok_or(WireError::MissingRequiredField {
            field: "listener_info_entry.info",
        })?;
        let li = crate::wire::listener_info_from_wire(info)?;
        glh.listeners.insert(entry.name.clone(), li);
    }
    Ok(glh)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Listener health round-trip ────────────────────────────────────────────

    #[test]
    fn listener_health_round_trips() {
        let mut map = std::collections::HashMap::new();
        let mut health = GatewayListenerHealth::default();

        let mut http_info = ListenerInfo::default();
        http_info.tls_outcome = ListenerTlsOutcome::NotApplicable;
        http_info.attached_routes = 3;
        http_info.hostname = "example.com".to_string();
        http_info.port = 80;
        health.listeners.insert("http".to_string(), http_info);

        let mut https_info = ListenerInfo::default();
        https_info.tls_outcome = ListenerTlsOutcome::Resolved;
        https_info.attached_routes = 5;
        https_info.hostname = "example.com".to_string();
        https_info.allows_all_namespaces = true;
        https_info.port = 443;
        health.listeners.insert("https".to_string(), https_info);

        map.insert(ObjectKey::new("default", "my-gw"), health);

        let dto = listener_health_to_wire(&map);
        let map2 = listener_health_from_wire(&dto).expect("from_wire");

        let h2 = map2
            .get(&ObjectKey::new("default", "my-gw"))
            .expect("key found");
        assert_eq!(h2.listeners.len(), 2, "listener count preserved");
        assert_eq!(
            h2.listeners["http"].attached_routes, 3,
            "attached_routes preserved"
        );
        assert!(
            matches!(
                h2.listeners["https"].tls_outcome,
                ListenerTlsOutcome::Resolved
            ),
            "tls_outcome preserved"
        );
    }
}
