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

use coxswain_core::listener_status::{
    ConflictReason, GatewayListenerStatus, ListenerInfo, ListenerReadiness, ListenerSource,
    ListenerStatusKey,
};
use coxswain_core::ownership::ObjectKey;

use crate::error::WireError;
use crate::proto::v1 as p;

// ────────────────────────────────────────────────────────────────────────────
// Listener health: to_wire
// ────────────────────────────────────────────────────────────────────────────

/// Serialise a map of `ObjectKey → GatewayListenerStatus` to its wire DTO.
///
/// Entries are sorted by `ObjectKey` string representation for hash determinism.
#[must_use = "wire DTO must be embedded in a Snapshot to reach the proxy"]
pub fn listener_status_to_wire(
    map: &std::collections::HashMap<ObjectKey, GatewayListenerStatus>,
) -> p::GatewayListenerStatus {
    let mut entries: Vec<(&ObjectKey, &GatewayListenerStatus)> = map.iter().collect();
    entries.sort_by_key(|(k, _)| k.to_string());

    p::GatewayListenerStatus {
        entries: entries
            .into_iter()
            .map(|(key, status)| p::GatewayStatusEntry {
                object_key: key.to_string(),
                status: Some(p::ListenerStatus {
                    // BTreeMap<ListenerStatusKey, ListenerInfo> is already sorted by (source, name).
                    listeners: status
                        .listeners
                        .iter()
                        .map(|(key, info)| p::ListenerInfoEntry {
                            name: key.name.clone(),
                            info: Some(listener_info_to_wire(info)),
                            source: listener_source_to_wire(&key.source),
                        })
                        .collect(),
                }),
            })
            .collect(),
    }
}

fn listener_info_to_wire(info: &ListenerInfo) -> p::ListenerInfo {
    let (outcome, message) = match &info.readiness {
        ListenerReadiness::NotApplicable => (p::ListenerReadiness::NotApplicable, String::new()),
        ListenerReadiness::Resolved => (p::ListenerReadiness::Resolved, String::new()),
        ListenerReadiness::RefNotPermitted { message } => {
            (p::ListenerReadiness::RefNotPermitted, message.clone())
        }
        ListenerReadiness::InvalidCertificateRef { message } => {
            (p::ListenerReadiness::InvalidCertificateRef, message.clone())
        }
        ListenerReadiness::Invalid { message } => (p::ListenerReadiness::Invalid, message.clone()),
        ListenerReadiness::ResolvedPartial { message } => {
            (p::ListenerReadiness::ResolvedPartial, message.clone())
        }
        ListenerReadiness::TlsPassthrough => (p::ListenerReadiness::TlsPassthrough, String::new()),
        ListenerReadiness::Unsupported { message } => {
            (p::ListenerReadiness::Unsupported, message.clone())
        }
        // #517: a protocol coxswain does not route. The proxy makes no functional
        // distinction between this and `Unsupported` (both mean "this listener
        // serves no traffic"); the Gateway status *reason* (`UnsupportedProtocol`
        // vs `UnsupportedValue`) is written to Kubernetes by the controller, not
        // carried on the wire — so reuse the existing `Unsupported` wire value
        // rather than growing the proto for a proxy-invisible distinction.
        ListenerReadiness::UnsupportedProtocol { message } => {
            (p::ListenerReadiness::Unsupported, message.clone())
        }
        ListenerReadiness::TlsTerminate => (p::ListenerReadiness::TlsTerminate, String::new()),
        ListenerReadiness::TcpProxy => (p::ListenerReadiness::TcpProxy, String::new()),
        // A shared-mode HTTPS/TLS listener still waiting for its VIP internal port
        // (#472). It has no dedicated wire value: the distinction is proxy-invisible
        // and transient (the next rebuild replaces it with the resolved outcome).
        // Encode as `Unsupported` so the proxy's `derive_gateway_specs` treats it as
        // an HTTPS listener (its `_ => Https` default) — VipPending is *always* an
        // HTTPS/TLS listener, so degrading it to the plaintext-HTTP `NotApplicable`
        // would bind the wrong protocol during the transient window.
        ListenerReadiness::VipPending => (p::ListenerReadiness::Unsupported, String::new()),
        // Data-plane safety: `ListenerReadiness` is a `#[non_exhaustive]` core
        // enum, so this wildcard is reachable the moment a *future* variant is
        // added. A panic here would take down the controller's discovery snapshot
        // push and stall the whole data plane, so degrade an unmapped readiness to
        // `NotApplicable` — the safe "proxy does nothing special with this
        // listener" default — and log it instead.
        other => {
            tracing::warn!(
                readiness = ?other,
                "unmapped ListenerReadiness in discovery wire encode; degrading to NotApplicable"
            );
            (p::ListenerReadiness::NotApplicable, String::new())
        }
    };
    p::ListenerInfo {
        readiness: outcome as i32,
        detail: message,
        attached_routes: info.attached_routes,
        hostname: info.hostname.clone(),
        // Lossy by design: the proxy never matches namespaces (it gets a pre-built
        // routing table), so the wire carries only the "all" bit. The reflector
        // holds the full resolved `RouteNamespaceSet` in-process and never
        // reconstructs it from the wire.
        allows_all_namespaces: info.route_namespaces.is_all(),
        port: u32::from(info.port),
        internal_port: u32::from(info.internal_port),
        conflicted: info.conflict.is_conflicted(),
        protocol_conflict: matches!(info.conflict, ConflictReason::ProtocolConflict),
        proxy_protocol: info
            .proxy_protocol
            .as_ref()
            .map(|pp| p::ProxyProtocolListenerConfig {
                enabled: pp.enabled,
                trusted_sources: pp.trusted_sources.iter().map(|n| n.to_string()).collect(),
            }),
    }
}

/// Encode a [`ListenerSource`] as its wire string: empty for the parent Gateway,
/// the ListenerSet's `"{namespace}/{name}"` key otherwise (GEP-1713).
fn listener_source_to_wire(source: &ListenerSource) -> String {
    match source {
        ListenerSource::Gateway => String::new(),
        ListenerSource::ListenerSet(key) => key.to_string(),
    }
}

/// Decode a wire `source` string back into a [`ListenerSource`]: empty → the
/// parent Gateway, else parse the ListenerSet `"{namespace}/{name}"` key.
fn listener_source_from_wire(source: &str) -> Result<ListenerSource, WireError> {
    if source.is_empty() {
        Ok(ListenerSource::Gateway)
    } else {
        source
            .parse::<ObjectKey>()
            .map(ListenerSource::ListenerSet)
            .map_err(|()| WireError::MissingRequiredField {
                field: "listener_info_entry.source",
            })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Listener health: from_wire
// ────────────────────────────────────────────────────────────────────────────

/// Reconstruct a `HashMap<ObjectKey, GatewayListenerStatus>` from its wire DTO.
///
/// # Errors
///
/// Returns [`WireError`] if any required field is missing.
#[must_use = "the rebuilt listener status map must be stored for the proxy to use it"]
pub fn listener_status_from_wire(
    dto: &p::GatewayListenerStatus,
) -> Result<std::collections::HashMap<ObjectKey, GatewayListenerStatus>, WireError> {
    dto.entries
        .iter()
        .map(|e| {
            let key =
                e.object_key
                    .parse::<ObjectKey>()
                    .map_err(|_| WireError::MissingRequiredField {
                        field: "gateway_status_entry.object_key",
                    })?;
            let status_dto = e.status.as_ref().ok_or(WireError::MissingRequiredField {
                field: "gateway_status_entry.status",
            })?;
            let status_entry = listener_status_from_dto(status_dto)?;
            Ok((key, status_entry))
        })
        .collect()
}

fn listener_status_from_dto(dto: &p::ListenerStatus) -> Result<GatewayListenerStatus, WireError> {
    let mut glh = GatewayListenerStatus::default();
    for entry in &dto.listeners {
        let info = entry.info.as_ref().ok_or(WireError::MissingRequiredField {
            field: "listener_info_entry.info",
        })?;
        let li = crate::wire::listener_info_from_wire(info)?;
        let source = listener_source_from_wire(&entry.source)?;
        glh.listeners.insert(
            ListenerStatusKey {
                source,
                name: entry.name.clone(),
            },
            li,
        );
    }
    Ok(glh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::listener_status::RouteNamespaceSet;

    // ── Listener health round-trip ────────────────────────────────────────────

    #[test]
    fn listener_status_round_trips() {
        let mut map = std::collections::HashMap::new();
        let mut status = GatewayListenerStatus::default();

        let mut http_info = ListenerInfo::default();
        http_info.readiness = ListenerReadiness::NotApplicable;
        http_info.attached_routes = 3;
        http_info.hostname = "example.com".to_string();
        http_info.port = 80;
        status
            .listeners
            .insert(ListenerStatusKey::gateway("http"), http_info);

        let mut https_info = ListenerInfo::default();
        https_info.readiness = ListenerReadiness::Resolved;
        https_info.attached_routes = 5;
        https_info.hostname = "example.com".to_string();
        https_info.route_namespaces = RouteNamespaceSet::All;
        https_info.port = 443;
        // Shared-mode per-Gateway addressing (#472): advertised :443 binds an
        // allocated internal targetPort — it must survive the wire round-trip so
        // the proxy binds and keys routing on the right port.
        https_info.internal_port = 30007;
        status
            .listeners
            .insert(ListenerStatusKey::gateway("https"), https_info);

        // GEP-2643 (#70): a TLS/Terminate listener resolves to Unsupported, and a
        // TLS/Passthrough listener to TlsPassthrough. Both must survive the wire
        // round-trip — encoding an Unsupported listener previously hit an
        // `unreachable!()` in `listener_info_to_wire` and crashed the controller's
        // discovery server, starving the proxy of every snapshot.
        let mut terminate_info = ListenerInfo::default();
        terminate_info.readiness = ListenerReadiness::Unsupported {
            message: "tls.mode: Terminate is not supported".to_string(),
        };
        terminate_info.port = 8443;
        status
            .listeners
            .insert(ListenerStatusKey::gateway("tls-terminate"), terminate_info);

        let mut passthrough_info = ListenerInfo::default();
        passthrough_info.readiness = ListenerReadiness::TlsPassthrough;
        passthrough_info.port = 8444;
        status.listeners.insert(
            ListenerStatusKey::gateway("tls-passthrough"),
            passthrough_info,
        );

        // #517: a listener whose spec `protocol` coxswain does not route resolves to
        // `UnsupportedProtocol`. Encoding it previously hit an `unreachable!()`
        // wildcard in `listener_info_to_wire` and crashed the controller's discovery
        // serializer, starving the proxy of every snapshot. It has no dedicated wire
        // value: the proxy makes no functional distinction, so it encodes as the
        // existing `Unsupported` and decodes back to `Unsupported` (lossy by design —
        // the k8s status reason is written by the controller, never carried here).
        let mut unsupported_proto_info = ListenerInfo::default();
        unsupported_proto_info.readiness = ListenerReadiness::UnsupportedProtocol {
            message: "protocol \"FOO\" is not supported".to_string(),
        };
        unsupported_proto_info.port = 5555;
        status.listeners.insert(
            ListenerStatusKey::gateway("unsupported-protocol"),
            unsupported_proto_info,
        );

        // #472: a shared-mode HTTPS listener still awaiting its VIP internal port
        // resolves to `VipPending`. Like `UnsupportedProtocol` it has no dedicated
        // wire value; it encodes as `Unsupported` (→ HTTPS on the proxy) and must
        // not hit the panic the old `unreachable!()` wildcard would have raised.
        let mut vip_pending_info = ListenerInfo::default();
        vip_pending_info.readiness = ListenerReadiness::VipPending;
        vip_pending_info.port = 6666;
        status
            .listeners
            .insert(ListenerStatusKey::gateway("vip-pending"), vip_pending_info);

        // GEP-1713: a listener contributed by a ListenerSet shares the name "http"
        // with the Gateway's own listener but lives under a distinct ListenerSource
        // and on a different port. It must survive the round-trip as its own entry.
        // Both ConflictReason variants must round-trip correctly.
        let ls_key = ObjectKey::new("apps", "team-a");
        let mut ls_http = ListenerInfo::default();
        ls_http.readiness = ListenerReadiness::NotApplicable;
        ls_http.attached_routes = 7;
        ls_http.port = 8080;
        ls_http.conflict = ConflictReason::HostnameConflict;
        status.listeners.insert(
            ListenerStatusKey::listener_set(ls_key.clone(), "http"),
            ls_http,
        );
        let mut ls_proto = ListenerInfo::default();
        ls_proto.readiness = ListenerReadiness::NotApplicable;
        ls_proto.port = 9090;
        ls_proto.conflict = ConflictReason::ProtocolConflict;
        status.listeners.insert(
            ListenerStatusKey::listener_set(ls_key.clone(), "proto-conflict"),
            ls_proto,
        );

        map.insert(ObjectKey::new("default", "my-gw"), status);

        let dto = listener_status_to_wire(&map);
        let map2 = listener_status_from_wire(&dto).expect("from_wire");

        let h2 = map2
            .get(&ObjectKey::new("default", "my-gw"))
            .expect("key found");
        assert_eq!(h2.listeners.len(), 8, "listener count preserved");
        let gw_http = ListenerStatusKey::gateway("http");
        let gw_https = ListenerStatusKey::gateway("https");
        assert_eq!(
            h2.listeners[&gw_http].attached_routes, 3,
            "attached_routes preserved"
        );
        assert!(
            matches!(
                h2.listeners[&gw_https].readiness,
                ListenerReadiness::Resolved
            ),
            "readiness preserved"
        );
        assert_eq!(
            h2.listeners[&gw_https].internal_port, 30007,
            "internal_port preserved (#472)"
        );
        assert_eq!(
            h2.listeners[&gw_https].bind_port(),
            30007,
            "bind_port honours the allocated internal port"
        );
        assert_eq!(
            h2.listeners[&gw_http].bind_port(),
            80,
            "bind_port falls back to spec port when internal_port unset"
        );
        assert!(
            matches!(
                &h2.listeners[&ListenerStatusKey::gateway("tls-terminate")].readiness,
                ListenerReadiness::Unsupported { message }
                    if message == "tls.mode: Terminate is not supported"
            ),
            "Unsupported outcome + message preserved"
        );
        assert!(
            matches!(
                h2.listeners[&ListenerStatusKey::gateway("tls-passthrough")].readiness,
                ListenerReadiness::TlsPassthrough
            ),
            "TlsPassthrough outcome preserved"
        );
        // #517: `UnsupportedProtocol` encodes without panicking and decodes to
        // `Unsupported` (no dedicated wire value), message preserved.
        assert!(
            matches!(
                &h2.listeners[&ListenerStatusKey::gateway("unsupported-protocol")].readiness,
                ListenerReadiness::Unsupported { message }
                    if message == "protocol \"FOO\" is not supported"
            ),
            "UnsupportedProtocol encodes as Unsupported + message preserved"
        );
        // #472: VipPending encodes without panicking and decodes to Unsupported.
        assert!(
            matches!(
                h2.listeners[&ListenerStatusKey::gateway("vip-pending")].readiness,
                ListenerReadiness::Unsupported { .. }
            ),
            "VipPending encodes as Unsupported (no dedicated wire value)"
        );
        // GEP-1713: the ListenerSet-sourced "http" is a distinct entry from the
        // Gateway's own "http", proving (source, name) keying survives the wire.
        let ls_http_key = ListenerStatusKey::listener_set(ls_key.clone(), "http");
        assert_eq!(
            h2.listeners[&ls_http_key].attached_routes, 7,
            "ListenerSet listener round-trips under its own source"
        );
        assert!(
            matches!(
                h2.listeners[&ls_http_key].conflict,
                ConflictReason::HostnameConflict
            ),
            "HostnameConflict preserved across the wire"
        );
        let ls_proto_key = ListenerStatusKey::listener_set(ls_key, "proto-conflict");
        assert!(
            matches!(
                h2.listeners[&ls_proto_key].conflict,
                ConflictReason::ProtocolConflict
            ),
            "ProtocolConflict preserved across the wire"
        );
    }
}
