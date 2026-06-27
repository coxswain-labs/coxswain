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
    GatewayListenerStatus, ListenerInfo, ListenerSource, ListenerStatusKey, ListenerTlsOutcome,
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
        ListenerTlsOutcome::ResolvedPartial { message } => {
            (p::ListenerTlsOutcome::ResolvedPartial, message.clone())
        }
        ListenerTlsOutcome::TlsPassthrough => {
            (p::ListenerTlsOutcome::TlsPassthrough, String::new())
        }
        ListenerTlsOutcome::Unsupported { message } => {
            (p::ListenerTlsOutcome::Unsupported, message.clone())
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
        internal_port: u32::from(info.internal_port),
        conflicted: info.conflicted,
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

    // ── Listener health round-trip ────────────────────────────────────────────

    #[test]
    fn listener_status_round_trips() {
        let mut map = std::collections::HashMap::new();
        let mut status = GatewayListenerStatus::default();

        let mut http_info = ListenerInfo::default();
        http_info.tls_outcome = ListenerTlsOutcome::NotApplicable;
        http_info.attached_routes = 3;
        http_info.hostname = "example.com".to_string();
        http_info.port = 80;
        status
            .listeners
            .insert(ListenerStatusKey::gateway("http"), http_info);

        let mut https_info = ListenerInfo::default();
        https_info.tls_outcome = ListenerTlsOutcome::Resolved;
        https_info.attached_routes = 5;
        https_info.hostname = "example.com".to_string();
        https_info.allows_all_namespaces = true;
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
        terminate_info.tls_outcome = ListenerTlsOutcome::Unsupported {
            message: "tls.mode: Terminate is not supported".to_string(),
        };
        terminate_info.port = 8443;
        status
            .listeners
            .insert(ListenerStatusKey::gateway("tls-terminate"), terminate_info);

        let mut passthrough_info = ListenerInfo::default();
        passthrough_info.tls_outcome = ListenerTlsOutcome::TlsPassthrough;
        passthrough_info.port = 8444;
        status.listeners.insert(
            ListenerStatusKey::gateway("tls-passthrough"),
            passthrough_info,
        );

        // GEP-1713: a listener contributed by a ListenerSet shares the name "http"
        // with the Gateway's own listener but lives under a distinct ListenerSource
        // and on a different port. It must survive the round-trip as its own entry,
        // and a conflicted listener must carry `conflicted=true` across the wire.
        let ls_key = ObjectKey::new("apps", "team-a");
        let mut ls_http = ListenerInfo::default();
        ls_http.tls_outcome = ListenerTlsOutcome::NotApplicable;
        ls_http.attached_routes = 7;
        ls_http.port = 8080;
        ls_http.conflicted = true;
        status.listeners.insert(
            ListenerStatusKey::listener_set(ls_key.clone(), "http"),
            ls_http,
        );

        map.insert(ObjectKey::new("default", "my-gw"), status);

        let dto = listener_status_to_wire(&map);
        let map2 = listener_status_from_wire(&dto).expect("from_wire");

        let h2 = map2
            .get(&ObjectKey::new("default", "my-gw"))
            .expect("key found");
        assert_eq!(h2.listeners.len(), 5, "listener count preserved");
        let gw_http = ListenerStatusKey::gateway("http");
        let gw_https = ListenerStatusKey::gateway("https");
        assert_eq!(
            h2.listeners[&gw_http].attached_routes, 3,
            "attached_routes preserved"
        );
        assert!(
            matches!(
                h2.listeners[&gw_https].tls_outcome,
                ListenerTlsOutcome::Resolved
            ),
            "tls_outcome preserved"
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
                &h2.listeners[&ListenerStatusKey::gateway("tls-terminate")].tls_outcome,
                ListenerTlsOutcome::Unsupported { message }
                    if message == "tls.mode: Terminate is not supported"
            ),
            "Unsupported outcome + message preserved"
        );
        assert!(
            matches!(
                h2.listeners[&ListenerStatusKey::gateway("tls-passthrough")].tls_outcome,
                ListenerTlsOutcome::TlsPassthrough
            ),
            "TlsPassthrough outcome preserved"
        );
        // GEP-1713: the ListenerSet-sourced "http" is a distinct entry from the
        // Gateway's own "http", proving (source, name) keying survives the wire.
        let ls_http_key = ListenerStatusKey::listener_set(ls_key, "http");
        assert_eq!(
            h2.listeners[&ls_http_key].attached_routes, 7,
            "ListenerSet listener round-trips under its own source"
        );
        assert!(
            h2.listeners[&ls_http_key].conflicted,
            "conflicted flag preserved across the wire"
        );
    }
}
