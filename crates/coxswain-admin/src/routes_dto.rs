//! Typed serde model of the proxy `/api/v1/routes` wire contract and the
//! aggregator response payloads built from it (`/api/v1/problems`, route `…/check`).
//!
//! One struct set is shared across both ends of the boundary: `AdminServer::routes_block`
//! (the producer, running on proxy pods) serialises these types, and the controller
//! aggregator (`aggregator::{routing,problems,route_check}`) deserialises them. That
//! turns a producer-side field rename into a compile error instead of a silently broken
//! aggregation — the previous code re-parsed the JSON stringly via `as_str().unwrap_or("")`.
//!
//! Shapes mirror the schemas in `api/openapi.yaml` (`RouteBlock`,
//! `Problems`/`Problem`, and the route-check response); keep both in sync. Object-key
//! ordering is not part of the contract — serde emits fields in declaration order, the
//! previous `serde_json::json!` path emitted them key-sorted; every consumer parses JSON,
//! so this is structurally identical.
//!
//! These types are `pub(crate)` (crate-internal, not a cross-crate API), so they are
//! exempt from the `#[non_exhaustive]` stability gate and are constructed via field
//! literals throughout the crate.

use coxswain_core::routing::{RouteConflict, RouteInfo};
use serde::{Deserialize, Serialize};

// ── Wire payload: GET /api/v1/routes ──────────────────────────────────────────

/// Top-level `/api/v1/routes` body: one [`RouteBlock`] per routing surface. A
/// missing surface deserialises to an empty block (tolerant reader — the producer
/// always emits both).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct RoutesResponse {
    #[serde(default)]
    pub(crate) ingress: RouteBlock,
    #[serde(default)]
    pub(crate) gateway: RouteBlock,
}

/// Per-surface compiled routes; gains `total`/`returned`/`offset` counts only when
/// filter/pagination params were supplied (mirrors openapi `RouteBlock`).
///
/// Collection fields default to empty on deserialize so a peer running a different
/// build (rolling upgrade) that omits one doesn't mark the whole proxy unreachable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct RouteBlock {
    #[serde(default)]
    pub(crate) hosts: Vec<HostGroup>,
    #[serde(default)]
    pub(crate) conflicts: Vec<ConflictRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) total: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) returned: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) offset: Option<usize>,
}

/// One `(port, host)` group and its compiled route rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HostGroup {
    pub(crate) port: u16,
    pub(crate) host: String,
    #[serde(default)]
    pub(crate) routes: Vec<RouteRow>,
}

/// A single compiled path rule as shown in the route table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RouteRow {
    /// Match kind: `"exact"` | `"prefix"` | `"regex"`.
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) path: String,
    pub(crate) backend_group: String,
    pub(crate) namespace: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) endpoints: Vec<String>,
}

/// A path rule dropped because an earlier rule already claimed the same slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ConflictRow {
    pub(crate) port: u16,
    pub(crate) host: String,
    /// Match kind: `"exact"` | `"prefix"` | `"regex"`.
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) path: String,
    pub(crate) rejected_group: String,
    pub(crate) namespace: String,
    pub(crate) name: String,
}

impl RouteRow {
    /// Build a route row from a compiled [`RouteInfo`]: splits `route_id` into
    /// `namespace`/`name` and renders endpoints as `host:port` strings.
    pub(crate) fn from_info(info: &RouteInfo) -> Self {
        let (namespace, name) = info
            .route_id
            .split_once('/')
            .unwrap_or(("", info.route_id.as_str()));
        Self {
            kind: info.kind.as_str().to_owned(),
            path: info.path.clone(),
            backend_group: info.backend_group.name().to_owned(),
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            endpoints: info
                .backend_group
                .endpoints()
                .iter()
                .map(|a| a.to_string())
                .collect(),
        }
    }
}

impl ConflictRow {
    /// Build a conflict row from a compiled [`RouteConflict`]: splits the rejected
    /// route's `route_id` into `namespace`/`name`.
    pub(crate) fn from_conflict(c: &RouteConflict) -> Self {
        let (namespace, name) = c
            .rejected_route_id
            .split_once('/')
            .unwrap_or(("", c.rejected_route_id.as_str()));
        Self {
            port: c.port,
            host: c.host.clone(),
            kind: c.kind.as_str().to_owned(),
            path: c.path.clone(),
            rejected_group: c.rejected_group.clone(),
            namespace: namespace.to_owned(),
            name: name.to_owned(),
        }
    }
}

// ── Aggregator fan-out envelope (admin-internal) ──────────────────────────────

/// One proxy's `/api/v1/routes` fan-out result: the parsed body, or `None` when the
/// pod was unreachable or returned an unparseable response. `reachable` mirrors
/// `routes.is_some()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProxyRoutes {
    pub(crate) pod_name: String,
    pub(crate) reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) routes: Option<RoutesResponse>,
}

// ── Output: GET /api/v1/problems (routing half) ───────────────────────────────

/// The `routing` half of `/api/v1/problems` (mirrors openapi `Problems.routing`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct RoutingProblems {
    pub(crate) conflicts: Vec<Problem>,
    pub(crate) dead_routes: Vec<Problem>,
}

/// One deduplicated routing problem and the pods that reported it (mirrors openapi
/// `Problem`). `rejected_group` is set on conflicts only, `backend_group` on dead
/// routes only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Problem {
    pub(crate) host: String,
    pub(crate) path: String,
    /// Routing surface: `"ingress"` | `"gateway"`.
    pub(crate) kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rejected_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) backend_group: Option<String>,
    pub(crate) pods: Vec<String>,
    pub(crate) route: RouteRef,
}

/// Source resource identity for a problem's deep-link (`kind` is the capitalised
/// resource kind, e.g. `"Ingress"`/`"HTTPRoute"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RouteRef {
    pub(crate) kind: String,
    pub(crate) namespace: String,
    pub(crate) name: String,
}

// ── Output: route …/check ─────────────────────────────────────────────────────

/// `…/routes/{kind}/{ns}/{name}/check` response: the union of expected route keys
/// and each serving proxy's view of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RouteCheck {
    pub(crate) kind: String,
    pub(crate) namespace: String,
    pub(crate) name: String,
    pub(crate) consistent: bool,
    pub(crate) expected: Vec<RouteKey>,
    pub(crate) proxies: Vec<ProxyCheck>,
}

/// `(host, path, backend_group)` identity of a compiled route; also the set-membership
/// key when diffing rows across proxies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct RouteKey {
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) backend_group: String,
}

/// One serving proxy's view in a route check. `rows`/`missing` are absent when the
/// pod is unreachable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProxyCheck {
    pub(crate) pod_name: String,
    pub(crate) reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rows: Option<Vec<CheckRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) missing: Option<Vec<RouteKey>>,
}

/// A route row present on a proxy, flagged `dead` when it serves zero endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CheckRow {
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) backend_group: String,
    pub(crate) endpoints: Vec<String>,
    pub(crate) dead: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative proxy `/api/v1/routes` body (unfiltered variant: no
    /// `total`/`returned`/`offset`), as the aggregator fans out without params.
    fn sample_unfiltered() -> serde_json::Value {
        serde_json::json!({
            "ingress": {
                "hosts": [{
                    "port": 80,
                    "host": "app.example.com",
                    "routes": [{
                        "type": "prefix",
                        "path": "/",
                        "backend_group": "default/app",
                        "namespace": "default",
                        "name": "app",
                        "endpoints": ["10.0.0.1:8080"]
                    }]
                }],
                "conflicts": [{
                    "port": 80,
                    "host": "app.example.com",
                    "type": "exact",
                    "path": "/dup",
                    "rejected_group": "default/other",
                    "namespace": "default",
                    "name": "other"
                }]
            },
            "gateway": { "hosts": [], "conflicts": [] }
        })
    }

    #[test]
    fn unfiltered_body_round_trips_structurally() {
        let original = sample_unfiltered();
        let typed: RoutesResponse =
            serde_json::from_value(original.clone()).expect("deserialise sample body");
        let reserialised = serde_json::to_value(&typed).expect("serialise typed body");
        // Structural (not byte) equality: object-key order is not part of the contract.
        assert_eq!(original, reserialised);
    }

    #[test]
    fn filtered_block_preserves_envelope_counts() {
        let filtered = serde_json::json!({
            "hosts": [],
            "conflicts": [],
            "total": 7,
            "returned": 2,
            "offset": 5
        });
        let block: RouteBlock =
            serde_json::from_value(filtered.clone()).expect("deserialise filtered block");
        assert_eq!(block.total, Some(7));
        assert_eq!(serde_json::to_value(&block).expect("serialise"), filtered);
    }

    #[test]
    fn unfiltered_block_omits_envelope_counts() {
        let block = RouteBlock::default();
        let v = serde_json::to_value(&block).expect("serialise");
        let obj = v.as_object().expect("object");
        assert!(!obj.contains_key("total"));
        assert!(!obj.contains_key("returned"));
        assert!(!obj.contains_key("offset"));
    }
}
