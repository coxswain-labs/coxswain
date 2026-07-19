//! Typed serde model of a proxy's compiled routing table
//! (`fleet/proxies/{name}/routes|facets`) and the aggregator response
//! payloads built from it (`/api/v1/problems`).
//!
//! One struct set spans both producer and consumer: `aggregator::proxies::routes_block`
//! builds these types from the controller's own local routing snapshot (#537),
//! and `aggregator::{routing,problems}` consume them. That turns a field rename
//! into a compile error instead of a silently broken aggregation — the previous
//! code re-parsed the JSON stringly via `as_str().unwrap_or("")`.
//!
//! Shapes mirror the schemas in `api/openapi.yaml` (`RouteBlock`,
//! `Problems`/`Problem`); keep both in sync. Object-key ordering is not part of
//! the contract — serde emits fields in declaration order, the previous
//! `serde_json::json!` path emitted them key-sorted; every consumer parses
//! JSON, so this is structurally identical.
//!
//! These types are `pub(crate)` — crate-internal, not a cross-crate API.

use coxswain_core::routing::{RouteConflict, RouteInfo};
use serde::{Deserialize, Serialize};

// ── Compiled routing table: fleet/proxies/{name}/routes ───────────────────────

/// A proxy's compiled routing table: one [`RouteBlock`] per routing surface. A
/// missing surface deserialises to an empty block (tolerant reader — the
/// producer always emits both).
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

// ── Aggregator per-proxy envelope (admin-internal) ────────────────────────────

/// One proxy's local-snapshot routing view (#537): `pod_name` plus its
/// [`RoutesResponse`], or `None` when the pod isn't a known fleet member.
/// `reachable` mirrors `routes.is_some()` — a vestige of the pre-#537 HTTP
/// fan-out envelope, kept for API/UI shape compatibility.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative `RoutesResponse` body (unfiltered variant: no
    /// `total`/`returned`/`offset`), as built without list params.
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
