//! Server-side materialized view: the routing world as a keyed resource set.
//!
//! [`materialize`] is the **single seam between the controller's `Shared` cells
//! and the discovery wire** (#383). It reads the same cells the v1
//! `build_snapshot` read — with the same pre-load publish-seq capture, the same
//! per-scope dispatch, and the same fail-closed empty-world branches — but emits
//! a resource-oriented [`MaterializedView`] instead of nine whole-table DTOs.
//!
//! Keeping this the *only* cell-reading function is deliberate: a later relay
//! (#384) feeds the same view from its client cache, so the server-side wire
//! shape is defined once, here.
//!
//! The view is diff-oriented: [`MaterializedView::resource_hashes`] is the
//! per-stream delta baseline, and `server.rs` diffs successive generations of the
//! same view to emit upserts + tombstones. A per-generation cache (see `view_for`
//! in `server.rs`) materializes the shared-pool world once per rebuild and shares
//! the resulting `Arc<MaterializedView>` across every shared-pool stream.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use coxswain_core::listener_status::GatewayListenerStatus;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{
    GatewayRoutingTable, IngressRoutingTable, TcpRouteTable, TlsPassthroughTable, UdpRouteTable,
};
use coxswain_core::tls::{ClientCertStore, PortTlsStore};

use crate::auth::{PeerSvid, svid_matches_dedicated_gateway};
use crate::proto::v1 as p;
use crate::server::SnapshotSource;
use crate::subscription::Scope;
use crate::version::ContentHash;
use crate::wire::resource::{canonical_key, resource_hash};
use crate::wire::{
    EndpointCollector, client_cert_resources, gateway_route_resources, ingress_route_resources,
    listener_status_resources, passthrough_resources, port_tls_resources, tcp_resources,
    udp_resources,
};

/// One resource in a [`MaterializedView`]: its content hash and the shared DTO.
///
/// The `Arc` lets the per-generation view cache (commit 7) and each stream's
/// pending-world snapshot share the resource bytes without cloning.
#[non_exhaustive]
pub struct ResourceEntry {
    /// Lowercase-hex `sha256` of the resource's proto encoding (change oracle).
    pub hash: String,
    /// The resource DTO, shared behind an `Arc`.
    pub resource: Arc<p::Resource>,
}

/// The routing world for one scope as a canonical-key-addressed resource set.
///
/// `version` is the global content hash (order-independent over the per-resource
/// hashes) — formally identical to the v1 whole-table hash, so NodeRegistry /
/// #531 convergence is untouched. `seq` is the pre-load publish-sequence capture
/// used by the #531 ack gate.
#[non_exhaustive]
pub struct MaterializedView {
    /// Global content hash of the post-apply world (sha256 hex).
    pub version: String,
    /// Publish sequence captured before any cell was read (never on the wire).
    pub seq: u64,
    /// Resources keyed by canonical key, in sorted order.
    pub resources: BTreeMap<String, ResourceEntry>,
    /// The canonical-key → per-resource-hash map of this world, precomputed once
    /// per view and shared behind an `Arc`.
    ///
    /// This is the sole per-stream delta baseline: the server retains it as the
    /// `pending`/`acked` world so it can diff the next generation's view against
    /// exactly what a node last confirmed. It intentionally drops the resource DTOs
    /// (kept behind the view's `Arc`s) — a diff only needs the hashes to decide
    /// which keys moved, and the upsert bodies are cloned lazily from the view at
    /// send time. Precomputing it here (rather than re-deriving per send) means each
    /// stream's pending world is a cheap `Arc` clone, never a full map copy.
    pub resource_hashes: Arc<BTreeMap<String, String>>,
}

/// References to the nine routing cells a view is built from, grouped to keep the
/// builder under the workspace 7-argument limit.
struct ViewInputs<'a> {
    ingress: &'a IngressRoutingTable,
    gateway: &'a GatewayRoutingTable,
    tls: &'a PortTlsStore,
    client_certs: &'a ClientCertStore,
    listener_status: &'a HashMap<ObjectKey, GatewayListenerStatus>,
    passthrough: &'a TlsPassthroughTable,
    terminate: &'a TlsPassthroughTable,
    tcp: &'a TcpRouteTable,
    udp: &'a UdpRouteTable,
}

/// Materialize the routing world for `scope` into a [`MaterializedView`].
///
/// - [`Scope::SharedPool`] reads the six shared L7/status cells plus the four L4
///   cells (these deliberately exclude cut-over Gateways).
/// - [`Scope::Gateway`] reads only the Gateway's dedicated-registry slice (empty
///   Ingress, empty L4). An absent entry — or a `peer_svid` that does not match
///   the entry's `expected_proxy_sa` — yields an empty world at **seq 0**, so an
///   Ack of a fail-closed world never advances the node's #531 convergence stamp.
///   This is the build-time complement to the open-time `PERMISSION_DENIED` check
///   in `server::stream` and closes the appear-after-open race (#427).
///
/// The publish sequence is captured BEFORE any cell load: every rebuild stamped
/// at a sequence `<=` the captured value stored its cells before bumping the
/// counter, so the loaded content is at least that new.
#[must_use = "the materialized view is the wire payload; discarding it drops the snapshot"]
pub fn materialize(
    source: &SnapshotSource,
    scope: &Scope,
    peer_svid: Option<&PeerSvid>,
) -> MaterializedView {
    let seq = source.publish.current_seq();
    match scope {
        Scope::SharedPool => {
            let ingress = source.ingress.load();
            let gateway = source.gateway.load();
            let tls = source.tls.load();
            let client_certs = source.client_certs.load();
            let listener_status = source.listener_status.load();
            let passthrough = source.passthrough_routes.load();
            let terminate = source.terminate_routes.load();
            let tcp = source.tcp_routes.load();
            let udp = source.udp_routes.load();
            build_view(
                &ViewInputs {
                    ingress: &ingress,
                    gateway: &gateway,
                    tls: &tls,
                    client_certs: &client_certs,
                    listener_status: &listener_status,
                    passthrough: &passthrough,
                    terminate: &terminate,
                    tcp: &tcp,
                    udp: &udp,
                },
                seq,
            )
        }
        Scope::Gateway { name, namespace } => {
            let key = ObjectKey::new(namespace.clone(), name.clone());
            let registry = source.dedicated.load();
            match registry.get(&key) {
                Some(snap) => {
                    // Build-time SVID binding: a Gateway entry that appeared after
                    // the open-time check must still be served only to its bound
                    // proxy identity, else an empty (seq-0) world.
                    if let Some(peer) = peer_svid
                        && !svid_matches_dedicated_gateway(
                            &peer.uri_sans,
                            namespace,
                            &snap.expected_proxy_sa,
                        )
                    {
                        return empty_view();
                    }
                    let empty_ingress = IngressRoutingTable::default();
                    let empty_pt = TlsPassthroughTable::default();
                    let empty_tcp = TcpRouteTable::default();
                    let empty_udp = UdpRouteTable::default();
                    build_view(
                        &ViewInputs {
                            // A dedicated proxy never serves Ingress or L4 traffic.
                            ingress: &empty_ingress,
                            gateway: &snap.gateway,
                            tls: &snap.tls,
                            client_certs: &snap.client_certs,
                            listener_status: &snap.listener_status,
                            passthrough: &empty_pt,
                            terminate: &empty_pt,
                            tcp: &empty_tcp,
                            udp: &empty_udp,
                        },
                        seq,
                    )
                }
                // Fail closed: not (yet) cut over → an empty world at seq 0.
                None => empty_view(),
            }
        }
    }
}

/// A deliberately-empty world at seq 0 (fail-closed dedicated branches).
fn empty_view() -> MaterializedView {
    MaterializedView {
        version: ContentHash::from_per_resource(Vec::new())
            .as_str()
            .to_owned(),
        seq: 0,
        resources: BTreeMap::new(),
        resource_hashes: Arc::new(BTreeMap::new()),
    }
}

/// Walk every cell once, emit per-resource DTOs (endpoints derived from backend
/// provenance), and fold them into a canonical-key-keyed view with a global hash.
fn build_view(inputs: &ViewInputs<'_>, seq: u64) -> MaterializedView {
    let mut endpoints = EndpointCollector::new();
    let mut all: Vec<p::Resource> = Vec::new();
    all.extend(ingress_route_resources(inputs.ingress, &mut endpoints));
    all.extend(gateway_route_resources(inputs.gateway, &mut endpoints));
    all.extend(port_tls_resources(inputs.tls));
    all.extend(client_cert_resources(inputs.client_certs));
    all.extend(listener_status_resources(inputs.listener_status));
    all.extend(passthrough_resources(
        inputs.passthrough,
        false,
        &mut endpoints,
    ));
    all.extend(passthrough_resources(
        inputs.terminate,
        true,
        &mut endpoints,
    ));
    all.extend(tcp_resources(inputs.tcp, &mut endpoints));
    all.extend(udp_resources(inputs.udp, &mut endpoints));
    // Endpoints last: they are populated by the route/L4 passes above.
    all.extend(endpoints.into_resources());

    let mut resources: BTreeMap<String, ResourceEntry> = BTreeMap::new();
    for resource in all {
        // canonical_key only fails for a resource we could not have emitted
        // (missing arm / unspecified table). Skip such a resource defensively
        // rather than panic — a dropped resource degrades one route, a panic
        // stalls the whole data plane. The emitters never produce one.
        let Ok(key) = canonical_key(&resource) else {
            continue;
        };
        let hash = resource_hash(&resource);
        let prev = resources.insert(
            key,
            ResourceEntry {
                hash,
                resource: Arc::new(resource),
            },
        );
        // The emitters never produce two resources with the same canonical key;
        // if a future one did, the last write wins the served set — the version
        // is derived from that set below, so it can never count a resource we
        // don't serve (a permanent-Nack hazard).
        debug_assert!(
            prev.is_none(),
            "duplicate canonical key would desync version from the served resource set"
        );
    }
    // Precompute the canonical-key → per-resource-hash map from the SERVED set (not
    // a parallel push list), so both the delta baseline AND the global `version`
    // are consistent-by-construction with `resources` even under a hypothetical
    // duplicate-key overwrite. `from_per_resource` is order-independent, so the
    // BTreeMap iteration order is irrelevant.
    let resource_hashes: BTreeMap<String, String> = resources
        .iter()
        .map(|(key, entry)| (key.clone(), entry.hash.clone()))
        .collect();
    let version = ContentHash::from_per_resource(resource_hashes.values().cloned().collect())
        .as_str()
        .to_owned();

    MaterializedView {
        version,
        seq,
        resources,
        resource_hashes: Arc::new(resource_hashes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::dedicated_registry::DedicatedRoutingRegistry;
    use coxswain_core::listener_status::SharedGatewayListenerStatus;
    use coxswain_core::publish_index::SharedGatewayPublishIndex;
    use coxswain_core::routing::{
        BackendGroup, IngressRoutingTableBuilder, RouteEntry, SharedGatewayRoutingTable,
        SharedIngressRoutingTable, SharedTcpRouteTable, SharedTlsPassthroughTable,
        SharedUdpRouteTable,
    };
    use coxswain_core::tls::{SharedClientCertStore, SharedPortTlsStore};

    fn source_with_ingress(table: IngressRoutingTable) -> SnapshotSource {
        let ingress = SharedIngressRoutingTable::new();
        ingress.store(Arc::new(table));
        SnapshotSource {
            ingress,
            gateway: SharedGatewayRoutingTable::new(),
            tls: SharedPortTlsStore::new(),
            client_certs: SharedClientCertStore::new(),
            listener_status: SharedGatewayListenerStatus::new(),
            dedicated: DedicatedRoutingRegistry::new(),
            passthrough_routes: SharedTlsPassthroughTable::new(),
            terminate_routes: SharedTlsPassthroughTable::new(),
            tcp_routes: SharedTcpRouteTable::new(),
            udp_routes: SharedUdpRouteTable::new(),
            publish: SharedGatewayPublishIndex::new(),
        }
    }

    fn ingress_with_route() -> IngressRoutingTable {
        let bg = Arc::new(BackendGroup::new(
            "ns/svc".to_owned(),
            vec!["10.0.0.1:80".parse().unwrap()],
        ));
        let entry = Arc::new(RouteEntry::path_only(bg, "ns/r".to_owned(), None));
        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);
        b.build().expect("build")
    }

    /// Materializing the same cells twice yields the same global version and the
    /// same canonical-key set — the convergence oracle is stable.
    #[test]
    fn materialize_is_deterministic() {
        let source = source_with_ingress(ingress_with_route());
        let a = materialize(&source, &Scope::SharedPool, None);
        let b = materialize(&source, &Scope::SharedPool, None);
        assert_eq!(a.version, b.version, "same cells → same global version");
        let ka: Vec<&String> = a.resources.keys().collect();
        let kb: Vec<&String> = b.resources.keys().collect();
        assert_eq!(ka, kb, "same cells → same canonical key set");
        assert!(
            a.resources
                .contains_key("route|ingress|80|exact|example.com"),
            "the route resource is keyed canonically"
        );
    }

    /// An absent dedicated Gateway materializes to an empty world at seq 0.
    #[test]
    fn absent_gateway_scope_is_empty_seq_zero() {
        let source = source_with_ingress(IngressRoutingTable::default());
        let view = materialize(
            &source,
            &Scope::Gateway {
                name: "gw".to_owned(),
                namespace: "prod".to_owned(),
            },
            None,
        );
        assert!(view.resources.is_empty(), "fail-closed empty world");
        assert_eq!(view.seq, 0, "empty world records seq 0");
    }
}
