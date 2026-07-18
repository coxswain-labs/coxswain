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
/// The `Arc` lets the per-generation view cache and each stream's pending-world
/// snapshot share the resource bytes without cloning.
#[non_exhaustive]
pub struct ResourceEntry {
    /// Lowercase-hex `sha256` of the resource's proto encoding (change oracle).
    ///
    /// `Arc<str>` so the per-generation `resource_hashes` baseline and the global
    /// version input share this digest allocation instead of deep-copying the
    /// 64-byte hex string once per stream.
    pub hash: Arc<str>,
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
    pub resource_hashes: Arc<BTreeMap<String, Arc<str>>>,
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
///   Ingress, empty L4). An absent entry yields an empty world at **seq 0**, so an
///   Ack of a fail-closed world never advances the node's #531 convergence stamp.
///
/// The build is deliberately **SVID-independent**: the per-subscriber
/// `Scope::Gateway` binding check (the #427 appear-after-open race guard) lives in
/// `server::view_for` as a post-cache filter, so this expensive build can be
/// shared across every subscriber of the same Gateway at one generation. The
/// open-time `PERMISSION_DENIED` check in `server::stream` remains the primary
/// gate.
///
/// The publish sequence is captured BEFORE any cell load: every rebuild stamped
/// at a sequence `<=` the captured value stored its cells before bumping the
/// counter, so the loaded content is at least that new.
#[must_use = "the materialized view is the wire payload; discarding it drops the snapshot"]
pub fn materialize(source: &SnapshotSource, scope: &Scope) -> MaterializedView {
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
            match registry.map.get(&key) {
                Some(snap) => {
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
        Scope::Namespace { namespace } => build_namespace_view(source, namespace, seq),
    }
}

/// Materialize every dedicated Gateway in `namespace` into one aggregate view
/// (#582, the relay tier's upstream subscription). Each Gateway's own
/// resources (routes, TLS, client-certs, listener status — the same slice
/// [`Scope::Gateway`] serves) are wrapped with the `gw|<ns>|<name>|` canonical-key
/// qualifier via [`p::Resource::qualifier_namespace`] / `qualifier_name`, plus one
/// [`p::resource::Payload::GatewayMeta`] resource carrying its publish sequence
/// (already tracked per Gateway by [`crate::server::SnapshotSource::publish`]).
/// EDS endpoint resources stay unqualified — they address a Service by
/// `(namespace, service, port)` independent of which Gateway references it, and
/// naturally de-duplicate via [`EndpointCollector`] when two Gateways in the
/// same namespace share a backend.
///
/// A namespace with no cut-over dedicated Gateways fails closed to an empty
/// world at seq 0, mirroring the absent-Gateway branch above.
fn build_namespace_view(source: &SnapshotSource, namespace: &str, seq: u64) -> MaterializedView {
    let registry = source.dedicated.load();
    let mut endpoints = EndpointCollector::new();
    let mut all: Vec<p::Resource> = Vec::new();
    let mut any_gateway = false;

    // Namespace fan-out via the prebuilt `by_ns` index (#621) — O(gateways in ns)
    // instead of scanning every dedicated Gateway in the cluster per namespace.
    let mut keys: Vec<&ObjectKey> = registry
        .by_ns
        .get(namespace)
        .map(|keys| keys.iter().collect())
        .unwrap_or_default();
    // Deterministic iteration order (the index Vec follows HashMap insertion):
    // sort by name so repeated materializations of the same cells fold identically.
    keys.sort_by(|a, b| a.name.cmp(&b.name));

    for key in keys {
        // Always present — `by_ns` is derived from `map` at construction — but a
        // missing entry degrades to one skipped Gateway rather than a panic.
        let Some(snap) = registry.map.get(key) else {
            continue;
        };
        any_gateway = true;
        let mut gw_resources: Vec<p::Resource> = Vec::new();
        gw_resources.extend(gateway_route_resources(&snap.gateway, &mut endpoints));
        gw_resources.extend(port_tls_resources(&snap.tls));
        gw_resources.extend(client_cert_resources(&snap.client_certs));
        gw_resources.extend(listener_status_resources(&snap.listener_status));
        for resource in &mut gw_resources {
            resource.qualifier_namespace.clone_from(&key.ns);
            resource.qualifier_name.clone_from(&key.name);
        }
        let publish_seq = source.publish.get(key).map_or(0, |stamp| stamp.seq);
        gw_resources.push(p::Resource {
            payload: Some(p::resource::Payload::GatewayMeta(p::GatewayMeta {
                publish_seq,
                // The relay needs the bound proxy SA to enforce the same
                // downstream `Scope::Gateway` SVID binding the controller does;
                // it cannot derive it (never sees the GatewayClass name).
                expected_proxy_sa: snap.expected_proxy_sa.clone(),
            })),
            qualifier_namespace: key.ns.clone(),
            qualifier_name: key.name.clone(),
        });
        all.extend(gw_resources);
    }

    if !any_gateway {
        return empty_view();
    }
    all.extend(endpoints.into_resources());
    fold_resources(all, seq)
}

/// A deliberately-empty world at seq 0 (fail-closed dedicated branches).
///
/// Also the per-subscriber SVID-mismatch result served by [`crate::server::view_for`]:
/// the Gateway view cache holds the SVID-independent real world, and a denied
/// peer is handed this uncached empty world instead (never advancing its #531
/// convergence stamp).
pub(crate) fn empty_view() -> MaterializedView {
    MaterializedView {
        version: ContentHash::from_per_resource(std::iter::empty())
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
    fold_resources(all, seq)
}

/// Fold a flat list of emitted resources into a canonical-key-keyed view with a
/// global content hash. Shared by [`build_view`] (SharedPool/Gateway) and
/// [`build_namespace_view`] (#582) so the folding + hashing discipline lives
/// in exactly one place.
fn fold_resources(all: Vec<p::Resource>, seq: u64) -> MaterializedView {
    let mut resources: BTreeMap<String, ResourceEntry> = BTreeMap::new();
    for resource in all {
        // canonical_key only fails for a resource we could not have emitted
        // (missing arm / unspecified table). Skip such a resource defensively
        // rather than panic — a dropped resource degrades one route, a panic
        // stalls the whole data plane. The emitters never produce one.
        let Ok(key) = canonical_key(&resource) else {
            continue;
        };
        let hash: Arc<str> = Arc::from(resource_hash(&resource));
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
    let resource_hashes: BTreeMap<String, Arc<str>> = resources
        .iter()
        .map(|(key, entry)| (key.clone(), Arc::clone(&entry.hash)))
        .collect();
    let version = ContentHash::from_per_resource(resource_hashes.values().map(|h| &**h))
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
    use coxswain_core::dedicated_registry::{
        DedicatedRegistryData, DedicatedRoutingRegistry, DedicatedRoutingSnapshot,
    };
    use coxswain_core::listener_status::SharedGatewayListenerStatus;
    use coxswain_core::publish_index::SharedGatewayPublishIndex;
    use coxswain_core::routing::{
        BackendGroup, GatewayRoutingTableBuilder, IngressRoutingTableBuilder, RouteEntry,
        SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
        SharedTlsPassthroughTable, SharedUdpRouteTable,
    };
    use coxswain_core::tls::{
        ClientCertStore, PortTlsStore, SharedClientCertStore, SharedPortTlsStore,
    };
    use std::collections::HashMap as StdHashMap;

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
        let a = materialize(&source, &Scope::SharedPool);
        let b = materialize(&source, &Scope::SharedPool);
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
        );
        assert!(view.resources.is_empty(), "fail-closed empty world");
        assert_eq!(view.seq, 0, "empty world records seq 0");
    }

    // ── #582: Namespace scope materialize ───────────────────────────────────

    /// A dedicated Gateway snapshot with one Gateway-table route on `host`,
    /// backed by `svc`.
    fn dedicated_snapshot(host: &str, svc: &str) -> DedicatedRoutingSnapshot {
        let bg = Arc::new(BackendGroup::new(
            format!("prod/{svc}"),
            vec!["10.0.0.1:80".parse().unwrap()],
        ));
        let entry = Arc::new(RouteEntry::path_only(bg, format!("prod/{svc}"), None));
        let mut b = GatewayRoutingTableBuilder::new();
        b.for_port(443).exact_host(host).add_exact_route("/", entry);
        DedicatedRoutingSnapshot {
            gateway: Arc::new(b.build().expect("build")),
            tls: Arc::new(PortTlsStore::default()),
            client_certs: Arc::new(ClientCertStore::default()),
            listener_status: StdHashMap::new(),
            expected_proxy_sa: format!("{svc}-coxswain"),
        }
    }

    fn source_with_dedicated(
        entries: Vec<(&str, &str, &str)>, // (namespace, name, host)
    ) -> SnapshotSource {
        let dedicated = DedicatedRoutingRegistry::new();
        let mut map = StdHashMap::new();
        for (ns, name, host) in &entries {
            let key = ObjectKey::new((*ns).to_owned(), (*name).to_owned());
            map.insert(key, Arc::new(dedicated_snapshot(host, name)));
        }
        dedicated.store(Arc::new(DedicatedRegistryData::from_map(map)));

        // Stamp each Gateway's publish-seq via its own incremental rebuild call,
        // always re-including every previously-stamped Gateway at the same
        // (generation, fingerprint) so it stays sticky (per `stamp_rebuild`'s
        // contract) — this is how sequential real-world rebuilds give each
        // Gateway a distinct seq rather than all sharing one call's sequence.
        let publish = SharedGatewayPublishIndex::new();
        let mut accum: Vec<(ObjectKey, i64, u64)> = Vec::new();
        for (ns, name, _) in &entries {
            accum.push((ObjectKey::new((*ns).to_owned(), (*name).to_owned()), 1, 0));
            publish.stamp_rebuild(accum.clone());
        }
        SnapshotSource {
            ingress: SharedIngressRoutingTable::new(),
            gateway: SharedGatewayRoutingTable::new(),
            tls: SharedPortTlsStore::new(),
            client_certs: SharedClientCertStore::new(),
            listener_status: SharedGatewayListenerStatus::new(),
            dedicated,
            passthrough_routes: SharedTlsPassthroughTable::new(),
            terminate_routes: SharedTlsPassthroughTable::new(),
            tcp_routes: SharedTcpRouteTable::new(),
            udp_routes: SharedUdpRouteTable::new(),
            publish,
        }
    }

    /// A `Namespace` view aggregates every dedicated Gateway in that namespace:
    /// each Gateway's route resource is qualified `gw|<ns>|<name>|...`, and each
    /// gets its own `gwmeta|<ns>|<name>` resource stamped with its own
    /// publish-seq (not the namespace-wide `current_seq`).
    #[test]
    fn namespace_view_aggregates_and_qualifies_every_dedicated_gateway() {
        let source = source_with_dedicated(vec![
            ("prod", "gw-a", "a.example.com"),
            ("prod", "gw-b", "b.example.com"),
        ]);
        let view = materialize(
            &source,
            &Scope::Namespace {
                namespace: "prod".to_owned(),
            },
        );
        assert!(
            view.resources
                .contains_key("gw|prod|gw-a|route|gateway|443|exact|a.example.com"),
            "gw-a's route must be qualified: {:?}",
            view.resources.keys().collect::<Vec<_>>()
        );
        assert!(
            view.resources
                .contains_key("gw|prod|gw-b|route|gateway|443|exact|b.example.com"),
            "gw-b's route must be qualified: {:?}",
            view.resources.keys().collect::<Vec<_>>()
        );
        // Assert the actual decoded `publish_seq` per Gateway, not just that the
        // two `GatewayMeta` resources hash differently — their qualifiers alone
        // (`gw-a` vs `gw-b`) would already guarantee that, so a hash-inequality
        // check alone would not catch a bug that stamped every Gateway with the
        // same (or the namespace-wide `current_seq()`) sequence.
        let gwmeta_seq = |key: &str| match view.resources[key].resource.payload.as_ref() {
            Some(p::resource::Payload::GatewayMeta(m)) => m.publish_seq,
            other => panic!("expected GatewayMeta payload at {key}, got {other:?}"),
        };
        assert_eq!(
            gwmeta_seq("gwmeta|prod|gw-a"),
            1,
            "gw-a was stamped at the first incremental rebuild"
        );
        assert_eq!(
            gwmeta_seq("gwmeta|prod|gw-b"),
            2,
            "gw-b was stamped at the second incremental rebuild, distinct from gw-a's"
        );
        // Each GatewayMeta carries the Gateway's bound proxy SA (#583) so the
        // relay can reconstruct the downstream `Scope::Gateway` SVID binding it
        // cannot derive locally. `dedicated_snapshot` stamps `{svc}-coxswain`.
        let gwmeta_sa = |key: &str| match view.resources[key].resource.payload.as_ref() {
            Some(p::resource::Payload::GatewayMeta(m)) => m.expected_proxy_sa.clone(),
            other => panic!("expected GatewayMeta payload at {key}, got {other:?}"),
        };
        assert_eq!(gwmeta_sa("gwmeta|prod|gw-a"), "gw-a-coxswain");
        assert_eq!(gwmeta_sa("gwmeta|prod|gw-b"), "gw-b-coxswain");
    }

    /// A namespace with no cut-over dedicated Gateways fails closed to an empty
    /// world at seq 0, mirroring the absent-Gateway scope branch.
    #[test]
    fn empty_namespace_is_empty_seq_zero() {
        let source = source_with_dedicated(vec![("prod", "gw-a", "a.example.com")]);
        let view = materialize(
            &source,
            &Scope::Namespace {
                namespace: "other-ns".to_owned(),
            },
        );
        assert!(view.resources.is_empty(), "fail-closed empty world");
        assert_eq!(view.seq, 0, "empty world records seq 0");
    }

    /// Removing one Gateway from the dedicated registry changes only that
    /// Gateway's qualified keys in the namespace view — the delta-over-qualified-
    /// keys acceptance criterion (verified here at the materialize layer: the
    /// surviving Gateway's key set is byte-identical across both worlds).
    #[test]
    fn gateway_removal_changes_only_its_own_qualified_keys() {
        let before = source_with_dedicated(vec![
            ("prod", "gw-a", "a.example.com"),
            ("prod", "gw-b", "b.example.com"),
        ]);
        let after = source_with_dedicated(vec![("prod", "gw-a", "a.example.com")]);

        let scope = Scope::Namespace {
            namespace: "prod".to_owned(),
        };
        let view_before = materialize(&before, &scope);
        let view_after = materialize(&after, &scope);

        let gw_a_key = "gw|prod|gw-a|route|gateway|443|exact|a.example.com";
        assert_eq!(
            view_before.resources[gw_a_key].hash, view_after.resources[gw_a_key].hash,
            "gw-a's resources are unaffected by gw-b's removal"
        );
        assert!(
            !view_after
                .resources
                .contains_key("gw|prod|gw-b|route|gateway|443|exact|b.example.com"),
            "gw-b's route must be gone from the post-removal view"
        );
        assert!(
            !view_after.resources.contains_key("gwmeta|prod|gw-b"),
            "gw-b's GatewayMeta must be gone from the post-removal view"
        );
    }
}
