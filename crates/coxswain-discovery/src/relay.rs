//! Relay-tier glue: compose an upstream discovery **client** with a downstream
//! discovery **server** over one process (#583, slice B of the relay epic #384).
//!
//! A relay subscribes upstream to the controller and re-serves the snapshot
//! stream to downstream proxies (leaves), which speak the unchanged protocol and
//! never learn they are behind a relay. Two shapes:
//!
//! - **Shared-pool relay** ([`shared_relay`]): subscribes `Scope::SharedPool`
//!   and re-serves it. The upstream client reconstructs exactly the flat routing
//!   cells a [`SnapshotSource`] serves, so this reuses the proxy's
//!   `RoutingApplier` verbatim — the reconstructed cells *are*
//!   the downstream-serving source.
//! - **Namespace relay** ([`namespace_relay`]): subscribes `Scope::Namespace`
//!   (the relay-tier aggregate) and demuxes the `gw|<ns>|<name>|…`-qualified
//!   resources back into a per-Gateway [`DedicatedRoutingRegistry`] via
//!   `NamespaceDemux`, so its downstream server answers `Scope::Gateway`
//!   subscribes exactly as the controller would (including the SVID binding).
//!
//! Both build a [`SnapshotSource`] from the client's own cache — the seam
//! [`crate::materialize`] documents — and hand it to a downstream
//! [`crate::DiscoveryService`], so the wire shape is defined once, on the server
//! side, and the relay adds no new materialization path.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use coxswain_core::dedicated_registry::{DedicatedRoutingRegistry, DedicatedRoutingSnapshot};
use coxswain_core::health::SubsystemHandle;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::publish_index::SharedGatewayPublishIndex;
use tokio::sync::watch;

use crate::apply::{ApplyStats, RoutingApplier, SnapshotApplier};
use crate::client::{DiscoveryClientConfig, Supervisor};
use crate::error::{DiscoveryError, WireError};
use crate::proto::v1 as p;
use crate::server::SnapshotSource;
use crate::version::ContentHash;
use crate::wire::resource::{canonical_key, resource_hash};

/// A relay's upstream client + the downstream-serving source it feeds (#583).
///
/// The caller (`coxswain-bin`) drives [`Self::supervisor`] as a background
/// service, hands [`Self::source`] + [`Self::rebuild_rx`] to a
/// [`crate::DiscoveryService`], and serves that downstream.
// intentionally open: field-literal consumed at the bin layer
pub struct RelayUpstream {
    /// The downstream-serving snapshot source, populated by the upstream client.
    pub source: SnapshotSource,
    /// The upstream reconnect supervisor — run it as a background service.
    pub supervisor: Supervisor,
    /// Rebuild-generation receiver: bumped after every successful upstream
    /// apply, drives the downstream `DiscoveryService` re-materialization.
    pub rebuild_rx: watch::Receiver<u64>,
}

/// Assemble a **shared-pool** relay's upstream (subscribes `Scope::SharedPool`).
///
/// The flat routing cells the `RoutingApplier` reconstructs are the shared
/// world verbatim, so they become the downstream [`SnapshotSource`]'s shared
/// cells directly; `dedicated` and `publish` stay empty (a shared relay serves
/// no dedicated Gateways).
///
/// `config.scope` must be [`crate::Scope::SharedPool`]; the caller sets it.
///
/// # Errors
///
/// [`DiscoveryError::InvalidEndpoint`] if any upstream endpoint is malformed.
#[must_use = "the returned supervisor + source must be driven and served, or the relay caches nothing"]
pub fn shared_relay(
    config: DiscoveryClientConfig,
    health: SubsystemHandle,
    health_check: &str,
) -> Result<RelayUpstream, DiscoveryError> {
    let (applier, cells) = RoutingApplier::new();
    let (supervisor, rebuild_rx) =
        Supervisor::with_applier(config, health, health_check, Box::new(applier))?;
    let source = SnapshotSource {
        ingress: cells.ingress,
        gateway: cells.gateway,
        tls: cells.tls,
        client_certs: cells.client_certs,
        listener_status: cells.listener_status,
        // A shared relay serves no dedicated Gateways and no cross-tier seq.
        dedicated: DedicatedRoutingRegistry::new(),
        passthrough_routes: cells.passthrough,
        terminate_routes: cells.terminate,
        tcp_routes: cells.tcp,
        udp_routes: cells.udp,
        publish: SharedGatewayPublishIndex::new(),
    };
    Ok(RelayUpstream {
        source,
        supervisor,
        rebuild_rx,
    })
}

/// Assemble a **namespace** relay's upstream (subscribes `Scope::Namespace`).
///
/// The `NamespaceDemux` reconstructs a per-Gateway [`DedicatedRoutingRegistry`]
/// from the qualified resources, so the downstream server answers
/// `Scope::Gateway` subscribes. The shared cells stay empty — a namespace relay
/// serves only dedicated Gateways downstream.
///
/// `config.scope` must be [`crate::Scope::Namespace`]; the caller sets it.
///
/// # Errors
///
/// [`DiscoveryError::InvalidEndpoint`] if any upstream endpoint is malformed.
#[must_use = "the returned supervisor + source must be driven and served, or the relay caches nothing"]
pub fn namespace_relay(
    config: DiscoveryClientConfig,
    health: SubsystemHandle,
    health_check: &str,
) -> Result<RelayUpstream, DiscoveryError> {
    let demux = NamespaceDemux::new();
    // Share the registry + publish index into the downstream-serving source
    // before the demux is boxed into the supervisor (both are cheap `Shared`
    // clones over the same `Arc`, so the source sees every applied rebuild).
    let dedicated = demux.dedicated.clone();
    let publish = demux.publish.clone();
    let (supervisor, rebuild_rx) =
        Supervisor::with_applier(config, health, health_check, Box::new(demux))?;
    let source = SnapshotSource {
        // A namespace relay serves only `Scope::Gateway` downstream, which reads
        // exclusively from `dedicated`; the shared L7/L4 cells stay empty.
        ingress: coxswain_core::routing::SharedIngressRoutingTable::new(),
        gateway: coxswain_core::routing::SharedGatewayRoutingTable::new(),
        tls: coxswain_core::tls::SharedPortTlsStore::new(),
        client_certs: coxswain_core::tls::SharedClientCertStore::new(),
        listener_status: coxswain_core::listener_status::SharedGatewayListenerStatus::new(),
        dedicated,
        passthrough_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
        terminate_routes: coxswain_core::routing::SharedTlsPassthroughTable::new(),
        tcp_routes: coxswain_core::routing::SharedTcpRouteTable::new(),
        udp_routes: coxswain_core::routing::SharedUdpRouteTable::new(),
        publish,
    };
    Ok(RelayUpstream {
        source,
        supervisor,
        rebuild_rx,
    })
}

/// The namespace-relay [`SnapshotApplier`] (#583): demuxes a `Scope::Namespace`
/// stream into a per-Gateway [`DedicatedRoutingRegistry`] + publish index.
///
/// The upstream stream carries every dedicated Gateway's world in one namespace,
/// each resource tagged with a `gw|<ns>|<name>|` qualifier plus a per-Gateway
/// [`p::GatewayMeta`] (publish-seq + bound proxy SA); endpoints ride unqualified
/// and shared. The demux keeps the raw de-duplicated resource set (so it can
/// fold deltas), then rebuilds the registry from it on every apply — the relay
/// is control-plane, not the request hot path, so a full rebuild per message is
/// cheap and keeps the reconstruction a pure function of the wire world.
pub(crate) struct NamespaceDemux {
    /// The de-duplicated wire world last applied, keyed by canonical key. A full
    /// replaces it; a delta upserts/tombstones onto a clone (committed only
    /// after the rebuild below succeeds — atomic like the proxy apply path).
    resources: HashMap<String, Arc<p::Resource>>,
    /// Whether a full has been applied on this session-spanning cache.
    has_full: bool,
    /// Downstream-serving registry (shared with the relay's `SnapshotSource`).
    dedicated: DedicatedRoutingRegistry,
    /// Downstream-serving publish index (shared with the `SnapshotSource`). The
    /// relay's own monotone rebuild counter drives the downstream `Gateway`-view
    /// seq; per-Gateway upstream seq propagation across tiers lands with #585.
    publish: SharedGatewayPublishIndex,
}

impl NamespaceDemux {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            resources: HashMap::new(),
            has_full: false,
            dedicated: DedicatedRoutingRegistry::new(),
            publish: SharedGatewayPublishIndex::new(),
        }
    }

    /// Fold `msg` into a fresh de-duplicated resource map (full = replace-all;
    /// delta = upsert/tombstone onto a clone of the committed world). Mirrors the
    /// proxy apply path's invariants: a delta before a full is rejected, a key in
    /// both a delta's upsert and tombstone sets is rejected, an unheld tombstone
    /// is an idempotent no-op.
    fn stage(&self, msg: &p::Snapshot) -> Result<HashMap<String, Arc<p::Resource>>, WireError> {
        if msg.full {
            let mut staged = HashMap::with_capacity(msg.resources.len());
            for resource in &msg.resources {
                let key = canonical_key(resource).map_err(wire_from_key_err)?;
                if staged.insert(key, Arc::new(resource.clone())).is_some() {
                    return Err(WireError::UnknownResourceKey {
                        reason: "namespace full contains a duplicate canonical resource key",
                    });
                }
            }
            Ok(staged)
        } else {
            let mut staged = self.resources.clone();
            let mut seen = HashSet::new();
            for resource in &msg.resources {
                let key = canonical_key(resource).map_err(wire_from_key_err)?;
                if !seen.insert(key.clone()) {
                    return Err(WireError::UnknownResourceKey {
                        reason: "namespace delta contains a duplicate canonical resource key",
                    });
                }
                staged.insert(key, Arc::new(resource.clone()));
            }
            for removed in &msg.removed_resources {
                if seen.contains(removed.as_str()) {
                    return Err(WireError::UnknownResourceKey {
                        reason: "namespace delta key appears in both upsert and tombstone sets",
                    });
                }
                staged.remove(removed);
            }
            Ok(staged)
        }
    }
}

impl SnapshotApplier for NamespaceDemux {
    fn apply(&mut self, msg: &p::Snapshot, expect_full: bool) -> Result<ApplyStats, WireError> {
        // Invariant 1: the first message of a session is a full (the server's
        // per-stream baseline does not survive a reconnect).
        if !msg.full && expect_full {
            return Err(WireError::DeltaBeforeFullSnapshot);
        }

        let staged = self.stage(msg)?;

        // Version self-check: the namespace view's global hash is order-
        // independent over the per-resource digests of the *qualified* resources,
        // exactly as the controller computed it. A mismatch means the two sides
        // disagree — Nack for a self-healing resync before touching anything.
        let computed =
            ContentHash::from_per_resource(staged.values().map(|r| resource_hash(r)).collect())
                .as_str()
                .to_owned();
        if computed != msg.version {
            return Err(WireError::VersionMismatch {
                expected: msg.version.clone(),
                computed,
            });
        }

        // Rebuild the registry (fallible) before committing any shared state, so
        // a malformed world leaves the last-good registry serving untouched.
        let rebuilt = rebuild_registry(&staged)?;

        // Commit (infallible from here). Store the registry first so a downstream
        // rebuild triggered by the supervisor's post-apply signal reads the new
        // world; advance the publish counter so the downstream view seq moves.
        self.dedicated.store(Arc::new(rebuilt.registry));
        self.publish
            .stamp_rebuild(rebuilt.gateways.into_iter().map(|key| (key, 1, 0)));
        self.resources = staged;
        self.has_full = true;
        Ok(ApplyStats::default())
    }
}

/// The reconstructed downstream world for one namespace apply.
struct RebuiltRegistry {
    registry: HashMap<ObjectKey, Arc<DedicatedRoutingSnapshot>>,
    /// Every Gateway present this rebuild (drives the publish index).
    gateways: Vec<ObjectKey>,
}

/// Partition the de-qualified resource world into per-Gateway snapshots plus the
/// shared endpoint set, then reconstruct one [`DedicatedRoutingSnapshot`] per
/// Gateway (#583). The authoritative Gateway set is the union of every qualifier
/// seen; a Gateway carries its bound proxy SA in its [`p::GatewayMeta`], defaulted
/// to empty (fail-closed — an empty SA matches no SVID) if absent.
fn rebuild_registry(
    resources: &HashMap<String, Arc<p::Resource>>,
) -> Result<RebuiltRegistry, WireError> {
    // Per-Gateway de-qualified routing resources; per-Gateway meta; shared eps.
    let mut per_gateway: HashMap<ObjectKey, Vec<p::Resource>> = HashMap::new();
    let mut meta: HashMap<ObjectKey, p::GatewayMeta> = HashMap::new();
    let mut endpoints: Vec<p::Resource> = Vec::new();

    for resource in resources.values() {
        let qualified =
            !resource.qualifier_namespace.is_empty() && !resource.qualifier_name.is_empty();
        let key = qualified.then(|| {
            ObjectKey::new(
                resource.qualifier_namespace.clone(),
                resource.qualifier_name.clone(),
            )
        });
        match resource.payload.as_ref() {
            Some(p::resource::Payload::GatewayMeta(m)) => {
                let key = key.ok_or(WireError::UnknownResourceKey {
                    reason: "namespace GatewayMeta resource carries no Gateway qualifier",
                })?;
                meta.insert(key, m.clone());
            }
            Some(p::resource::Payload::Endpoints(_)) if key.is_none() => {
                // Shared, unqualified endpoints — resolvable by every Gateway.
                endpoints.push((**resource).clone());
            }
            Some(_) => {
                let key = key.ok_or(WireError::UnknownResourceKey {
                    reason: "namespace routing resource carries no Gateway qualifier",
                })?;
                // De-qualify so it keys and compiles like a `Scope::Gateway`
                // resource in the per-Gateway snapshot below.
                let mut dequalified = (**resource).clone();
                dequalified.qualifier_namespace.clear();
                dequalified.qualifier_name.clear();
                per_gateway.entry(key).or_default().push(dequalified);
            }
            None => {
                return Err(WireError::UnknownResourceKey {
                    reason: "namespace resource carries no payload arm (unknown future variant)",
                });
            }
        }
    }

    // Authoritative Gateway set: every Gateway that emitted any resource. The
    // controller always emits a GatewayMeta per cut-over Gateway, so this is the
    // meta key set in practice; the union stays robust to a routes-only world.
    let mut gateways: Vec<ObjectKey> = meta.keys().chain(per_gateway.keys()).cloned().collect();
    gateways.sort();
    gateways.dedup();

    let mut registry = HashMap::with_capacity(gateways.len());
    for key in &gateways {
        let gateway_resources = per_gateway.get(key).map(Vec::as_slice).unwrap_or(&[]);
        let expected_proxy_sa = meta
            .get(key)
            .map(|m| m.expected_proxy_sa.clone())
            .unwrap_or_default();
        let snapshot =
            dedicated_snapshot_from_resources(gateway_resources, &endpoints, expected_proxy_sa)?;
        registry.insert(key.clone(), Arc::new(snapshot));
    }

    Ok(RebuiltRegistry { registry, gateways })
}

/// Reconstruct one dedicated Gateway's [`DedicatedRoutingSnapshot`] from its
/// de-qualified resources plus the namespace-shared endpoints (#583).
///
/// Reuses the proxy apply pipeline verbatim: a synthetic full snapshot fed
/// through [`RoutingApplier`] compiles exactly the typed tables a
/// `Scope::Gateway` proxy would build, so the relay's downstream materialize
/// re-emits byte-identical resources. A dedicated Gateway serves no Ingress/L4,
/// so those cells stay empty.
///
/// # Errors
///
/// Any [`WireError`] from compiling the world (bad regex, dangling endpoint ref,
/// malformed address, …) — the relay Nacks and retains its last-good registry.
fn dedicated_snapshot_from_resources(
    gateway_resources: &[p::Resource],
    endpoint_resources: &[p::Resource],
    expected_proxy_sa: String,
) -> Result<DedicatedRoutingSnapshot, WireError> {
    let mut all = Vec::with_capacity(gateway_resources.len() + endpoint_resources.len());
    all.extend(gateway_resources.iter().cloned());
    all.extend(endpoint_resources.iter().cloned());

    // The synthetic full must carry the version `apply_message` will recompute
    // from the same per-resource digests, or its self-check would reject it.
    let version = ContentHash::from_per_resource(all.iter().map(resource_hash).collect())
        .as_str()
        .to_owned();
    let synthetic = p::Snapshot {
        version,
        nonce: Vec::new(),
        full: true,
        resources: all,
        removed_resources: Vec::new(),
    };

    let (mut applier, cells) = RoutingApplier::new();
    // Fresh applier ⇒ `expect_full = true`; a first full publishes its cells even
    // when empty, so a routes-less Gateway yields an empty gateway table.
    applier.apply(&synthetic, true)?;

    Ok(DedicatedRoutingSnapshot {
        gateway: cells.gateway.load(),
        tls: cells.tls.load(),
        client_certs: cells.client_certs.load(),
        // `SharedGatewayListenerStatus::load` yields a `Guard<Arc<HashMap>>`;
        // the snapshot holds the owned map, so double-deref then clone.
        listener_status: (**cells.listener_status.load()).clone(),
        expected_proxy_sa,
    })
}

/// Map a resource-key error into the crate's wire error, mirroring the proxy
/// apply path's own conversion so both fail closed on an unkeyable resource.
fn wire_from_key_err(_e: crate::wire::resource::ResourceKeyError) -> WireError {
    WireError::UnknownResourceKey {
        reason: "namespace-view resource could not be canonically keyed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerSvid;
    use crate::materialize::materialize;
    use crate::subscription::Scope;
    use coxswain_core::listener_status::SharedGatewayListenerStatus;
    use coxswain_core::publish_index::SharedGatewayPublishIndex;
    use coxswain_core::routing::{
        BackendGroup, GatewayRoutingTableBuilder, RouteEntry, SharedGatewayRoutingTable,
        SharedIngressRoutingTable, SharedTcpRouteTable, SharedTlsPassthroughTable,
        SharedUdpRouteTable,
    };
    use coxswain_core::tls::{
        ClientCertStore, PortTlsStore, SharedClientCertStore, SharedPortTlsStore,
    };
    use std::collections::HashMap as StdHashMap;

    /// A dedicated Gateway snapshot with one Gateway-table route on `host`,
    /// stamped with a distinct `expected_proxy_sa` derived from `name`.
    fn dedicated_snapshot(name: &str, host: &str) -> DedicatedRoutingSnapshot {
        let bg = Arc::new(BackendGroup::new(
            format!("prod/{name}"),
            vec!["10.0.0.1:80".parse().expect("addr")],
        ));
        let entry = Arc::new(RouteEntry::path_only(bg, format!("prod/{name}"), None));
        let mut b = GatewayRoutingTableBuilder::new();
        b.for_port(443).exact_host(host).add_exact_route("/", entry);
        DedicatedRoutingSnapshot {
            gateway: Arc::new(b.build().expect("build")),
            tls: Arc::new(PortTlsStore::default()),
            client_certs: Arc::new(ClientCertStore::default()),
            listener_status: StdHashMap::new(),
            expected_proxy_sa: format!("{name}-coxswain"),
        }
    }

    /// A source with the given `(namespace, name, host)` dedicated Gateways.
    fn source_with_dedicated(entries: &[(&str, &str, &str)]) -> SnapshotSource {
        let dedicated = DedicatedRoutingRegistry::new();
        let mut map = StdHashMap::new();
        for (ns, name, host) in entries {
            map.insert(
                ObjectKey::new((*ns).to_owned(), (*name).to_owned()),
                Arc::new(dedicated_snapshot(name, host)),
            );
        }
        dedicated.store(Arc::new(map));
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
            publish: SharedGatewayPublishIndex::new(),
        }
    }

    /// Turn a materialized view into the full wire snapshot the controller would
    /// send as the first message of a session.
    fn full_snapshot(view: &crate::materialize::MaterializedView) -> p::Snapshot {
        p::Snapshot {
            version: view.version.clone(),
            nonce: Vec::new(),
            full: true,
            resources: view
                .resources
                .values()
                .map(|entry| (*entry.resource).clone())
                .collect(),
            removed_resources: Vec::new(),
        }
    }

    /// The downstream-serving source a relay exposes after applying `msg` on its
    /// namespace stream.
    fn relay_source_after(msgs: &[p::Snapshot]) -> SnapshotSource {
        let mut demux = NamespaceDemux::new();
        let dedicated = demux.dedicated.clone();
        let publish = demux.publish.clone();
        let mut expect_full = true;
        for msg in msgs {
            demux.apply(msg, expect_full).expect("apply");
            expect_full = false;
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

    fn gw_scope(name: &str) -> Scope {
        Scope::Gateway {
            name: name.to_owned(),
            namespace: "prod".to_owned(),
        }
    }

    /// Round-trip: a leaf served a `Scope::Gateway` world *by the relay* sees a
    /// world byte-identical (version + per-resource hashes) to what the
    /// controller would serve it directly. This is the relay's core invariant.
    #[test]
    fn relay_gateway_world_matches_direct_controller_world() {
        let origin = source_with_dedicated(&[
            ("prod", "gw-a", "a.example.com"),
            ("prod", "gw-b", "b.example.com"),
        ]);
        let ns_view = materialize(
            &origin,
            &Scope::Namespace {
                namespace: "prod".to_owned(),
            },
            None,
        );
        let relay = relay_source_after(&[full_snapshot(&ns_view)]);

        for name in ["gw-a", "gw-b"] {
            let direct = materialize(&origin, &gw_scope(name), None);
            let via_relay = materialize(&relay, &gw_scope(name), None);
            assert_eq!(
                direct.version, via_relay.version,
                "{name}: relay-served version must equal the controller's"
            );
            assert_eq!(
                *direct.resource_hashes, *via_relay.resource_hashes,
                "{name}: relay-served per-resource hashes must match the controller's"
            );
        }
    }

    /// The relay reconstructs each Gateway's bound proxy SA from `GatewayMeta`,
    /// so its downstream `Scope::Gateway` materialize enforces the same SVID
    /// binding the controller does: a non-matching identity gets an empty,
    /// seq-0 world (AC #4, at the materialize layer).
    #[test]
    fn relay_enforces_gateway_svid_binding_from_reconstructed_sa() {
        let origin = source_with_dedicated(&[("prod", "gw-a", "a.example.com")]);
        let ns_view = materialize(
            &origin,
            &Scope::Namespace {
                namespace: "prod".to_owned(),
            },
            None,
        );
        let relay = relay_source_after(&[full_snapshot(&ns_view)]);

        // Matching SVID (`gw-a-coxswain` in ns `prod`) → the real world.
        let matching = PeerSvid {
            uri_sans: vec!["spiffe://cluster.local/ns/prod/sa/gw-a-coxswain".to_owned()],
        };
        let served = materialize(&relay, &gw_scope("gw-a"), Some(&matching));
        assert!(
            !served.resources.is_empty(),
            "matching SVID must be served the Gateway world"
        );

        // Wrong SA → fail closed to an empty, seq-0 world.
        let wrong = PeerSvid {
            uri_sans: vec!["spiffe://cluster.local/ns/prod/sa/someone-else".to_owned()],
        };
        let denied = materialize(&relay, &gw_scope("gw-a"), Some(&wrong));
        assert!(
            denied.resources.is_empty() && denied.seq == 0,
            "non-matching SVID must get an empty seq-0 world"
        );
    }

    /// A delta that adds one Gateway and removes another updates only those
    /// Gateways' registry entries; the surviving Gateway's world is unchanged.
    #[test]
    fn delta_adds_and_removes_gateways() {
        let origin_ab = source_with_dedicated(&[
            ("prod", "gw-a", "a.example.com"),
            ("prod", "gw-b", "b.example.com"),
        ]);
        let full = full_snapshot(&materialize(
            &origin_ab,
            &Scope::Namespace {
                namespace: "prod".to_owned(),
            },
            None,
        ));

        // Target world: gw-a removed, gw-c added; gw-b unchanged.
        let origin_bc = source_with_dedicated(&[
            ("prod", "gw-b", "b.example.com"),
            ("prod", "gw-c", "c.example.com"),
        ]);
        let target_view = materialize(
            &origin_bc,
            &Scope::Namespace {
                namespace: "prod".to_owned(),
            },
            None,
        );

        // Build the delta from full → target by canonical-key diff.
        let full_view = materialize(
            &origin_ab,
            &Scope::Namespace {
                namespace: "prod".to_owned(),
            },
            None,
        );
        let upserts: Vec<p::Resource> = target_view
            .resources
            .iter()
            .filter(|(k, e)| {
                full_view.resource_hashes.get(*k).map(String::as_str) != Some(e.hash.as_str())
            })
            .map(|(_, e)| (*e.resource).clone())
            .collect();
        let removed: Vec<String> = full_view
            .resource_hashes
            .keys()
            .filter(|k| !target_view.resources.contains_key(*k))
            .cloned()
            .collect();
        let delta = p::Snapshot {
            version: target_view.version.clone(),
            nonce: Vec::new(),
            full: false,
            resources: upserts,
            removed_resources: removed,
        };

        let relay = relay_source_after(&[full, delta]);
        let registry = relay.dedicated.load();
        assert!(
            registry
                .get(&ObjectKey::new("prod".to_owned(), "gw-a".to_owned()))
                .is_none(),
            "gw-a must be gone after the delta"
        );
        assert!(
            registry
                .get(&ObjectKey::new("prod".to_owned(), "gw-c".to_owned()))
                .is_some(),
            "gw-c must be present after the delta"
        );
        // gw-b's relay world still matches the controller's direct world.
        let direct_b = materialize(&origin_bc, &gw_scope("gw-b"), None);
        let via_relay_b = materialize(&relay, &gw_scope("gw-b"), None);
        assert_eq!(direct_b.version, via_relay_b.version, "gw-b unchanged");
    }

    /// A delta arriving as the first message of a session is rejected (invariant
    /// 1): the relay has no baseline, so it Nacks for a fresh full.
    #[test]
    fn delta_before_full_is_rejected() {
        let mut demux = NamespaceDemux::new();
        let err = demux
            .apply(
                &p::Snapshot {
                    version: String::new(),
                    nonce: Vec::new(),
                    full: false,
                    resources: Vec::new(),
                    removed_resources: Vec::new(),
                },
                true,
            )
            .expect_err("delta-first must fail");
        assert!(matches!(err, WireError::DeltaBeforeFullSnapshot));
    }

    /// A full whose stamped version disagrees with its resources is rejected
    /// before any registry is committed (self-healing resync).
    #[test]
    fn version_mismatch_is_rejected() {
        let origin = source_with_dedicated(&[("prod", "gw-a", "a.example.com")]);
        let mut full = full_snapshot(&materialize(
            &origin,
            &Scope::Namespace {
                namespace: "prod".to_owned(),
            },
            None,
        ));
        full.version = "deadbeef".to_owned();
        let mut demux = NamespaceDemux::new();
        let err = demux.apply(&full, true).expect_err("bad version must fail");
        assert!(matches!(err, WireError::VersionMismatch { .. }));
        // Nothing was committed.
        assert!(demux.dedicated.load().is_empty(), "registry stays empty");
    }
}
