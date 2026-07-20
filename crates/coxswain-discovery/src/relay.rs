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

use coxswain_core::dedicated_registry::{
    DedicatedRegistryData, DedicatedRoutingRegistry, DedicatedRoutingSnapshot,
};
use coxswain_core::health::SubsystemHandle;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::publish_index::GatewayPublishIndexHandle;
use tokio::sync::watch;

use crate::apply::{ApplyStats, RoutingApplier, SnapshotApplier, wire_from_key_err};
use crate::client::{DiscoveryClientConfig, Supervisor, UpstreamDirectiveHandler};
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
pub struct RelayUpstream {
    /// The downstream-serving snapshot source, populated by the upstream client.
    pub source: SnapshotSource,
    /// The upstream reconnect supervisor — run it as a background service.
    pub supervisor: Supervisor,
    /// Rebuild-generation receiver: bumped after every successful upstream
    /// apply, drives the downstream `DiscoveryService` re-materialization.
    pub rebuild_rx: watch::Receiver<u64>,
    /// Latest-directive cell (#601/#652): the upstream client writes the most
    /// recent controller `PreferredUpstream` here; hand it to the downstream
    /// `DiscoveryService::with_directive_forwarding` so leaves get repointed. A
    /// `watch` (not a `broadcast`) so a leaf that subscribes *after* the directive
    /// was written still reads it on open — the late-subscriber replay that closes
    /// the wedged-GC race. `None` until the first directive.
    pub directive_tx: watch::Sender<Option<p::PreferredUpstream>>,
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
    mut config: DiscoveryClientConfig,
    health: SubsystemHandle,
    health_check: &str,
) -> Result<RelayUpstream, DiscoveryError> {
    // Directive forwarding (#601/#652): the upstream client publishes the latest
    // controller `PreferredUpstream` into this watch cell; the caller wires the
    // sender into the downstream `DiscoveryService` so leaves get repointed — a
    // `watch` (not a `broadcast`) so a leaf subscribing after publication still reads
    // it on open. A relay never repoints its own upstream (it always streams from the
    // controller).
    let (directive_tx, _) = watch::channel::<Option<p::PreferredUpstream>>(None);
    config.upstream_directive_handler = UpstreamDirectiveHandler::Forward(directive_tx.clone());
    // One publish index shared between the applier (writer: advances it to the
    // controller's envelope seq on each apply) and the downstream `SnapshotSource`
    // (reader: stamps that seq onto leaf Acks), so shared leaves Ack in the
    // controller's seq space and the #531 gate can evaluate them (#585).
    let publish = GatewayPublishIndexHandle::new();
    let (applier, cells) = RoutingApplier::new();
    let applier = applier.with_publish_index(publish.clone());
    let (supervisor, rebuild_rx) =
        Supervisor::with_applier(config, health, health_check, Box::new(applier))?;
    let source = SnapshotSource {
        ingress: cells.ingress,
        gateway: cells.gateway,
        tls: cells.tls,
        client_certs: cells.client_certs,
        listener_status: cells.listener_status,
        // A shared relay serves no dedicated Gateways.
        dedicated: DedicatedRoutingRegistry::new(),
        passthrough_routes: cells.passthrough,
        terminate_routes: cells.terminate,
        tcp_routes: cells.tcp,
        udp_routes: cells.udp,
        publish,
    };
    Ok(RelayUpstream {
        source,
        supervisor,
        rebuild_rx,
        directive_tx,
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
    mut config: DiscoveryClientConfig,
    health: SubsystemHandle,
    health_check: &str,
) -> Result<RelayUpstream, DiscoveryError> {
    // Directive forwarding (#601/#652) — see `shared_relay` for the rationale.
    let (directive_tx, _) = watch::channel::<Option<p::PreferredUpstream>>(None);
    config.upstream_directive_handler = UpstreamDirectiveHandler::Forward(directive_tx.clone());
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
        listener_status: coxswain_core::listener_status::GatewayListenerStatusHandle::new(),
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
        directive_tx,
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
    ///
    /// Keys are `Arc<str>` shared with [`Self::resource_hashes`], so a delta's
    /// clone-then-mutate of both maps bumps refcounts instead of deep-copying
    /// every canonical key (#621).
    resources: HashMap<Arc<str>, Arc<p::Resource>>,
    /// Per-key content digests of the committed world (`canonical_key →
    /// resource_hash`), retained so a delta re-hashes only its own upserts rather
    /// than the whole staged world on every message (#621). The version self-check
    /// folds this map order-independently.
    resource_hashes: HashMap<Arc<str>, Arc<str>>,
    /// Downstream-serving registry (shared with the relay's `SnapshotSource`).
    dedicated: DedicatedRoutingRegistry,
    /// Downstream-serving publish index (shared with the `SnapshotSource`). The
    /// relay's own monotone rebuild counter drives the downstream `Gateway`-view
    /// seq; per-Gateway upstream seq propagation across tiers lands with #585.
    publish: GatewayPublishIndexHandle,
}

impl NamespaceDemux {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            resources: HashMap::new(),
            resource_hashes: HashMap::new(),
            dedicated: DedicatedRoutingRegistry::new(),
            publish: GatewayPublishIndexHandle::new(),
        }
    }

    /// Fold `msg` into a fresh de-duplicated resource map **and** its per-key
    /// digest map (full = replace-all; delta = upsert/tombstone onto a clone of
    /// the committed world). Mirrors the proxy apply path's invariants: a delta
    /// before a full is rejected, a key in both a delta's upsert and tombstone
    /// sets is rejected, an unheld tombstone is an idempotent no-op.
    ///
    /// A delta re-hashes only its own upserts; every unchanged key's digest is
    /// carried over from [`Self::resource_hashes`] by refcount bump, so a
    /// one-resource delta never re-hashes the whole namespace world (#621).
    fn stage(&self, msg: &p::Snapshot) -> Result<StagedWorld, WireError> {
        if msg.full {
            let mut resources = HashMap::with_capacity(msg.resources.len());
            let mut hashes = HashMap::with_capacity(msg.resources.len());
            for resource in &msg.resources {
                let key: Arc<str> = Arc::from(canonical_key(resource).map_err(wire_from_key_err)?);
                let hash: Arc<str> = Arc::from(resource_hash(resource));
                if resources
                    .insert(Arc::clone(&key), Arc::new(resource.clone()))
                    .is_some()
                {
                    return Err(WireError::UnknownResourceKey {
                        reason: "namespace full contains a duplicate canonical resource key",
                    });
                }
                hashes.insert(key, hash);
            }
            Ok(StagedWorld { resources, hashes })
        } else {
            // Refcount-only clones (both maps key on the same shared `Arc<str>`).
            let mut resources = self.resources.clone();
            let mut hashes = self.resource_hashes.clone();
            let mut seen = HashSet::new();
            for resource in &msg.resources {
                let key: Arc<str> = Arc::from(canonical_key(resource).map_err(wire_from_key_err)?);
                if !seen.insert(Arc::clone(&key)) {
                    return Err(WireError::UnknownResourceKey {
                        reason: "namespace delta contains a duplicate canonical resource key",
                    });
                }
                // Hash ONLY this upsert; retained keys keep their carried digest.
                let hash: Arc<str> = Arc::from(resource_hash(resource));
                resources.insert(Arc::clone(&key), Arc::new(resource.clone()));
                hashes.insert(key, hash);
            }
            for removed in &msg.removed_resources {
                if seen.contains(removed.as_str()) {
                    return Err(WireError::UnknownResourceKey {
                        reason: "namespace delta key appears in both upsert and tombstone sets",
                    });
                }
                resources.remove(removed.as_str());
                hashes.remove(removed.as_str());
            }
            Ok(StagedWorld { resources, hashes })
        }
    }
}

/// The staged successor of a [`NamespaceDemux`] world: the de-duplicated resource
/// map plus its per-key digest map, committed together on a successful apply.
struct StagedWorld {
    resources: HashMap<Arc<str>, Arc<p::Resource>>,
    hashes: HashMap<Arc<str>, Arc<str>>,
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
        // Folded from the retained + delta digests, never re-hashing unchanged
        // resources (#621).
        let computed = ContentHash::from_per_resource(staged.hashes.values().map(|h| &**h))
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
        let rebuilt = rebuild_registry(&staged.resources)?;

        // Commit (infallible from here). Store the registry FIRST so a downstream
        // rebuild triggered by the supervisor's post-apply signal reads the new
        // world; THEN advance the downstream publish counter to the controller's
        // seq. Ordering is the publication fence (#585): a downstream `Scope::Gateway`
        // build captures `current_seq()` before reading cells, so the counter must
        // only reach `max_publish_seq` after those cells are stored — else a leaf
        // could Ack a fresh seq over a stale world. The counter tracks the max
        // per-Gateway `GatewayMeta.publish_seq`, so a leaf for Gateway G Acks
        // `current_seq() >= stamp_G.seq`, exactly what `gateway_node_acked` checks.
        self.dedicated
            .store(Arc::new(DedicatedRegistryData::from_map(rebuilt.registry)));
        self.publish.advance_to(rebuilt.max_publish_seq);
        self.resources = staged.resources;
        self.resource_hashes = staged.hashes;
        Ok(ApplyStats::default())
    }
}

/// The reconstructed downstream world for one namespace apply.
struct RebuiltRegistry {
    registry: HashMap<ObjectKey, Arc<DedicatedRoutingSnapshot>>,
    /// Max per-Gateway `GatewayMeta.publish_seq` across this rebuild — the
    /// controller sequence the relay advances its downstream publish index to
    /// (#585). 0 when the namespace has no cut-over Gateway (empty world).
    max_publish_seq: u64,
}

/// Partition the de-qualified resource world into per-Gateway snapshots plus the
/// shared endpoint set, then reconstruct one [`DedicatedRoutingSnapshot`] per
/// Gateway (#583). The authoritative Gateway set is the union of every qualifier
/// seen; a Gateway carries its bound proxy SA in its [`p::GatewayMeta`], defaulted
/// to empty (fail-closed — an empty SA matches no SVID) if absent.
fn rebuild_registry(
    resources: &HashMap<Arc<str>, Arc<p::Resource>>,
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

    // The controller sequence to re-stamp downstream: the max publish-seq the
    // controller assigned any Gateway in this namespace view. Global (not
    // per-Gateway) because the downstream `Scope::Gateway` server captures the
    // index's global `current_seq()`; a leaf for Gateway G then Acks
    // `>= stamp_G.seq` since `max >= stamp_G.seq` (#585).
    let max_publish_seq = meta.values().map(|m| m.publish_seq).max().unwrap_or(0);

    Ok(RebuiltRegistry {
        registry,
        max_publish_seq,
    })
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

    // No version stamp: this synthetic full is applied via `apply_trusted`, which
    // skips the F6 self-check (#621). The relay just built this set locally, so
    // re-hashing it to satisfy a check against itself is pure waste — dropping the
    // stamp eliminates that hash and the check's recompute together.
    let synthetic = p::Snapshot {
        version: String::new(),
        nonce: Vec::new(),
        full: true,
        resources: all,
        removed_resources: Vec::new(),
        // Local reconstruction only; this applier has no publish index wired, so
        // the seq is inert (the namespace demux advances the real downstream
        // counter from `GatewayMeta.publish_seq`, not from here).
        publish_seq: 0,
    };

    let (mut applier, cells) = RoutingApplier::new();
    // Fresh applier ⇒ `expect_full = true`; a first full publishes its cells even
    // when empty, so a routes-less Gateway yields an empty gateway table.
    applier.apply_trusted(&synthetic, true)?;

    Ok(DedicatedRoutingSnapshot {
        gateway: cells.gateway.load(),
        tls: cells.tls.load(),
        client_certs: cells.client_certs.load(),
        // `GatewayListenerStatusHandle::load` yields a `Guard<Arc<HashMap>>`;
        // the snapshot holds the owned map, so double-deref then clone.
        listener_status: (**cells.listener_status.load()).clone(),
        expected_proxy_sa,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerSvid;
    use crate::materialize::materialize;
    use crate::subscription::Scope;
    use coxswain_core::listener_status::GatewayListenerStatusHandle;
    use coxswain_core::publish_index::GatewayPublishIndexHandle;
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
        dedicated.store(Arc::new(DedicatedRegistryData::from_map(map)));
        SnapshotSource {
            ingress: SharedIngressRoutingTable::new(),
            gateway: SharedGatewayRoutingTable::new(),
            tls: SharedPortTlsStore::new(),
            client_certs: SharedClientCertStore::new(),
            listener_status: GatewayListenerStatusHandle::new(),
            dedicated,
            passthrough_routes: SharedTlsPassthroughTable::new(),
            terminate_routes: SharedTlsPassthroughTable::new(),
            tcp_routes: SharedTcpRouteTable::new(),
            udp_routes: SharedUdpRouteTable::new(),
            publish: GatewayPublishIndexHandle::new(),
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
            publish_seq: view.seq,
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
            listener_status: GatewayListenerStatusHandle::new(),
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
        );
        let relay = relay_source_after(&[full_snapshot(&ns_view)]);

        for name in ["gw-a", "gw-b"] {
            let direct = materialize(&origin, &gw_scope(name));
            let via_relay = materialize(&relay, &gw_scope(name));
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

    /// The relay reconstructs each Gateway's bound proxy SA from `GatewayMeta`, so
    /// its downstream `Scope::Gateway` serving enforces the same SVID binding the
    /// controller does. Enforcement is the server's post-cache
    /// [`crate::server::gateway_svid_denied`] gate (#427, moved out of the cached
    /// build); this asserts the relay feeds it the correct `expected_proxy_sa` —
    /// a matching identity is allowed, a non-matching one denied — over the relay's
    /// reconstructed registry (AC #4).
    #[test]
    fn relay_reconstructs_sa_so_gateway_svid_gate_binds() {
        let origin = source_with_dedicated(&[("prod", "gw-a", "a.example.com")]);
        let ns_view = materialize(
            &origin,
            &Scope::Namespace {
                namespace: "prod".to_owned(),
            },
        );
        let relay = relay_source_after(&[full_snapshot(&ns_view)]);

        // The reconstructed Gateway world is non-empty, so a denial below is a real
        // withholding, not a vacuously-empty world.
        assert!(
            !materialize(&relay, &gw_scope("gw-a")).resources.is_empty(),
            "relay reconstructs a non-empty gw-a world"
        );

        // Matching SVID (`gw-a-coxswain` in ns `prod`) → allowed.
        let matching = PeerSvid {
            uri_sans: vec!["spiffe://cluster.local/ns/prod/sa/gw-a-coxswain".to_owned()],
        };
        assert!(
            !crate::server::gateway_svid_denied(&relay, "prod", "gw-a", Some(&matching)),
            "matching SVID must be allowed the reconstructed Gateway world"
        );

        // Wrong SA → denied (served an empty seq-0 world by `view_for`).
        let wrong = PeerSvid {
            uri_sans: vec!["spiffe://cluster.local/ns/prod/sa/someone-else".to_owned()],
        };
        assert!(
            crate::server::gateway_svid_denied(&relay, "prod", "gw-a", Some(&wrong)),
            "non-matching SVID must be denied"
        );
    }

    /// #585 seq propagation: the namespace relay advances its downstream publish
    /// index to the max controller `GatewayMeta.publish_seq`, so a downstream
    /// `Scope::Gateway` leaf Acks a seq `>=` that Gateway's controller stamp —
    /// exactly what `gateway_node_acked` checks. Without this the leaf would Ack
    /// the relay's own (incomparable) counter and the #531 gate could never pass.
    #[test]
    fn namespace_relay_advances_downstream_seq_to_max_controller_publish_seq() {
        let origin = source_with_dedicated(&[
            ("prod", "gw-a", "a.example.com"),
            ("prod", "gw-b", "b.example.com"),
        ]);
        // Controller stamps gw-a at seq 1, gw-b at seq 2 (two rebuilds; gw-a's
        // sticky stamp stays at 1 across the second).
        let key_a = ObjectKey::new("prod".to_owned(), "gw-a".to_owned());
        let key_b = ObjectKey::new("prod".to_owned(), "gw-b".to_owned());
        origin.publish.stamp_rebuild([(key_a.clone(), 1, 0)]);
        origin
            .publish
            .stamp_rebuild([(key_a.clone(), 1, 0), (key_b.clone(), 1, 0)]);
        assert_eq!(origin.publish.get(&key_a).map(|s| s.seq), Some(1));
        assert_eq!(origin.publish.get(&key_b).map(|s| s.seq), Some(2));

        let ns_view = materialize(
            &origin,
            &Scope::Namespace {
                namespace: "prod".to_owned(),
            },
        );
        let relay = relay_source_after(&[full_snapshot(&ns_view)]);

        assert_eq!(
            relay.publish.current_seq(),
            2,
            "downstream counter must reach the max controller publish_seq (gw-b @ 2)"
        );
        // A leaf for gw-a (controller stamp 1) captures the downstream seq 2 on
        // its build → Acks 2 >= 1, satisfying the dedicated ack gate.
        assert_eq!(
            materialize(&relay, &gw_scope("gw-a")).seq,
            2,
            "a gw-a leaf Acks a seq >= gw-a's controller stamp"
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
        );

        // Build the delta from full → target by canonical-key diff.
        let full_view = materialize(
            &origin_ab,
            &Scope::Namespace {
                namespace: "prod".to_owned(),
            },
        );
        let upserts: Vec<p::Resource> = target_view
            .resources
            .iter()
            .filter(|(k, e)| full_view.resource_hashes.get(*k) != Some(&e.hash))
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
            publish_seq: target_view.seq,
        };

        let relay = relay_source_after(&[full, delta]);
        let registry = relay.dedicated.load();
        assert!(
            !registry
                .map
                .contains_key(&ObjectKey::new("prod".to_owned(), "gw-a".to_owned())),
            "gw-a must be gone after the delta"
        );
        assert!(
            registry
                .map
                .contains_key(&ObjectKey::new("prod".to_owned(), "gw-c".to_owned())),
            "gw-c must be present after the delta"
        );
        // gw-b's relay world still matches the controller's direct world.
        let direct_b = materialize(&origin_bc, &gw_scope("gw-b"));
        let via_relay_b = materialize(&relay, &gw_scope("gw-b"));
        assert_eq!(direct_b.version, via_relay_b.version, "gw-b unchanged");
    }

    /// #621: a namespace delta carries over every unchanged key's digest by
    /// refcount (pointer-identical `Arc<str>`), re-hashing only its own upserts —
    /// a one-Gateway addition never re-hashes the rest of the namespace world.
    #[test]
    fn namespace_delta_retains_unchanged_digests_by_refcount() {
        let ns_scope = Scope::Namespace {
            namespace: "prod".to_owned(),
        };
        let origin_ab = source_with_dedicated(&[
            ("prod", "gw-a", "a.example.com"),
            ("prod", "gw-b", "b.example.com"),
        ]);

        let mut demux = NamespaceDemux::new();
        demux
            .apply(&full_snapshot(&materialize(&origin_ab, &ns_scope)), true)
            .expect("full");

        // Pre-delta digest allocations, keyed by canonical key.
        let before: StdHashMap<Arc<str>, *const u8> = demux
            .resource_hashes
            .iter()
            .map(|(k, v)| (Arc::clone(k), Arc::as_ptr(v) as *const u8))
            .collect();
        assert!(!before.is_empty(), "the full must have populated digests");

        // Delta: add gw-c only — gw-a and gw-b are untouched (no upserts, no
        // tombstones for their keys).
        let full_view = materialize(&origin_ab, &ns_scope);
        let origin_abc = source_with_dedicated(&[
            ("prod", "gw-a", "a.example.com"),
            ("prod", "gw-b", "b.example.com"),
            ("prod", "gw-c", "c.example.com"),
        ]);
        let target = materialize(&origin_abc, &ns_scope);
        let upserts: Vec<p::Resource> = target
            .resources
            .iter()
            .filter(|(k, e)| full_view.resource_hashes.get(*k) != Some(&e.hash))
            .map(|(_, e)| (*e.resource).clone())
            .collect();
        assert!(
            !upserts.is_empty(),
            "adding gw-c must produce at least one upsert"
        );
        let delta = p::Snapshot {
            version: target.version.clone(),
            nonce: Vec::new(),
            full: false,
            resources: upserts,
            removed_resources: Vec::new(),
            publish_seq: target.seq,
        };
        demux.apply(&delta, false).expect("delta");

        // Every pre-delta key still present keeps its exact digest allocation.
        for (key, ptr) in &before {
            let now = demux
                .resource_hashes
                .get(key)
                .expect("an unchanged key must survive the delta");
            assert_eq!(
                Arc::as_ptr(now) as *const u8,
                *ptr,
                "unchanged key {key} must carry its digest by refcount, not re-hash it"
            );
        }
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
                    publish_seq: 0,
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
        ));
        full.version = "deadbeef".to_owned();
        let mut demux = NamespaceDemux::new();
        let err = demux.apply(&full, true).expect_err("bad version must fail");
        assert!(matches!(err, WireError::VersionMismatch { .. }));
        // Nothing was committed.
        assert!(
            demux.dedicated.load().map.is_empty(),
            "registry stays empty"
        );
    }
}
