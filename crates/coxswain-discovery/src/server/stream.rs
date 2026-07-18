//! The per-stream state machine: one task per connected proxy (#383).
//!
//! [`run_stream`] drives the push-after-Ack delta engine — build the outbound diff
//! against the node's acked baseline ([`build_outbound`]), send one in-flight
//! snapshot, coalesce rebuilds, and fold Acks/Nacks/NodeStatus/RosterReports back
//! into the node registry. The send helpers thread [`StreamClosed`] so a hung-up
//! peer winds the task down cleanly.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{broadcast, mpsc, watch};
use tonic::{Status, Streaming};
use tracing::{debug, warn};

use coxswain_core::node_registry::{NodeRegistryHandle, NodeScope, RosterChild};

use crate::auth::PeerSvid;
use crate::bootstrap_server::{ResolvedUpstream, UpstreamResolverConfig};
use crate::materialize::MaterializedView;
use crate::proto::v1::{self as p, client_message::Kind as CKind, server_message::Kind as SKind};
use crate::subscription::Scope;
use crate::wire::scope_from_wire;

use super::source::SnapshotSource;
use super::view_cache::{SharedViewCache, view_for};

/// Stream-rejection message sent by a non-leader replica (#531).
///
/// The discovery client matches on this text (plus `FAILED_PRECONDITION`) to
/// classify the rejection as an expected fast-retry — `FAILED_PRECONDITION`
/// alone is ambiguous (wire-version mismatch uses the same code). Keep the
/// phrase "not the leader" stable; `client::is_not_leader` depends on it.
pub(crate) const NOT_LEADER_MSG: &str =
    "discovery: this replica is not the leader; redial to reach the leader";

/// The wire-stable substring `client::is_not_leader` matches on. Must appear
/// verbatim in [`NOT_LEADER_MSG`] — enforced by a unit test — and must never
/// change wording: controller and proxy binaries skew across upgrades, so an
/// old proxy classifies a new controller's rejection by this exact phrase.
pub(crate) const NOT_LEADER_NEEDLE: &str = "not the leader";

// ── nonce counter ─────────────────────────────────────────────────────────────

/// Global monotone counter for nonce generation.
///
/// Nonces are not cryptographic; they let the client correlate an Ack/Nack with
/// the specific transmission that triggered it.
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(super) fn next_nonce() -> Vec<u8> {
    NONCE_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .to_be_bytes()
        .to_vec()
}

// ── snapshot construction ─────────────────────────────────────────────────────

/// The world a node last confirmed (or is about to), retained per stream as the
/// delta baseline. Replaces the v1 full-blob retention: a diff only needs the
/// key → hash map, never the resource bytes (those stay behind the view's `Arc`s).
pub(super) struct PendingWorld {
    /// Global content hash of this world (echoed by the node's Ack).
    version: String,
    /// Canonical-key → per-resource-hash map — the diff baseline. Shared with the
    /// view behind an `Arc`, so retaining it per stream is a cheap clone.
    resources: Arc<BTreeMap<String, Arc<str>>>,
    /// Publish sequence captured before the cells were read (never on the wire);
    /// recorded into the node registry when this world is Ack'd (#531).
    seq: u64,
}

/// An outbound snapshot ready to send: the wire message (nonce already stamped)
/// paired with the post-apply world the client will hold once it Acks.
pub(super) struct Outbound {
    /// The wire message — `full = true` for a full, `false` for a delta.
    message: p::Snapshot,
    /// The world this message brings the client to; retained as `pending`.
    world: PendingWorld,
}

/// Diff `view` against a node's acked baseline into the message to send next.
///
/// - `acked == None` ⇒ a **full**: every resource in canonical-key order,
///   `full = true`, no tombstones. Used for the first message of a session.
/// - `acked == Some(base)` ⇒ a **delta**: upserts are the view resources whose
///   key is absent from `base` or whose hash moved; tombstones are the `base`
///   keys absent from the view. Both lists are canonical-key sorted (the view and
///   `base` are `BTreeMap`s), and the two key sets are disjoint by construction.
///   An **empty** delta (no upserts, no tombstones — the world equals the
///   baseline, so `view.version` necessarily equals the acked version) returns
///   `None`: nothing is sent, and the caller advances the node's convergence
///   stamp instead of pushing.
///
/// In every case the message `version` is `view.version` — the global hash of the
/// POST-APPLY world (never the delta payload's own hash), so the client's
/// per-resource version self-check reproduces it exactly.
pub(super) fn build_outbound(
    view: &MaterializedView,
    acked: Option<&BTreeMap<String, Arc<str>>>,
) -> Option<Outbound> {
    // The post-apply world a client reaches once it Acks this message. Built ONLY
    // on a send path (never on the empty-delta no-op below), and cheap regardless:
    // the hash map is shared with the view behind an `Arc`, so this is an `Arc`
    // clone plus the version string, not a copy of the whole key→hash map.
    let world = || PendingWorld {
        version: view.version.clone(),
        resources: Arc::clone(&view.resource_hashes),
        seq: view.seq,
    };
    match acked {
        // First message of a session: the whole world as a full.
        None => {
            let resources = view
                .resources
                .values()
                .map(|entry| (*entry.resource).clone())
                .collect();
            Some(Outbound {
                message: p::Snapshot {
                    version: view.version.clone(),
                    nonce: next_nonce(),
                    full: true,
                    resources,
                    removed_resources: Vec::new(),
                    // Envelope seq (#585): a relay re-stamps its downstream index
                    // from this; direct proxies ignore it (their `acked_seq` is
                    // set server-side from the pre-build capture). Not hashed.
                    publish_seq: view.seq,
                },
                world: world(),
            })
        }
        // Steady state: diff the view against what the node last confirmed.
        Some(base) => {
            // Upserts: new keys or keys whose per-resource hash moved. BTreeMap
            // iteration is canonical-key order, so the wire list is sorted.
            let resources: Vec<p::Resource> = view
                .resources
                .iter()
                .filter(|(key, entry)| base.get(*key) != Some(&entry.hash))
                .map(|(_, entry)| (*entry.resource).clone())
                .collect();
            // Tombstones: baseline keys the view no longer carries. `base` is a
            // BTreeMap, so this is already canonical-key sorted.
            let removed_resources: Vec<String> = base
                .keys()
                .filter(|key| !view.resources.contains_key(*key))
                .cloned()
                .collect();
            // Empty delta: the world matches the baseline. Do not send — the
            // caller advances the convergence stamp (quiet-cluster #531 liveness).
            if resources.is_empty() && removed_resources.is_empty() {
                return None;
            }
            Some(Outbound {
                message: p::Snapshot {
                    version: view.version.clone(),
                    nonce: next_nonce(),
                    full: false,
                    resources,
                    removed_resources,
                    // Envelope seq (#585) — carried on deltas too, so a relay's
                    // downstream counter tracks the controller across steady-state
                    // pushes, not just fulls.
                    publish_seq: view.seq,
                },
                world: world(),
            })
        }
    }
}

/// Read the first `ClientMessage` from the stream and unwrap the `Subscribe`.
///
/// # Errors
///
/// Returns a tonic `Status` if the stream closes before a message arrives,
/// if the transport errors, or if the first message is not a `Subscribe`.
pub(super) async fn read_subscribe(
    inbound: &mut Streaming<p::ClientMessage>,
) -> Result<p::Subscribe, Status> {
    match inbound.message().await {
        Ok(Some(msg)) => match msg.kind {
            Some(CKind::Subscribe(s)) => Ok(s),
            _ => Err(Status::invalid_argument(
                "discovery: first client message must be Subscribe",
            )),
        },
        Ok(None) => Err(Status::cancelled(
            "discovery: stream closed before Subscribe",
        )),
        Err(e) => Err(Status::internal(format!(
            "discovery: stream error reading Subscribe: {e}"
        ))),
    }
}

// ── per-stream state machine ──────────────────────────────────────────────────

/// The outbound stream channel closed: the peer hung up or the send task exited.
///
/// A typed marker (`err-custom-type`) for the one failure every send helper on the
/// per-stream path can hit. It replaces a bare `Result<_, ()>`, whose unit error
/// erases *why* the send failed; the closure is always the same event — the
/// `ReceiverStream` feeding tonic was dropped — so it carries no payload and the
/// caller uniformly winds the stream down.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamClosed;

/// Immutable per-stream subscriber identity, grouped so function signatures
/// stay under the 7-argument threshold.
///
/// Groups the three fields that together describe WHO is subscribing and with
/// what credential: the node identifier, the requested scope, and the peer SVID
/// extracted from the mTLS client certificate (absent on plaintext connections).
pub(super) struct StreamSubscription {
    /// Unique identifier for this proxy node.
    pub(super) node_id: String,
    /// Subscription scope (SharedPool or a specific Gateway).
    pub(super) scope: Scope,
    /// URI SANs from the peer's mTLS client certificate; absent on plaintext
    /// connections (test/degraded mode).  Used to bind `Scope::Gateway` claims
    /// to the authenticated SVID identity on every snapshot build.
    pub(super) peer_svid: Option<PeerSvid>,
}

/// Mutable per-stream flow-control state, grouped to keep helper function
/// signatures under the 7-argument threshold.
pub(super) struct StreamState {
    /// The canonical-key → resource-hash world the node last Ack'd — the delta
    /// baseline. `None` until the first Ack, which is exactly when the next
    /// outbound must be a full: on connect (no baseline yet) and on any defensive
    /// path that clears it. Every delta is diffed against this map.
    acked_resources: Option<Arc<BTreeMap<String, Arc<str>>>>,
    /// Version hash of the snapshot currently awaiting an Ack from the client;
    /// `None` when no snapshot is in-flight (safe to push the next one).
    in_flight: Option<String>,
    /// The world currently in-flight, retained until its Ack promotes it into
    /// [`Self::acked_resources`]. Replaces the v1 full-blob retention: a Nack no
    /// longer retransmits it (it triggers a fresh full resync instead), so only
    /// the diff baseline is kept, never the resource bytes. `Some` iff a snapshot
    /// is in flight.
    pending: Option<PendingWorld>,
    /// When the in-flight snapshot was transmitted (#513 ack-latency stage). A
    /// Nack-driven full resync of the SAME version keeps this original send time
    /// (the snapshot took a Nack round trip before converging — its true
    /// end-to-end latency spans both legs); a resync at a DIFFERENT version is a
    /// new snapshot and refreshes it.
    sent_at: Option<Instant>,
}

/// Shared per-stream service handles, cloned from [`DiscoveryService`](crate::DiscoveryService) into the
/// stream task and passed to the Ack / Nack / rebuild handlers by reference.
/// Grouped so those handlers stay under the 7-argument workspace limit.
pub(super) struct StreamServices {
    pub(super) source: SnapshotSource,
    pub(super) registry: NodeRegistryHandle,
    pub(super) rebuild_rx: watch::Receiver<u64>,
    pub(super) shared_view: SharedViewCache,
    pub(super) leader_rx: Option<watch::Receiver<bool>>,
    /// Best-upstream resolver for live repoint directives (#601); `None` disables
    /// the push (unit tests / non-leaf-fronting roles).
    pub(super) upstream_resolver: Option<Arc<UpstreamResolverConfig>>,
    /// Relay-provisioning change signal (#601); `None` when directives are off.
    pub(super) relay_changed_rx: Option<watch::Receiver<u64>>,
    /// Relay directive-forwarding fan-out (#601); `Some` only on a relay's
    /// downstream server. Each stream subscribes a receiver from it.
    pub(super) directive_tx: Option<broadcast::Sender<p::PreferredUpstream>>,
}

/// Immutable references the outbound handlers need, borrowed from the stream
/// task's owned locals. Grouped to keep [`handle_ack`] / [`handle_nack`] under the
/// 7-argument limit. Deliberately excludes the mutable `rebuild_rx`/`leader_rx`
/// watches (owned as `mut` locals in [`run_stream`]); the current generation is
/// read at the select-arm call site and passed as a scalar.
pub(super) struct StreamCtx<'a> {
    sub: &'a StreamSubscription,
    source: &'a SnapshotSource,
    registry: &'a NodeRegistryHandle,
    shared_view: &'a SharedViewCache,
    tx: &'a mpsc::Sender<Result<p::ServerMessage, Status>>,
}

/// Map a discovery [`Scope`] to the core-local [`NodeScope`] mirror.
///
/// `coxswain-admin` consumes [`NodeScope`] without importing `coxswain-discovery`,
/// so the conversion lives here at the crate boundary.
pub(super) fn node_scope_from(scope: &Scope) -> NodeScope {
    match scope {
        Scope::SharedPool => NodeScope::SharedPool,
        Scope::Gateway { name, namespace } => NodeScope::Gateway {
            namespace: namespace.clone(),
            name: name.clone(),
        },
        Scope::Namespace { namespace } => NodeScope::Namespace {
            namespace: namespace.clone(),
        },
    }
}

/// Drive the push-after-Ack state machine for one connected proxy node.
///
/// Exits when the client disconnects, the outbound channel closes, or a stream
/// error is received. Calls [`NodeRegistryHandle::disconnect`] unconditionally
/// on exit so the registry stays consistent.
pub(super) async fn run_stream(
    sub: StreamSubscription,
    services: StreamServices,
    mut inbound: Streaming<p::ClientMessage>,
    tx: mpsc::Sender<Result<p::ServerMessage, Status>>,
) {
    // Destructure so the mutable watches stay as `mut` locals (they are polled in
    // the select loop) while the rest is borrowed immutably by `ctx`.
    let StreamServices {
        source,
        registry,
        mut rebuild_rx,
        shared_view,
        mut leader_rx,
        upstream_resolver,
        mut relay_changed_rx,
        directive_tx,
    } = services;
    // Relay directive-forwarding (#601): a relay's downstream leaf subscribes to
    // the fan-out its upstream client feeds, and forwards directives targeting
    // this leaf's Gateway. `None` on the controller (it originates, never forwards).
    let mut directive_rx = directive_tx.as_ref().map(broadcast::Sender::subscribe);
    let ctx = StreamCtx {
        sub: &sub,
        source: &source,
        registry: &registry,
        shared_view: &shared_view,
        tx: &tx,
    };

    let mut state = StreamState {
        acked_resources: None,
        in_flight: None,
        pending: None,
        sent_at: None,
    };

    // Live upstream-repoint baseline (#601): the last [`ResolvedUpstream`] this
    // stream was told to use. Seeded on stream open — the client just bootstrapped
    // to this upstream — then a `PreferredUpstream` is pushed only when it changes
    // (a relay is provisioned or torn down).
    let mut last_upstream: Option<ResolvedUpstream> = None;
    // Seed the baseline on open. This does send a `PreferredUpstream` when the
    // leaf's best upstream already diverges from its bootstrap seed (e.g. a relay
    // came Ready between bootstrap and stream open); a closed channel returns
    // `Err(StreamClosed)`, which the shutdown path handles, so it is ignored here.
    let _ = seed_or_push_upstream(
        &sub.scope,
        sub.peer_svid.as_ref(),
        upstream_resolver.as_ref(),
        &mut last_upstream,
        &tx,
    )
    .await;

    // Send the initial snapshot immediately on stream open. With no baseline yet
    // (`acked_resources == None`) this is always a full; `build_outbound`
    // therefore always yields `Some`, so the initial send never no-ops.
    let generation = *rebuild_rx.borrow();
    let view = view_for(
        &shared_view,
        &source,
        &sub.scope,
        sub.peer_svid.as_ref(),
        generation,
    );
    registry.record_target(&sub.node_id, view.version.clone());
    match push_if_changed(&ctx, &view, &mut state).await {
        Ok(_) => {}
        Err(StreamClosed) => {
            registry.disconnect(&sub.node_id);
            // If this stream was a relay, evict its folded leaf subtree so the
            // #531 gate fails closed on the now-invisible leaves (#585). No-op
            // for a non-relay node (no children tagged with its id).
            registry.evict_children(&sub.node_id);
            crate::metrics::connected_proxies().dec();
            return;
        }
    }

    loop {
        tokio::select! {
            // Inbound message from the proxy client.
            result = inbound.message() => {
                match result {
                    Ok(Some(client_msg)) => {
                        match client_msg.kind {
                            Some(CKind::Ack(ack)) => {
                                let generation = *rebuild_rx.borrow();
                                if handle_ack(&ctx, ack, &mut state, generation).await.is_err() {
                                    break;
                                }
                            }
                            Some(CKind::Nack(nack)) => {
                                let generation = *rebuild_rx.borrow();
                                if handle_nack(&ctx, &nack, &mut state, generation).await.is_err() {
                                    break;
                                }
                            }
                            Some(CKind::NodeStatus(ns)) => {
                                record_node_status(&sub.node_id, &ns, &registry);
                            }
                            Some(CKind::RosterReport(rr)) => {
                                record_roster_report(&sub.node_id, rr, &registry);
                            }
                            Some(CKind::Subscribe(_)) => {
                                // Duplicate Subscribe mid-stream; ignore (idempotent).
                                debug!(node_id = %sub.node_id, "discovery: duplicate Subscribe ignored");
                            }
                            None => {
                                debug!(
                                    node_id = %sub.node_id,
                                    "discovery: unrecognised ClientMessage kind, ignoring"
                                );
                            }
                        }
                    }
                    Ok(None) => {
                        debug!(node_id = %sub.node_id, "discovery: client disconnected (stream closed)");
                        break;
                    }
                    Err(e) => {
                        warn!(node_id = %sub.node_id, error = %e, "discovery: stream error from client");
                        break;
                    }
                }
            }

            // Leadership lost (#531) — terminate the stream so the proxy
            // redials and its readiness reports land on the new leader, not in
            // this demoted replica's registry.
            () = watch_demotion(&mut leader_rx) => {
                debug!(node_id = %sub.node_id, "discovery: leadership lost; terminating stream");
                let _ = tx
                    .send(Err(Status::failed_precondition(NOT_LEADER_MSG)))
                    .await;
                break;
            }

            // Routing world was rebuilt — check for a new delta to push.
            _ = rebuild_rx.changed() => {
                if state.in_flight.is_some() {
                    // A snapshot is already awaiting Ack; coalesce this rebuild.
                    // After its Ack promotes the baseline, `handle_ack` reads the
                    // current world once and sends a single delta spanning
                    // baseline → latest.
                    debug!(node_id = %sub.node_id, "discovery: rebuild while in-flight, coalescing");
                    continue;
                }
                let generation = *rebuild_rx.borrow();
                let view = view_for(&shared_view, &source, &sub.scope, sub.peer_svid.as_ref(), generation);
                registry.record_target(&sub.node_id, view.version.clone());
                match push_if_changed(&ctx, &view, &mut state).await {
                    Ok(true) => {}
                    Ok(false) => {
                        // No change vs the node's acked baseline: advance its
                        // convergence stamp to the freshly-captured sequence so
                        // the #531 ack gate converges without a content change.
                        debug!(
                            node_id = %sub.node_id,
                            "discovery: rebuild produced no change vs baseline — no push needed"
                        );
                        registry.advance_acked_seq(&sub.node_id, view.seq);
                    }
                    Err(StreamClosed) => break,
                }
            }

            // Relay provisioning changed (#601) — repoint this leaf if its
            // namespace's best upstream moved (relay provisioned or torn down).
            // Inert (`pending`) when directives are disabled (no receiver wired).
            changed = wait_relay_changed(&mut relay_changed_rx) => {
                if changed.is_err() {
                    // Sender dropped (controller shutting down): stop watching.
                    relay_changed_rx = None;
                    continue;
                }
                if seed_or_push_upstream(
                    &sub.scope,
                    sub.peer_svid.as_ref(),
                    upstream_resolver.as_ref(),
                    &mut last_upstream,
                    &tx,
                )
                .await
                .is_err()
                {
                    break;
                }
            }

            // Relay directive-forwarding (#601): the upstream client fanned a
            // controller directive here — forward it to this leaf if it targets
            // this leaf's Gateway. Inert (`pending`) when not a relay.
            directive = recv_directive(&mut directive_rx) => {
                match directive {
                    Ok(directive) if directive_targets_leaf(&directive, &sub.scope) => {
                        debug!(
                            node_id = %sub.node_id,
                            endpoint = %directive.endpoint,
                            "discovery: relay forwarding PreferredUpstream to leaf"
                        );
                        if tx
                            .send(Ok(p::ServerMessage {
                                kind: Some(SKind::PreferredUpstream(directive)),
                            }))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    // Directive for a different Gateway, or the fan-out lagged
                    // (dropped messages): ignore. A dropped forward is not stuck —
                    // the only live forward case is a relay teardown, which also
                    // drops this leaf's stream, so the leaf reconnects and (via the
                    // re-bootstrap fallback) converges onto the controller anyway.
                    // A fresh controller-originated directive re-drives the rest.
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => {
                        directive_rx = None;
                    }
                }
            }
        }
    }

    registry.disconnect(&sub.node_id);
    // Relay subtree eviction on stream exit (#585); no-op for a non-relay node.
    registry.evict_children(&sub.node_id);
    crate::metrics::connected_proxies().dec();
}

/// Await a relay-provisioning change on an optional watch (#601), standing in a
/// never-resolving future when directives are disabled so it can share `select!`.
pub(super) async fn wait_relay_changed(
    rx: &mut Option<watch::Receiver<u64>>,
) -> Result<(), watch::error::RecvError> {
    match rx.as_mut() {
        Some(r) => r.changed().await,
        None => std::future::pending().await,
    }
}

/// Await a forwarded directive on an optional broadcast receiver (#601), standing
/// in a never-resolving future when this stream is not a relay leaf.
pub(super) async fn recv_directive(
    rx: &mut Option<broadcast::Receiver<p::PreferredUpstream>>,
) -> Result<p::PreferredUpstream, broadcast::error::RecvError> {
    match rx.as_mut() {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Whether a relay-forwarded directive targets the leaf on this stream (#601).
///
/// The controller tags a directive it pushes on a relay's Namespace stream with
/// the target `namespace` (and optionally a specific Gateway `name`); the relay
/// forwards it to every leaf whose Gateway scope matches. An empty `target_name`
/// matches every Gateway in the namespace.
///
/// A `SharedPool` leaf downstream of a **shared** relay always matches (#605): a
/// shared relay serves only shared-pool leaves, so every directive the controller
/// pushes on its upstream targets them — the `target_namespace`/`target_name`
/// fields carry no namespace to match and are left empty. A `Namespace` leaf is
/// never itself a forward target (a relay is never a leaf).
pub(super) fn directive_targets_leaf(directive: &p::PreferredUpstream, scope: &Scope) -> bool {
    match scope {
        Scope::Gateway { namespace, name } => {
            directive.target_namespace == *namespace
                && (directive.target_name.is_empty() || directive.target_name == *name)
        }
        Scope::SharedPool => true,
        Scope::Namespace { .. } => false,
    }
}

/// Seed or push this stream's live upstream-repoint directive (#601).
///
/// `last` tracks the upstream this stream's client(s) currently use. On the FIRST
/// call (`last` is `None`) it seeds that baseline from **where the client is
/// connected right now**, not from the desired best-upstream — a Gateway-scope
/// client whose stream is served here is, by definition, streaming from the
/// controller (it may have bootstrapped to the controller *before* its namespace
/// gained a relay), while a Namespace-scope relay's leaves stream from the relay.
/// Then, on the seed call and every later relay-provisioning tick, it sends a
/// `PreferredUpstream` whenever the desired best-upstream diverges from `last`
/// (a relay was provisioned, or torn down). Seeding from the connected upstream
/// — rather than the desired one — is what makes a fresh proxy that landed on the
/// controller get repointed onto a relay provisioned in the same reconcile.
///
/// A resolver-less service is a no-op.
///
/// The seed baseline and the target are computed per scope as a `(seed, target,
/// forward_target)` triple, then the shared push logic runs:
/// - `Gateway` (dedicated leaf streaming directly from the controller): seed from
///   the controller; target its namespace's best upstream; untargeted directive —
///   the leaf is the sole recipient.
/// - `Namespace` (a dedicated relay's aggregate stream): seed and target from the
///   namespace's best upstream; the directive carries `target_namespace` so the
///   relay forwards it to its downstream leaves in that namespace.
/// - `SharedPool` (#605): the shared relay (peer SA == `shared_relay_sa`) seeds
///   from the shared best upstream and forwards to its downstream shared-pool
///   leaves on change; a direct shared proxy seeds from the controller and
///   repoints itself. Both target the shared best upstream; the directive is
///   untargeted (a shared relay serves only shared-pool leaves, so
///   `directive_targets_leaf` matches them without a namespace).
///
/// Returns `Err(StreamClosed)` if the outbound channel closed.
pub(super) async fn seed_or_push_upstream(
    scope: &Scope,
    peer_svid: Option<&crate::auth::PeerSvid>,
    resolver: Option<&Arc<UpstreamResolverConfig>>,
    last: &mut Option<ResolvedUpstream>,
    tx: &mpsc::Sender<Result<p::ServerMessage, Status>>,
) -> Result<(), StreamClosed> {
    let Some(resolver) = resolver else {
        return Ok(());
    };
    // Seed from the CURRENTLY-CONNECTED upstream, not the desired one: a leaf
    // streaming here is on the controller (Gateway / direct shared proxy), a relay's
    // leaves are behind the relay (Namespace / shared relay). The `forward_target`
    // is only meaningful for a relay's own stream (empty for SharedPool — a shared
    // relay's leaves match regardless).
    let (seed, target, forward_target) = match scope {
        Scope::Gateway { namespace, .. } => (
            resolver.controller_target(),
            resolver.resolve_namespace(namespace),
            String::new(),
        ),
        Scope::Namespace { namespace } => (
            resolver.resolve_namespace(namespace),
            resolver.resolve_namespace(namespace),
            namespace.clone(),
        ),
        Scope::SharedPool => {
            let seed = if resolver.is_shared_relay(peer_svid) {
                resolver.resolve_shared()
            } else {
                resolver.controller_target()
            };
            (seed, resolver.resolve_shared(), String::new())
        }
    };
    if last.is_none() {
        *last = Some(seed);
    }
    if last.as_ref() == Some(&target) {
        return Ok(());
    }
    *last = Some(target.clone());
    let ResolvedUpstream {
        endpoint,
        expected_sa: expected_server_sa,
    } = target;
    debug!(
        %endpoint,
        %expected_server_sa,
        forward_namespace = %forward_target,
        "discovery: pushing PreferredUpstream directive (relay provisioning changed)"
    );
    let directive = p::PreferredUpstream {
        endpoint,
        expected_server_sa,
        target_namespace: forward_target,
        target_name: String::new(),
    };
    tx.send(Ok(p::ServerMessage {
        kind: Some(SKind::PreferredUpstream(directive)),
    }))
    .await
    .map_err(|_| StreamClosed)
}

/// Build the outbound message for `view` against the stream's acked baseline and,
/// if it is non-empty, send it and record it as the new in-flight/pending world.
///
/// Returns:
/// - `Ok(true)`  — a message was sent; `in_flight`/`pending`/`sent_at` updated.
/// - `Ok(false)` — an empty delta (the world equals the baseline); nothing sent,
///   caller advances the node's convergence stamp.
/// - `Err(StreamClosed)`   — the outbound channel closed.
///
/// A full (baseline `None`) is never empty, so the initial send always returns
/// `Ok(true)`.
pub(super) async fn push_if_changed(
    ctx: &StreamCtx<'_>,
    view: &MaterializedView,
    state: &mut StreamState,
) -> Result<bool, StreamClosed> {
    let Some(Outbound { message, world }) = build_outbound(view, state.acked_resources.as_deref())
    else {
        return Ok(false);
    };
    state.in_flight = Some(world.version.clone());
    state.pending = Some(world);
    state.sent_at = Some(Instant::now());
    send_outbound(ctx.tx, message).await?;
    Ok(true)
}

/// Handle an `Ack` from the client.
///
/// An Ack that matches the in-flight world (`pending.version`) is honest: it
/// promotes that world into the delta baseline ([`StreamState::acked_resources`]),
/// records its publish sequence (#531), observes the #513 ack latency, and clears
/// `in_flight`. Then — the world may have moved on while the Ack was in flight
/// (coalesced rebuilds) — the current world is re-materialized and a single delta
/// spanning baseline → latest is sent (or the convergence stamp advanced if the
/// world matches the baseline).
///
/// A stale / duplicate Ack (no in-flight world, or a version mismatch) does NOT
/// promote the baseline and does NOT clear `in_flight` — the honest Ack for the
/// still-in-flight world is yet to come. It records sequence 0 (a no-op under the
/// registry's monotone max) so the registry stays consistent with the v1 filter.
///
/// Returns `Err(StreamClosed)` if the outbound channel is closed.
pub(super) async fn handle_ack(
    ctx: &StreamCtx<'_>,
    ack: p::Ack,
    state: &mut StreamState,
    generation: u64,
) -> Result<(), StreamClosed> {
    debug!(node_id = %ctx.sub.node_id, version = %ack.version, "discovery: Ack received");

    // Promote only an Ack matching the in-flight world. The nested `take()` is
    // guarded by the same predicate, so the `Some` arm always fires when honest;
    // a `None` there would leave `acked_seq` at 0 without panicking.
    let mut acked_seq = 0;
    let honest = state
        .pending
        .as_ref()
        .is_some_and(|p| p.version == ack.version);
    if honest {
        // #513 ack-latency stage: observed only for the honest Ack — a stale one
        // carries no send timestamp to measure against.
        if let Some(sent_at) = state.sent_at {
            crate::metrics::ack_latency_seconds().observe(sent_at.elapsed().as_secs_f64());
        }
        if let Some(pending) = state.pending.take() {
            acked_seq = pending.seq;
            state.acked_resources = Some(pending.resources);
            state.in_flight = None;
            state.sent_at = None;
        }
    }
    ctx.registry
        .record_ack(&ctx.sub.node_id, ack.version, acked_seq, SystemTime::now());
    crate::metrics::acks_total().inc();

    // Re-check the current world only once nothing is in flight. A stale Ack that
    // did not clear `in_flight` skips this — the world genuinely in flight must
    // Ack before the next push (one in-flight invariant).
    if state.in_flight.is_none() {
        let view = view_for(
            ctx.shared_view,
            ctx.source,
            &ctx.sub.scope,
            ctx.sub.peer_svid.as_ref(),
            generation,
        );
        ctx.registry
            .record_target(&ctx.sub.node_id, view.version.clone());
        match push_if_changed(ctx, &view, state).await {
            Ok(true) => {}
            Ok(false) => {
                // World matches the baseline: advance the convergence stamp
                // without a push (#531 ack-gate liveness on a quiet cluster).
                ctx.registry.advance_acked_seq(&ctx.sub.node_id, view.seq);
            }
            Err(StreamClosed) => return Err(StreamClosed),
        }
    }
    Ok(())
}

/// Handle a `Nack` from the client → **full resync**.
///
/// A Nack means the client rejected the last message and its baseline is now
/// untrustworthy, so the server re-materializes the current world and sends it as
/// a fresh `full = true` snapshot (new version + nonce). That full becomes the new
/// in-flight/pending world; the per-stream payload retention is gone, so there is
/// nothing to "retransmit" — the client self-heals from the full.
///
/// The #513 ack-latency send timestamp is refreshed only when the resync's version
/// differs from the Nack'd one: a converged-but-transiently-Nack'd snapshot keeps
/// its original send time so the eventual Ack measures the true end-to-end
/// latency across both legs, not just the retry.
///
/// Returns `Err(StreamClosed)` if the outbound channel is closed.
pub(super) async fn handle_nack(
    ctx: &StreamCtx<'_>,
    nack: &p::Nack,
    state: &mut StreamState,
    generation: u64,
) -> Result<(), StreamClosed> {
    warn!(
        node_id = %ctx.sub.node_id,
        version = %nack.version,
        detail = %nack.detail,
        "discovery: Nack received; sending full resync of the current world",
    );
    let view = view_for(
        ctx.shared_view,
        ctx.source,
        &ctx.sub.scope,
        ctx.sub.peer_svid.as_ref(),
        generation,
    );
    ctx.registry
        .record_target(&ctx.sub.node_id, view.version.clone());
    // Force a full (ignore the acked baseline — it is untrustworthy after a Nack).
    // `build_outbound(_, None)` is always a full, hence never `None`; the else arm
    // degrades to a no-op rather than panicking on the impossible case.
    let Some(Outbound { message, world }) = build_outbound(&view, None) else {
        return Ok(());
    };
    // Preserve #513 latency semantics: keep the original send time when the
    // resync carries the same version the client Nack'd, refresh it otherwise.
    if world.version != nack.version {
        state.sent_at = Some(Instant::now());
    } else if state.sent_at.is_none() {
        // Same version but no prior timestamp (e.g. a Nack with no in-flight
        // send): stamp now so the eventual Ack still observes a latency.
        state.sent_at = Some(Instant::now());
    }
    state.in_flight = Some(world.version.clone());
    state.pending = Some(world);
    send_outbound(ctx.tx, message).await
}

/// Resolve when the watched leadership value is (or becomes) `false` (#531).
///
/// Pends forever when ungated (`None`). A dropped sender means the controller
/// lease loop is gone (process shutdown) — treated as demotion so streams
/// close promptly rather than lingering on a dying replica.
pub(super) async fn watch_demotion(rx: &mut Option<watch::Receiver<bool>>) {
    let Some(rx) = rx else {
        return std::future::pending().await;
    };
    loop {
        if !*rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Record a `NodeStatus` bound-port report into the registry (#531).
///
/// Wire carries `u32`; values outside the `u16` port domain are dropped with a
/// debug log rather than rejecting the whole report — a hostile or buggy client
/// must not be able to wedge its own row, and dropping oversized values fails
/// closed (the port reads as not-bound).
pub(super) fn record_node_status(
    node_id: &str,
    status: &p::NodeStatus,
    registry: &NodeRegistryHandle,
) {
    let mut ports = std::collections::BTreeSet::new();
    for raw in &status.bound_ports {
        match u16::try_from(*raw) {
            Ok(port) => {
                ports.insert(port);
            }
            Err(_) => {
                debug!(
                    node_id,
                    raw, "discovery: NodeStatus port out of u16 range, dropped"
                );
            }
        }
    }
    registry.record_bound_ports(node_id, ports);
}

/// Decode Unix seconds (a wire `int64` from a relay's `RosterReport`) into a
/// [`SystemTime`], fail-safe on both ends: a negative value clamps to the epoch,
/// and an overflowing add saturates to the epoch rather than panicking. The
/// value is display-only (topology panel), never a gate input, and this decodes
/// peer bytes — so it must not be a crash site under any relay input.
pub(super) fn unix_secs_to_system_time(secs: i64) -> SystemTime {
    let offset = Duration::from_secs(u64::try_from(secs).unwrap_or(0));
    SystemTime::UNIX_EPOCH
        .checked_add(offset)
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// Fold a relay's `RosterReport` into the registry (#585).
///
/// Each `RosterEntry` is decoded into a [`RosterChild`] and handed to
/// [`NodeRegistryHandle::apply_roster`], which wholesale-replaces this relay's
/// subtree and marks it `is_relay`. An entry with a missing/undecodable scope or
/// out-of-`u16` port is dropped (fail-closed: that leaf simply won't appear this
/// round; the relay re-reports), never wedging the whole report. An empty report
/// legitimately evicts the relay's subtree (the relay has no leaves).
pub(super) fn record_roster_report(
    parent_node_id: &str,
    report: p::RosterReport,
    registry: &NodeRegistryHandle,
) {
    let mut children = Vec::with_capacity(report.children.len());
    for entry in report.children {
        let Some(wire_scope) = entry.scope.as_ref() else {
            debug!(
                parent_node_id,
                node_id = %entry.node_id,
                "discovery: RosterEntry missing scope, dropped"
            );
            continue;
        };
        let scope = match scope_from_wire(wire_scope) {
            Ok(scope) => node_scope_from(&scope),
            Err(e) => {
                debug!(
                    parent_node_id,
                    node_id = %entry.node_id,
                    error = %e,
                    "discovery: RosterEntry undecodable scope, dropped"
                );
                continue;
            }
        };
        // `bound_reported == false` ⇒ the leaf has not reported bound ports;
        // preserve the None/Some(∅) distinction the #531 gate relies on.
        let bound_ports = entry.bound_reported.then(|| {
            entry
                .bound_ports
                .iter()
                .filter_map(|raw| u16::try_from(*raw).ok())
                .collect::<std::collections::BTreeSet<u16>>()
        });
        children.push(RosterChild {
            node_id: entry.node_id,
            scope,
            last_acked_version: entry.acked_version,
            target_version: entry.target_version,
            last_acked_seq: entry.acked_seq,
            bound_ports,
            connected_since: unix_secs_to_system_time(entry.connected_since_unix),
            last_ack_at: entry.last_ack_at_unix.map(unix_secs_to_system_time),
        });
    }
    registry.apply_roster(parent_node_id, children);
}

/// Wrap a wire snapshot in a `ServerMessage`, send it, and — only on a successful
/// hand-off to the transport — emit the #383 send-side metrics. The nonce is
/// already stamped by [`build_outbound`].
///
/// Counting after the send keeps a closed channel (stream teardown) from inflating
/// the send-side counters with a message that was never delivered.
///
/// Returns `Err(StreamClosed)` if the receiver has been dropped.
pub(super) async fn send_outbound(
    tx: &mpsc::Sender<Result<p::ServerMessage, Status>>,
    message: p::Snapshot,
) -> Result<(), StreamClosed> {
    let kind = if message.full { "full" } else { "delta" };
    let resources_sent = message.resources.len() as u64;
    let resources_removed = message.removed_resources.len() as u64;
    let msg = p::ServerMessage {
        kind: Some(SKind::Snapshot(message)),
    };
    tx.send(Ok(msg)).await.map_err(|_| StreamClosed)?;
    crate::metrics::snapshot_messages_total()
        .with_label_values(&[kind])
        .inc();
    crate::metrics::snapshot_resources_sent_total().inc_by(resources_sent);
    crate::metrics::snapshot_resources_removed_total().inc_by(resources_removed);
    Ok(())
}
