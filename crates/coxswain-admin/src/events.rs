//! Server-Sent Events stream powering the live Operator UI (`GET /api/v1/events`).
//!
//! [`AdminServer`](crate::AdminServer) wires an [`EventSources`] bundle only for
//! the controller and dev pod roles; proxy pods leave it `None`, so the endpoint
//! returns 404 structurally there — the same gate used for the aggregator
//! surface.
//!
//! ## Why a hand-rolled stream
//!
//! Pingora's [`ServeHttp`](pingora_core::apps::http_app::ServeHttp) trait buffers
//! the entire response before returning, so it cannot drive a long-lived SSE
//! stream. [`AdminServer`] therefore implements the lower-level
//! [`HttpServerApp`](pingora_core::apps::HttpServerApp) directly and calls
//! [`run`] for the events path, writing chunked body frames as events arrive.
//!
//! ## Event sources
//!
//! - **Rebuild** — a `watch::Receiver<u64>` over the reconciler's generation
//!   counter (from `RouteStatusHandle::subscribe()`). The receiver type keeps
//!   this crate dependent on `coxswain-core` only, never on `coxswain-reflector`.
//! - **Fleet** — the [`SharedFleet`] cell, polled once per second and diffed
//!   against the previous snapshot (the cell is a plain `ArcSwap` with no change
//!   notification, so polling is the only option).
//! - **Ownership** — the [`SharedClusterSummary`], polled on the same tick; a
//!   Gateway whose [`ProxyPool`] flips between snapshots emits `ownership.changed`.
//! - **Leadership** — the shared leader `AtomicBool`, read on the same tick.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use coxswain_core::cluster::{ClusterSummary, ProxyPool, SharedClusterSummary};
use coxswain_core::fleet::{Component, FleetSnapshot, SharedFleet};
use http::{StatusCode, header};
use pingora_core::protocols::http::ServerSession;
use pingora_core::server::ShutdownWatch;
use pingora_http::ResponseHeader;
use tokio::sync::watch;

/// How often the fleet / cluster / leader sources are polled and diffed.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Keepalive comment cadence — defeats proxy / load-balancer idle timeouts and
/// doubles as the disconnect probe (a failed write on the next keepalive ends
/// the stream).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

// ── EventSources ────────────────────────────────────────────────────────────

/// Live event sources feeding the `/api/v1/events` SSE stream.
///
/// Cheap to clone (every field is an `Arc`-backed handle or a `watch::Receiver`);
/// [`AdminServer`](crate::AdminServer) holds one instance and each connection
/// clones the rebuild receiver so consumers never starve one another.
#[derive(Clone)]
pub struct EventSources {
    /// Generation counter that advances on every successful reconciler rebuild.
    rebuild_rx: watch::Receiver<u64>,
    /// Live fleet snapshot, polled and diffed for pod connect/disconnect events.
    fleet: SharedFleet,
    /// Cluster summary, polled for Gateway proxy-pool ownership changes.
    cluster: SharedClusterSummary,
    /// Name of the controller pod serving this stream, surfaced in
    /// `leader.changed` so the UI can attribute leadership to a pod.
    pod_name: String,
}

impl EventSources {
    /// Bundle the live event sources for the SSE stream.
    ///
    /// `rebuild_rx` is obtained from the reconciler's
    /// `RouteStatusHandle::subscribe()`; passing the receiver (not the
    /// reflector handle) keeps `coxswain-admin` off the `coxswain-reflector`
    /// dependency edge.
    #[must_use]
    pub fn new(
        rebuild_rx: watch::Receiver<u64>,
        fleet: SharedFleet,
        cluster: SharedClusterSummary,
        pod_name: String,
    ) -> Self {
        Self {
            rebuild_rx,
            fleet,
            cluster,
            pod_name,
        }
    }
}

// ── Event model ─────────────────────────────────────────────────────────────

/// One SSE event, kept as a typed value so the diff logic stays unit-testable
/// independent of the wire format produced by [`Event::to_frame`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    /// A reconciler rebuild cycle completed; `cycle` is the generation counter.
    RebuildCompleted { cycle: u64 },
    /// A proxy pod appeared in the fleet.
    ProxyConnected {
        pod: String,
        mode: &'static str,
        admin_addr: String,
    },
    /// A proxy pod left the fleet.
    ProxyDisconnected { pod: String },
    /// A controller pod appeared in the fleet.
    ControllerConnected { pod: String },
    /// A controller pod left the fleet.
    ControllerDisconnected { pod: String },
    /// The serving controller's leader-election state changed (or its initial
    /// value at stream start).
    LeaderChanged { pod: String, is_leader: bool },
    /// A Gateway moved between the shared and dedicated proxy pools.
    OwnershipChanged {
        gateway: String,
        from: &'static str,
        to: &'static str,
    },
}

impl Event {
    /// Wire event name (the `event:` field).
    fn name(&self) -> &'static str {
        match self {
            Event::RebuildCompleted { .. } => "rebuild.completed",
            Event::ProxyConnected { .. } => "proxy.connected",
            Event::ProxyDisconnected { .. } => "proxy.disconnected",
            Event::ControllerConnected { .. } => "controller.connected",
            Event::ControllerDisconnected { .. } => "controller.disconnected",
            Event::LeaderChanged { .. } => "leader.changed",
            Event::OwnershipChanged { .. } => "ownership.changed",
        }
    }

    /// JSON payload (the `data:` field).
    fn data(&self) -> serde_json::Value {
        match self {
            Event::RebuildCompleted { cycle } => {
                serde_json::json!({ "cycle": cycle, "published": true })
            }
            Event::ProxyConnected {
                pod,
                mode,
                admin_addr,
            } => serde_json::json!({ "pod": pod, "mode": mode, "admin_addr": admin_addr }),
            Event::ProxyDisconnected { pod } => {
                serde_json::json!({ "pod": pod, "reason": "pod-deleted" })
            }
            Event::ControllerConnected { pod } => serde_json::json!({ "pod": pod }),
            Event::ControllerDisconnected { pod } => serde_json::json!({ "pod": pod }),
            Event::LeaderChanged { pod, is_leader } => {
                serde_json::json!({ "pod": pod, "is_leader": is_leader })
            }
            Event::OwnershipChanged { gateway, from, to } => {
                serde_json::json!({ "gateway": gateway, "from": from, "to": to })
            }
        }
    }

    /// Render the SSE frame: `event: <name>\ndata: <json>\n\n`.
    fn to_frame(&self) -> String {
        format!("event: {}\ndata: {}\n\n", self.name(), self.data())
    }
}

/// Pool label as it appears in `ownership.changed` `from`/`to` fields.
fn pool_str(pool: ProxyPool) -> &'static str {
    match pool {
        ProxyPool::Shared => "shared",
        ProxyPool::Dedicated => "dedicated",
    }
}

// ── Diff logic ──────────────────────────────────────────────────────────────

/// Diff two fleet snapshots into connect/disconnect events.
///
/// Pods are matched by `pod_name` within each component bucket: names present
/// in `cur` but not `prev` are connects; names present in `prev` but not `cur`
/// are disconnects. Ordering within a bucket is irrelevant — comparison is
/// set-based.
fn diff_fleet(prev: &FleetSnapshot, cur: &FleetSnapshot) -> Vec<Event> {
    let mut events = Vec::new();

    // Proxies (shared + dedicated share one event family, distinguished by `mode`).
    let prev_proxies: Vec<&_> = prev
        .shared_proxies
        .iter()
        .chain(&prev.dedicated_proxies)
        .collect();
    let cur_proxies: Vec<&_> = cur
        .shared_proxies
        .iter()
        .chain(&cur.dedicated_proxies)
        .collect();

    for e in &cur_proxies {
        if !prev_proxies.iter().any(|p| p.pod_name == e.pod_name) {
            let mode = match e.component {
                Component::DedicatedProxy => "dedicated",
                _ => "shared",
            };
            events.push(Event::ProxyConnected {
                pod: e.pod_name.clone(),
                mode,
                admin_addr: SocketAddr::new(e.pod_ip, e.admin_port).to_string(),
            });
        }
    }
    for e in &prev_proxies {
        if !cur_proxies.iter().any(|p| p.pod_name == e.pod_name) {
            events.push(Event::ProxyDisconnected {
                pod: e.pod_name.clone(),
            });
        }
    }

    // Controllers.
    for e in &cur.controllers {
        if !prev.controllers.iter().any(|p| p.pod_name == e.pod_name) {
            events.push(Event::ControllerConnected {
                pod: e.pod_name.clone(),
            });
        }
    }
    for e in &prev.controllers {
        if !cur.controllers.iter().any(|p| p.pod_name == e.pod_name) {
            events.push(Event::ControllerDisconnected {
                pod: e.pod_name.clone(),
            });
        }
    }

    events
}

/// Diff two cluster summaries for Gateway proxy-pool ownership transitions.
///
/// Only Gateways present in **both** snapshots with a changed [`ProxyPool`] emit
/// an event — a newly-appearing Gateway is a creation, not a re-assignment, and
/// is surfaced through the REST list endpoints instead. The `gateway` field is
/// `"namespace/name"`.
fn diff_ownership(prev: &ClusterSummary, cur: &ClusterSummary) -> Vec<Event> {
    let mut events = Vec::new();
    for cur_gw in &cur.gateways {
        let Some(prev_gw) = prev
            .gateways
            .iter()
            .find(|g| g.name == cur_gw.name && g.namespace == cur_gw.namespace)
        else {
            continue;
        };
        if prev_gw.proxy.pool != cur_gw.proxy.pool {
            events.push(Event::OwnershipChanged {
                gateway: format!("{}/{}", cur_gw.namespace, cur_gw.name),
                from: pool_str(prev_gw.proxy.pool),
                to: pool_str(cur_gw.proxy.pool),
            });
        }
    }
    events
}

// ── Stream driver ───────────────────────────────────────────────────────────

/// Drive the SSE stream for one client connection until it disconnects or the
/// server shuts down.
///
/// Writes the `text/event-stream` response header, an initial `leader.changed`
/// reflecting current leadership, then loops on a `tokio::select!`: rebuild
/// ticks emit `rebuild.completed`; a 1 s poll diffs the fleet, cluster, and
/// leader flag; a 15 s keepalive comment keeps intermediaries from timing out.
/// Any downstream write error (client gone) or shutdown signal ends the loop
/// cleanly — the per-connection task simply returns, leaking nothing.
pub(crate) async fn run(sources: &EventSources, leader: &AtomicBool, session: &mut ServerSession) {
    // SSE connections are single-use and long-lived; never offer keepalive reuse.
    session.set_keepalive(None);

    if write_header(session).await.is_err() {
        return;
    }

    let mut rebuild_rx = sources.rebuild_rx.clone();
    let mut prev_fleet = sources.fleet.load();
    let mut prev_cluster = sources.cluster.load();
    let mut last_leader = leader.load(Ordering::Acquire);

    // Announce current leadership immediately so the UI starts in a known state.
    if write_event(
        session,
        &Event::LeaderChanged {
            pod: sources.pod_name.clone(),
            is_leader: last_leader,
        },
    )
    .await
    .is_err()
    {
        return;
    }

    let mut poll = tokio::time::interval(POLL_INTERVAL);
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    // Drop the immediate first tick of each interval — nothing has changed yet.
    poll.tick().await;
    keepalive.tick().await;

    loop {
        tokio::select! {
            biased;
            changed = rebuild_rx.changed() => {
                if changed.is_err() {
                    break; // reconciler dropped its sender — no more rebuilds
                }
                let cycle = *rebuild_rx.borrow_and_update();
                if write_event(session, &Event::RebuildCompleted { cycle }).await.is_err() {
                    break;
                }
            }
            _ = poll.tick() => {
                let cur_fleet = sources.fleet.load();
                let mut events = diff_fleet(&prev_fleet, &cur_fleet);
                prev_fleet = cur_fleet;

                let cur_cluster = sources.cluster.load();
                events.extend(diff_ownership(&prev_cluster, &cur_cluster));
                prev_cluster = cur_cluster;

                let now_leader = leader.load(Ordering::Acquire);
                if now_leader != last_leader {
                    last_leader = now_leader;
                    events.push(Event::LeaderChanged {
                        pod: sources.pod_name.clone(),
                        is_leader: now_leader,
                    });
                }

                if write_events(session, &events).await.is_err() {
                    break;
                }
            }
            _ = keepalive.tick() => {
                if write_chunk(session, ": keepalive\n\n").await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Like [`run`] but also races a [`ShutdownWatch`] so a graceful server
/// shutdown tears the stream down promptly instead of waiting on the next tick.
pub(crate) async fn run_until_shutdown(
    sources: &EventSources,
    leader: &AtomicBool,
    session: &mut ServerSession,
    shutdown: &ShutdownWatch,
) {
    let mut shutdown = shutdown.clone();
    if *shutdown.borrow() {
        return;
    }
    tokio::select! {
        () = run(sources, leader, session) => {}
        _ = shutdown.changed() => {}
    }
}

/// Write the SSE response header: 200 with `text/event-stream`, no caching, and
/// explicit chunked framing (Pingora otherwise falls back to close-delimited for
/// an unknown-length body).
async fn write_header(session: &mut ServerSession) -> pingora_core::Result<()> {
    let mut header = ResponseHeader::build(StatusCode::OK, Some(4))?;
    header.insert_header(header::CONTENT_TYPE, "text/event-stream")?;
    header.insert_header(header::CACHE_CONTROL, "no-cache")?;
    header.insert_header(header::CONNECTION, "keep-alive")?;
    header.insert_header(header::TRANSFER_ENCODING, "chunked")?;
    session.write_response_header(Box::new(header)).await
}

/// Write a batch of events, stopping at the first downstream error.
async fn write_events(session: &mut ServerSession, events: &[Event]) -> pingora_core::Result<()> {
    for ev in events {
        write_event(session, ev).await?;
    }
    Ok(())
}

/// Write one event as a chunked body frame.
async fn write_event(session: &mut ServerSession, ev: &Event) -> pingora_core::Result<()> {
    write_chunk(session, &ev.to_frame()).await
}

/// Write a raw string as a non-terminal body chunk (`end = false` keeps the
/// stream open).
async fn write_chunk(session: &mut ServerSession, body: &str) -> pingora_core::Result<()> {
    session
        .write_response_body(Bytes::copy_from_slice(body.as_bytes()), false)
        .await
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::cluster::{
        ClusterSummary, ControllerSummary, GatewaySummary, ProxyAssignment,
    };
    use coxswain_core::fleet::{
        ADMIN_PORT_ANNOTATION, COMPONENT_LABEL, FleetSnapshot, GATEWAY_NAME_LABEL, build_snapshot,
    };
    use k8s_openapi::api::core::v1::{Pod, PodStatus};
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;

    /// Build a fake [`Pod`] recognised by [`build_snapshot`] — mirrors the
    /// aggregator test helper.
    fn make_pod(name: &str, component: &str, pod_ip: &str, gateway_name: Option<&str>) -> Pod {
        let mut labels = BTreeMap::new();
        labels.insert(COMPONENT_LABEL.to_string(), component.to_string());
        if let Some(gw) = gateway_name {
            labels.insert(GATEWAY_NAME_LABEL.to_string(), gw.to_string());
        }
        let mut annotations = BTreeMap::new();
        annotations.insert(ADMIN_PORT_ANNOTATION.to_string(), "8082".to_string());
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(labels),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: None,
            status: Some(PodStatus {
                pod_ip: Some(pod_ip.to_string()),
                ..Default::default()
            }),
        }
    }

    // ── frame formatting ──────────────────────────────────────────────────────

    #[test]
    fn frame_has_event_and_data_lines_terminated_by_blank_line() {
        let frame = Event::RebuildCompleted { cycle: 47 }.to_frame();
        assert_eq!(
            frame,
            "event: rebuild.completed\ndata: {\"cycle\":47,\"published\":true}\n\n"
        );
    }

    #[test]
    fn proxy_connected_data_carries_mode_and_admin_addr() {
        let ev = Event::ProxyConnected {
            pod: "shared-proxy-abc".to_string(),
            mode: "shared",
            admin_addr: "10.0.1.5:8082".to_string(),
        };
        assert_eq!(ev.name(), "proxy.connected");
        let d = ev.data();
        assert_eq!(d["pod"], "shared-proxy-abc");
        assert_eq!(d["mode"], "shared");
        assert_eq!(d["admin_addr"], "10.0.1.5:8082");
    }

    #[test]
    fn proxy_disconnected_carries_reason() {
        let ev = Event::ProxyDisconnected {
            pod: "ded-gw1".to_string(),
        };
        assert_eq!(
            ev.data(),
            serde_json::json!({ "pod": "ded-gw1", "reason": "pod-deleted" })
        );
    }

    #[test]
    fn leader_changed_carries_pod_and_flag() {
        let ev = Event::LeaderChanged {
            pod: "ctrl-xyz".to_string(),
            is_leader: true,
        };
        assert_eq!(
            ev.data(),
            serde_json::json!({ "pod": "ctrl-xyz", "is_leader": true })
        );
    }

    // ── fleet diff ────────────────────────────────────────────────────────────

    #[test]
    fn diff_fleet_empty_to_empty_yields_nothing() {
        let events = diff_fleet(&FleetSnapshot::default(), &FleetSnapshot::default());
        assert!(events.is_empty());
    }

    #[test]
    fn diff_fleet_detects_proxy_connect_with_mode_and_addr() {
        let prev = FleetSnapshot::default();
        let cur = build_snapshot([&make_pod("proxy-0", "shared-proxy", "10.0.0.2", None)]);
        let events = diff_fleet(&prev, &cur);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            Event::ProxyConnected {
                pod: "proxy-0".to_string(),
                mode: "shared",
                admin_addr: "10.0.0.2:8082".to_string(),
            }
        );
    }

    #[test]
    fn diff_fleet_detects_dedicated_proxy_mode() {
        let prev = FleetSnapshot::default();
        let cur = build_snapshot([&make_pod(
            "ded-0",
            "dedicated-proxy",
            "10.0.0.3",
            Some("gw1"),
        )]);
        let events = diff_fleet(&prev, &cur);
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::ProxyConnected { mode, pod, .. } => {
                assert_eq!(*mode, "dedicated");
                assert_eq!(pod, "ded-0");
            }
            other => panic!("expected ProxyConnected, got {other:?}"),
        }
    }

    #[test]
    fn diff_fleet_detects_proxy_disconnect() {
        let prev = build_snapshot([&make_pod("proxy-0", "shared-proxy", "10.0.0.2", None)]);
        let cur = FleetSnapshot::default();
        let events = diff_fleet(&prev, &cur);
        assert_eq!(
            events,
            vec![Event::ProxyDisconnected {
                pod: "proxy-0".to_string()
            }]
        );
    }

    #[test]
    fn diff_fleet_detects_controller_connect_and_disconnect() {
        let prev = build_snapshot([&make_pod("ctrl-a", "controller", "10.0.0.1", None)]);
        let cur = build_snapshot([&make_pod("ctrl-b", "controller", "10.0.0.9", None)]);
        let events = diff_fleet(&prev, &cur);
        // ctrl-b connected, ctrl-a disconnected (order: connects first).
        assert!(events.contains(&Event::ControllerConnected {
            pod: "ctrl-b".to_string()
        }));
        assert!(events.contains(&Event::ControllerDisconnected {
            pod: "ctrl-a".to_string()
        }));
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn diff_fleet_stable_snapshot_yields_nothing() {
        let snap = build_snapshot([
            &make_pod("proxy-0", "shared-proxy", "10.0.0.2", None),
            &make_pod("ctrl-0", "controller", "10.0.0.1", None),
        ]);
        // Rebuild an identical snapshot from the same pods.
        let same = build_snapshot([
            &make_pod("proxy-0", "shared-proxy", "10.0.0.2", None),
            &make_pod("ctrl-0", "controller", "10.0.0.1", None),
        ]);
        assert!(diff_fleet(&snap, &same).is_empty());
    }

    // ── ownership diff ────────────────────────────────────────────────────────

    fn cluster_with(gateways: Vec<GatewaySummary>) -> ClusterSummary {
        ClusterSummary::new(gateways, vec![], vec![], ControllerSummary::new(false))
    }

    #[test]
    fn diff_ownership_detects_shared_to_dedicated() {
        let prev = cluster_with(vec![GatewaySummary::new("gw1", "default")]);
        let cur = cluster_with(vec![
            GatewaySummary::new("gw1", "default").with_proxy(ProxyAssignment::dedicated()),
        ]);
        let events = diff_ownership(&prev, &cur);
        assert_eq!(
            events,
            vec![Event::OwnershipChanged {
                gateway: "default/gw1".to_string(),
                from: "shared",
                to: "dedicated",
            }]
        );
    }

    #[test]
    fn diff_ownership_detects_dedicated_to_shared() {
        let prev = cluster_with(vec![
            GatewaySummary::new("gw1", "default").with_proxy(ProxyAssignment::dedicated()),
        ]);
        let cur = cluster_with(vec![GatewaySummary::new("gw1", "default")]);
        let events = diff_ownership(&prev, &cur);
        assert_eq!(events[0].name(), "ownership.changed");
        assert_eq!(events[0].data()["from"], "dedicated");
        assert_eq!(events[0].data()["to"], "shared");
    }

    #[test]
    fn diff_ownership_ignores_unchanged_pool() {
        let prev = cluster_with(vec![GatewaySummary::new("gw1", "default")]);
        let cur = cluster_with(vec![
            GatewaySummary::new("gw1", "default").with_route_count(5),
        ]);
        assert!(diff_ownership(&prev, &cur).is_empty());
    }

    #[test]
    fn diff_ownership_ignores_newly_created_gateway() {
        let prev = cluster_with(vec![]);
        let cur = cluster_with(vec![
            GatewaySummary::new("gw1", "default").with_proxy(ProxyAssignment::dedicated()),
        ]);
        assert!(diff_ownership(&prev, &cur).is_empty());
    }
}
