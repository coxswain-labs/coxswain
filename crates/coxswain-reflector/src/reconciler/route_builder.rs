//! Routing-table and TLS-store builders driven by the [`super::proxy`] rebuild
//! loop. The orchestration (debounce, leader gating, dedicated-path management)
//! stays in `proxy.rs`; this module owns the pure "snapshot → table/store +
//! health" build steps it calls, communicating via the parameter-group DTOs
//! ([`ReflectorStores`], [`Ownership`], [`SharedOutputs`], [`IngressBuildConfig`])
//! defined alongside the loop.

use super::listener_merge::{EffectiveGateway, EffectiveListener};
use super::proxy::{
    IngressBuildConfig, IngressDefaultBackend, IngressEvent, Ownership, ReflectorStores,
    SharedOutputs, gateway_is_cut_over,
};
use crate::endpoints;
use crate::gateway_api::hostnames_intersect;
use crate::gateway_api::{
    GatewayApiReconciler, GrpcRouteReconciler, GrpcRouteResolution, ListenerBinding, RouteLike,
    TlsRouteReconciler, parent_listener_source,
};
use crate::gw_types::{GrpcRoute, HttpRoute};
use crate::ingress::annotations::AnnotationIssue;
use crate::ingress::{IngressClassContext, IngressPorts, IngressReconciler, resolve_class_params};
use crate::keys::ListenerKey;
use crate::tls::{
    BackendClientCertOutcome, GatewayListenerHealth, ListenerHealthKey, ListenerInfo,
    ListenerSource, ListenerTlsOutcome, RouteHealthMap,
};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::reference_grants::{self as reference_grants, ReferenceGrantKey};
use coxswain_core::routing::{
    BackendClientCert, BackendGroup, GatewayRoutingTableBuilder, IngressRoutingTableBuilder,
    RouteEntry, RoutingTable, RoutingTableBuilder, SharedGatewayRoutingTable,
    SharedIngressRoutingTable, SharedTlsPassthroughTable, TlsPassthroughTableBuilder,
};
use coxswain_core::shared::Shared;
use coxswain_core::tls::{
    ClientCertStoreBuilder, ListenerHostnamesBuilder, PortTlsStoreBuilder, SharedClientCertStore,
    SharedListenerHostnames, SharedPortTlsStore,
};

use crate::port_alloc::ListenerKey as VipListenerKey;

/// `(Gateway, listenerPort) → internalPort` map read once per rebuild from the
/// VIP Services (#472) and threaded into every route/TLS/passthrough builder, so
/// all four keyings agree within one reconcile (a fresh `.state()` read per
/// builder could otherwise observe a mid-rebuild Service mutation and disagree).
pub(super) type VipInternalPorts = std::collections::HashMap<VipListenerKey, u16>;

use k8s_openapi::api::networking::v1::Ingress;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Build and publish the Ingress and Gateway routing tables from their
/// respective source resources.
///
/// Two independent build pipelines run, each with its own typed builder. The
/// two `Shared` outputs are swapped independently: a failure in one cannot
/// disrupt or partially clear the other. Returns `true` only when BOTH builds
/// publish successfully — the proxy is not considered "fully synchronised"
/// until each table has had at least one honest publish.
pub(super) fn build_routes(
    stores: &ReflectorStores<'_>,
    routes: &[Arc<HttpRoute>],
    grpc_routes: &[Arc<GrpcRoute>],
    ingresses: &[Arc<Ingress>],
    ownership: &Ownership<'_>,
    ingress_cfg: IngressBuildConfig<'_>,
    outputs: &SharedOutputs<'_>,
) -> bool {
    let gateway_published = build_gateway_routes(
        stores,
        routes,
        grpc_routes,
        ownership,
        outputs.gateway_routes,
        true,
    );
    let ingress_published = build_ingress_routes(
        stores,
        ingresses,
        ownership,
        ingress_cfg.default_backend,
        ingress_cfg.ports,
        outputs.ingress_routes,
        outputs.ingress_event_tx,
    );
    gateway_published && ingress_published
}

/// Per-rebuild resolution of every owned Gateway's GEP-3155 backend client cert.
///
/// `certs` feeds the routing build (attached to `UpstreamTls`); `health` feeds the
/// controller's gateway-level `ResolvedRefs` condition. Resolved once so both views
/// stay consistent. `skip_cut_over` mirrors [`build_tls`]'s semantics.
pub(super) struct BackendClientCertResolution {
    /// Gateways that resolved a usable client cert, keyed by `ObjectKey(ns, name)`.
    pub certs: HashMap<ObjectKey, Arc<BackendClientCert>>,
    /// Per-Gateway resolution outcome (only Gateways with the ref set appear here).
    pub health: HashMap<ObjectKey, BackendClientCertOutcome>,
    /// Gateways whose ref is configured but failed to resolve. Drives the
    /// data-plane fail-closed (502) on their routes' BackendTLSPolicy upstreams.
    pub failures: HashSet<ObjectKey>,
}

/// Resolve `spec.tls.backend.clientCertificateRef` for every owned Gateway.
///
/// Takes the two fields from `Ownership` it actually needs (`gateway_classes` and
/// `cert_grants`) so it can be called *before* `Ownership` is constructed — the
/// resolution result is then folded into `Ownership.backend_client_certs`.
pub(super) fn resolve_backend_client_certs(
    stores: &ReflectorStores<'_>,
    gateway_classes: &HashSet<String>,
    cert_grants: &HashSet<ReferenceGrantKey>,
    skip_cut_over: bool,
) -> BackendClientCertResolution {
    let mut certs = HashMap::new();
    let mut health = HashMap::new();
    let mut failures = HashSet::new();
    for gw in stores.gateways.state() {
        if !gateway_classes.contains(&gw.spec.gateway_class_name) {
            continue;
        }
        if skip_cut_over && gateway_is_cut_over(&gw) {
            continue;
        }
        let Some((outcome, cert)) =
            crate::gateway_api::backend_client_cert::reconcile_backend_client_cert(
                &gw,
                stores.secrets,
                cert_grants,
            )
        else {
            continue;
        };
        let ns = gw.metadata.namespace.clone().unwrap_or_default();
        let name = gw.metadata.name.clone().unwrap_or_default();
        let key = ObjectKey::new(ns, name);
        if let Some(cert) = cert {
            certs.insert(key.clone(), cert);
        }
        if outcome.is_failed() {
            failures.insert(key.clone());
        }
        health.insert(key, outcome);
    }
    BackendClientCertResolution {
        certs,
        health,
        failures,
    }
}

/// Build the Gateway-API routing table from `HTTPRoute` resources and publish
/// it to `shared`. Returns `true` if the publish succeeded.
/// `skip_cut_over` drops cut-over Gateways from the listener-info map —
/// correct for the *shared* reconciler (those listeners bind on the dedicated
/// proxy instead). The dedicated reconciler must pass `false`: its target
/// Gateway IS the cut-over Gateway, and filtering it leaves the dedicated
/// subprocess with no listener_info and no resolvable routes.
pub(super) fn build_gateway_routes(
    stores: &ReflectorStores<'_>,
    routes: &[Arc<HttpRoute>],
    grpc_routes: &[Arc<GrpcRoute>],
    ownership: &Ownership<'_>,
    shared: &SharedGatewayRoutingTable,
    skip_cut_over: bool,
) -> bool {
    let vip_internal = stores.vip_internal;
    // Precompute ListenerKey → (hostname, spec port, bind port) from every owned
    // Gateway's EFFECTIVE listeners (its own plus those merged from attached
    // ListenerSets, GEP-1713). `effective_gateways` already excludes unowned
    // classes; conflicted listeners (lost a port conflict) are not programmed.
    let listener_info: HashMap<ListenerKey, ListenerBinding> = ownership
        .effective_gateways
        .values()
        .filter(|e| !(skip_cut_over && gateway_is_cut_over(&e.gateway)))
        .flat_map(|e| {
            let ns = e.gateway.metadata.namespace.clone().unwrap_or_default();
            let name = e.gateway.metadata.name.clone().unwrap_or_default();
            let gw_key = ObjectKey::new(ns.clone(), name.clone());
            let vip = vip_internal.clone();
            e.listeners
                .iter()
                .filter(|l| !l.conflicted)
                .map(move |l| {
                    // Key by the DECLARING resource so a route's parentRef (Gateway
                    // or ListenerSet) resolves to the right listener and same-named
                    // listeners across sources don't collide (GEP-1713). The bind
                    // port is still the parent Gateway's VIP slot for this spec port.
                    let key = match &l.source {
                        ListenerSource::Gateway => {
                            ListenerKey::new(ns.clone(), name.clone(), l.name.clone())
                        }
                        ListenerSource::ListenerSet(ls_key) => {
                            ListenerKey::for_listener_set(ls_key, l.name.clone())
                        }
                    };
                    let spec_port = l.port as u16;
                    let bind_port = vip
                        .get(&(gw_key.clone(), spec_port))
                        .copied()
                        .unwrap_or(spec_port);
                    let binding = ListenerBinding {
                        hostname: l.hostname.clone().unwrap_or_default(),
                        port: spec_port,
                        bind_port,
                    };
                    (key, binding)
                })
                .collect::<Vec<_>>()
        })
        .collect();

    let mut builder = GatewayRoutingTableBuilder::new();
    for route in routes {
        GatewayApiReconciler::reconcile(
            route,
            stores.slices,
            stores.services,
            ownership.gateways,
            ownership.backend_grants,
            crate::gateway_api::RouteResolution {
                listener_info: &listener_info,
                policy_index: ownership.policy_index,
                rate_limits: stores.rate_limits,
                path_rewrites: stores.path_rewrites,
                backend_client_certs: ownership.backend_client_certs,
                backend_client_cert_failures: ownership.backend_client_cert_failures,
            },
            &mut builder,
        );
    }
    // GRPCRoute rules are installed into the same builder — gRPC is HTTP/2 POST
    // `/{Service}/{Method}`, so it competes in the same routing table as HTTPRoute.
    for grpc_route in grpc_routes {
        GrpcRouteReconciler::reconcile(
            grpc_route,
            stores.slices,
            stores.services,
            ownership.gateways,
            ownership.backend_grants,
            GrpcRouteResolution {
                listener_info: &listener_info,
                policy_index: ownership.policy_index,
            },
            &mut builder,
        );
    }

    publish_routes(
        shared,
        builder,
        "gateway",
        routes.len() + grpc_routes.len(),
        ownership.gateways.len(),
        None,
    )
}

/// Build the Ingress routing table from `Ingress` resources (plus the
/// controller-wide default backend, if configured) and publish it to `shared`.
/// Returns `true` if the publish succeeded.
fn build_ingress_routes(
    stores: &ReflectorStores<'_>,
    ingresses: &[Arc<Ingress>],
    ownership: &Ownership<'_>,
    ingress_default_backend: Option<&IngressDefaultBackend>,
    ingress_ports: IngressPorts,
    shared: &SharedIngressRoutingTable,
    event_tx: Option<&tokio::sync::mpsc::Sender<IngressEvent>>,
) -> bool {
    // Resolve per-class parameters once for this rebuild: each owned IngressClass's
    // spec.parameters → CoxswainIngressClassParameters → defaultAnnotations +
    // accessLog. Reconcile layers annotation defaults under each Ingress's own
    // annotations (per-Ingress keys win); accessLog is class-scoped and has no
    // per-Ingress override (#279).
    let class_params = resolve_class_params(
        stores.ingress_classes,
        ownership.ingress_classes,
        stores.ingress_class_parameters,
    );
    let class_ctx = IngressClassContext::new(
        ownership.ingress_classes,
        ownership.default_ingress_class,
        &class_params,
    );

    let mut builder = IngressRoutingTableBuilder::new();
    let mut pending_annotation_events: Vec<(String, String, Vec<AnnotationIssue>)> = Vec::new();
    for ingress in ingresses {
        let issues = IngressReconciler::reconcile(
            ingress,
            stores.slices,
            stores.services,
            &class_ctx,
            ingress_ports,
            &mut builder,
            stores.auth_secrets,
        );
        if !issues.is_empty() && event_tx.is_some() {
            let ns = ingress
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default")
                .to_string();
            let name = ingress
                .metadata
                .name
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            pending_annotation_events.push((ns, name, issues));
        }
    }

    // Install the controller-wide default backend on the catchall for each configured
    // Ingress port. Per-Ingress defaults always win because they are installed on the
    // host router (matched first).
    if let Some(db) = ingress_default_backend {
        let resolved = endpoints::resolve(
            &db.namespace,
            &db.name,
            db.port,
            stores.slices,
            stores.services,
        );
        if resolved.addrs.is_empty() {
            tracing::warn!(
                svc = %format!("{}/{}", db.namespace, db.name),
                "No ready endpoints for --ingress-default-backend — skipping"
            );
        } else {
            let protocol = resolved.app_protocol;
            let group = Arc::new(
                BackendGroup::new(format!("{}/{}", db.namespace, db.name), resolved.addrs)
                    .with_protocol(protocol),
            );
            let svc_id = format!("{}/{}", db.namespace, db.name);
            // Distinct kind prefix so the controller-wide `--ingress-default-backend`
            // doesn't collide with any specific Ingress's `spec.defaultBackend`
            // (which uses `ingress/<ns>/<name>:default`).
            let metric_route_id: Arc<str> = Arc::from(format!(
                "ingress-default-backend/{}/{}",
                db.namespace, db.name
            ));
            for port in [ingress_ports.http, ingress_ports.https]
                .into_iter()
                .flatten()
            {
                let e = Arc::new(
                    RouteEntry::path_only(Arc::clone(&group), svc_id.clone(), None)
                        .with_path_pattern(Arc::from("/"))
                        .with_metric_route_id(Arc::clone(&metric_route_id)),
                );
                builder.for_port(port).catchall().add_prefix_route("/", e);
            }
        }
    }

    let published = publish_routes(
        shared,
        builder,
        "ingress",
        ingresses.len(),
        ownership.ingress_classes.len(),
        event_tx,
    );

    // Send annotation-failure events after the table is published.
    // Non-blocking: if the channel is full the event is dropped rather than
    // stalling the rebuild loop.
    if let Some(tx) = event_tx {
        for (ns, name, issues) in pending_annotation_events {
            for issue in issues {
                let _ = tx.try_send(IngressEvent::InvalidAnnotation {
                    namespace: ns.clone(),
                    name: name.clone(),
                    annotation: issue.annotation,
                    message: issue.message,
                });
            }
        }
    }

    published
}

/// Generic publish step: compile a builder, log conflicts, swap the snapshot.
///
/// Returns `true` if the build succeeded; `false` leaves the previous snapshot
/// in place and lets the failure surface in logs without taking the proxy down.
///
/// When `event_tx` is `Some`, a non-blocking [`IngressEvent::Conflict`] is sent
/// for each conflict in addition to the existing `tracing::warn!`. Dropped
/// events (full channel) are silently ignored — the warn log still fires.
fn publish_routes<K>(
    shared: &Shared<RoutingTable<K>>,
    builder: RoutingTableBuilder<K>,
    table_label: &'static str,
    source_count: usize,
    owned_owner_count: usize,
    event_tx: Option<&tokio::sync::mpsc::Sender<IngressEvent>>,
) -> bool {
    match builder.build() {
        Ok(table) => {
            for c in table.conflicts() {
                tracing::warn!(
                    port = c.port,
                    host = %c.host,
                    path = %c.path,
                    kind = c.kind.as_str(),
                    rejected_group = %c.rejected_group,
                    table = table_label,
                    "Route conflict: path already claimed by an earlier rule — ignoring"
                );
                if let Some(tx) = event_tx {
                    let (namespace, name) = c
                        .rejected_route_id
                        .split_once('/')
                        .map(|(ns, n)| (ns.to_string(), n.to_string()))
                        .unwrap_or_default();
                    let _ = tx.try_send(IngressEvent::Conflict {
                        namespace,
                        name,
                        winner_route_id: c.winner_route_id.clone(),
                        host: c.host.clone(),
                        path: c.path.clone(),
                    });
                }
            }
            shared.store(Arc::new(table));
            tracing::info!(
                table = table_label,
                sources = source_count,
                owners = owned_owner_count,
                "Routing table rebuilt"
            );
            true
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                table = table_label,
                "Routing table build failed — retaining previous table"
            );
            false
        }
    }
}

/// Build and publish the TLS cert store and the per-port HTTPS listener-hostname
/// snapshot; returns per-gateway listener health for further use.
///
/// `skip_cut_over` drops Gateways whose `DedicatedProxyReady=True` condition
/// matches their current generation — appropriate for the *shared* reconciler
/// (the shared pool yields these listeners to the dedicated proxy that owns
/// them). The dedicated reconciler must pass `false`: the Gateway it serves
/// IS the cut-over Gateway, and skipping it leaves the dedicated subprocess
/// with no listener specs and no bound listener.
pub(super) fn build_tls(
    stores: &ReflectorStores<'_>,
    ingresses: &[Arc<Ingress>],
    ownership: &Ownership<'_>,
    tls_shared: &SharedPortTlsStore,
    listener_hostnames_shared: &SharedListenerHostnames,
    skip_cut_over: bool,
    ingress_https_port: u16,
) -> HashMap<ObjectKey, GatewayListenerHealth> {
    let vip_internal = stores.vip_internal;
    // Per-port cert store (#472): the bind port keys each cert so the proxy's
    // per-port SniCertSelector — scoped to the accepted local port — finds it.
    let mut tls_builder = PortTlsStoreBuilder::new();
    for ingress in ingresses {
        IngressReconciler::reconcile_tls(
            ingress,
            stores.secrets,
            ownership.ingress_classes,
            ownership.default_ingress_class,
            &mut tls_builder,
            ingress_https_port,
        );
    }

    let mut lh_builder = ListenerHostnamesBuilder::new();
    let mut gateway_listener_health: HashMap<ObjectKey, GatewayListenerHealth> = HashMap::new();
    for gw in stores.gateways.state() {
        if !ownership
            .gateway_classes
            .contains(&gw.spec.gateway_class_name)
        {
            continue;
        }
        // Cut-over Gateways (#210) don't contribute TLS certs to the shared
        // store — the dedicated proxy terminates their TLS instead. The
        // dedicated reconciler passes `skip_cut_over = false` because its
        // target Gateway IS cut over and it must still bind its listener.
        if skip_cut_over && gateway_is_cut_over(&gw) {
            continue;
        }
        let ns = gw.metadata.namespace.clone().unwrap_or_default();
        let name = gw.metadata.name.clone().unwrap_or_default();
        let gw_key = ObjectKey::new(ns.clone(), name.clone());
        // This Gateway's listenerPort → internalPort slice of the global map.
        let gw_internal: std::collections::HashMap<u16, u16> = vip_internal
            .iter()
            .filter(|((k, _), _)| k == &gw_key)
            .map(|((_, lp), ip)| (*lp, *ip))
            .collect();
        // GEP-1713: reconcile the Gateway's EFFECTIVE listeners (its own plus those
        // merged from attached ListenerSets), each resolving its certs in its own
        // namespace. Falls back to an empty slice for a Gateway not in the map.
        let listeners: &[EffectiveListener] = ownership
            .effective_gateways
            .get(&gw_key)
            .map(|e| e.listeners.as_slice())
            .unwrap_or(&[]);
        let health = GatewayApiReconciler::reconcile_tls(
            &name,
            listeners,
            stores.secrets,
            ownership.cert_grants,
            ownership.ls_cert_grants,
            &mut tls_builder,
            &gw_internal,
        );
        // Populate the per-port listener-hostname snapshot for
        // misdirected-request detection (GEP-3567, #96). Keyed by BIND port so
        // the proxy (which checks by the accepted local port) matches it (#472).
        // Conflicted listeners (GEP-1713) are not programmed — skip them.
        for li in health.listeners.values() {
            if li.conflicted {
                continue;
            }
            lh_builder.add_listener(
                li.bind_port(),
                &li.hostname,
                li.tls_outcome.is_https_terminate(),
            );
        }
        gateway_listener_health.insert(gw_key, health);
    }

    let tls_store = tls_builder.build();
    let ports = tls_store.port_count();
    let current = tls_shared.load();
    if *current != tls_store {
        tracing::debug!(ports, "per-port TLS cert store swapped");
        tls_shared.store(Arc::new(tls_store));
    } else {
        tracing::trace!(ports, "per-port TLS cert store unchanged, skip swap");
    }

    let lh = lh_builder.build();
    let current_lh = listener_hostnames_shared.load();
    if *current_lh != lh {
        tracing::debug!("listener-hostnames snapshot swapped");
        listener_hostnames_shared.store(Arc::new(lh));
    } else {
        tracing::trace!("listener-hostnames snapshot unchanged, skip swap");
    }

    gateway_listener_health
}

/// Build and publish the per-host client-certificate mTLS config store.
///
/// Two sources are reconciled into a single [`ClientCertStoreBuilder`]:
///
/// 1. **Ingress** `auth-tls-*` annotations (`reconcile_client_certs`) — per-listener CA
///    sourced from a labeled Secret.
/// 2. **Gateway** `spec.tls.frontend.default.validation` (GEP-91, #86) — gateway-wide CA
///    sourced from a ConfigMap, keyed by listener hostname.
///
/// The function also annotates `gateway_listener_health` with
/// [`coxswain_core::listener_health::FrontendValidationHealth`] so the controller can emit
/// the `InsecureFrontendValidationMode` condition required by GEP-91.
///
/// Uses a `PartialEq` short-circuit identical to [`build_tls`]: if the new store is byte-for-byte
/// equal to the current snapshot the [`SharedClientCertStore`] ArcSwap is NOT updated, preventing
/// a spurious hot-reload.
pub(super) fn build_client_certs(
    stores: &ReflectorStores<'_>,
    ingresses: &[Arc<Ingress>],
    ownership: &Ownership<'_>,
    client_certs_shared: &SharedClientCertStore,
    gateway_listener_health: &mut HashMap<ObjectKey, GatewayListenerHealth>,
    skip_cut_over: bool,
) {
    let mut builder = ClientCertStoreBuilder::new();

    // ── Ingress: auth-tls-* annotations ──────────────────────────────────────
    for ingress in ingresses {
        IngressReconciler::reconcile_client_certs(
            ingress,
            stores.auth_tls_secrets,
            ownership.ingress_classes,
            ownership.default_ingress_class,
            &mut builder,
        );
    }

    // ── Gateway: spec.tls.frontend.default.validation (GEP-91) ───────────────
    for gw in stores.gateways.state() {
        if !ownership
            .gateway_classes
            .contains(&gw.spec.gateway_class_name)
        {
            continue;
        }
        if skip_cut_over && gateway_is_cut_over(&gw) {
            continue;
        }
        let ns = gw.metadata.namespace.clone().unwrap_or_default();
        let name = gw.metadata.name.clone().unwrap_or_default();
        let key = ObjectKey::new(ns, name);
        // Update the health entry that was created by build_tls for this Gateway.
        // If no entry exists yet (race on first rebuild) create a default one.
        let health = gateway_listener_health.entry(key).or_default();
        crate::gateway_api::frontend_tls::reconcile_frontend_validation(
            &gw,
            stores.configmaps,
            ownership.ca_grants,
            &mut builder,
            health,
        );
    }

    let store = builder.build();
    let count = store.host_count();
    let current = client_certs_shared.load();
    if *current != store {
        tracing::debug!(count, "Client-cert store swapped");
        client_certs_shared.store(Arc::new(store));
    } else {
        tracing::trace!(count, "Client-cert store unchanged, skip swap");
    }
}

/// Fold per-Gateway GEP-3155 backend client-cert outcomes into `gateway_listener_health`
/// so the controller can emit the gateway-level `ResolvedRefs` condition.
///
/// Creates a health entry for a Gateway that resolved a backend client cert but has no
/// TLS listeners (the invalid-config conformance gateways have only an HTTP listener).
pub(super) fn merge_backend_client_cert_health(
    gateway_listener_health: &mut HashMap<ObjectKey, GatewayListenerHealth>,
    health: &HashMap<ObjectKey, BackendClientCertOutcome>,
) {
    for (key, outcome) in health {
        gateway_listener_health
            .entry(key.clone())
            .or_default()
            .backend_client_cert = Some(outcome.clone());
    }
}

/// Increment `attached_routes` counters for each gateway listener whose hostname
/// intersects with the route's hostnames. Only owned gateways are counted.
///
/// Generic over [`RouteLike`] so the one algorithm serves every route kind
/// (HTTPRoute, GRPCRoute, TLSRoute) — GRPC/TLS listeners would otherwise always
/// report `attachedRoutes: 0` (#470). `passthrough_kind` flips listener
/// eligibility by kind: TLSRoutes attach **only** to `TlsPassthrough` listeners,
/// HTTP/GRPC routes attach only to non-passthrough listeners (the
/// `allowedRoutes.kinds` restriction implied by listener protocol/mode).
pub(super) fn count_attached_routes<R: RouteLike>(
    routes: &[Arc<R>],
    owned_gateways: &HashSet<ObjectKey>,
    ls_parent: &HashMap<ObjectKey, ObjectKey>,
    gateway_listener_health: &mut HashMap<ObjectKey, GatewayListenerHealth>,
    passthrough_kind: bool,
) {
    // A listener accepts this route kind when its passthrough-ness matches the
    // kind: passthrough listeners ↔ TLSRoutes, everything else ↔ HTTP/GRPC.
    let listener_accepts = |info: &ListenerInfo| {
        passthrough_kind == matches!(info.tls_outcome, ListenerTlsOutcome::TlsPassthrough)
    };

    for route in routes {
        let route_ns = route.route_namespace().unwrap_or("default");
        let route_hostnames = route.route_hostnames();

        for pr in route.route_parent_refs() {
            let ref_ns = pr.namespace.unwrap_or(route_ns);
            // GEP-1713: a parentRef targets either a Gateway or a ListenerSet. Resolve
            // the owning Gateway whose health holds the listener, plus the source to
            // match — a ListenerSet parentRef counts only against its own listeners.
            let gw_api_group = pr
                .group
                .is_none_or(|g| g.is_empty() || g == "gateway.networking.k8s.io");
            let (target_gw, source) = if gw_api_group && pr.kind == Some("ListenerSet") {
                let ls_key = ObjectKey::new(ref_ns, pr.name);
                match ls_parent.get(&ls_key) {
                    Some(gw) => (gw.clone(), ListenerSource::ListenerSet(ls_key)),
                    None => continue,
                }
            } else {
                (ObjectKey::new(ref_ns, pr.name), ListenerSource::Gateway)
            };
            if !owned_gateways.contains(&target_gw) {
                continue;
            }
            if let Some(health) = gateway_listener_health.get_mut(&target_gw) {
                if let Some(sn) = pr.section_name {
                    let key = ListenerHealthKey {
                        source: source.clone(),
                        name: sn.to_string(),
                    };
                    let Some(info) = health.listeners.get_mut(&key) else {
                        continue;
                    };
                    if ref_ns != route_ns && !info.allows_all_namespaces {
                        continue;
                    }
                    if let Some(port) = pr.port
                        && info.port != port
                    {
                        continue;
                    }
                    if !listener_accepts(info) {
                        continue;
                    }
                    if hostnames_intersect(&route_hostnames, &info.hostname) {
                        info.attached_routes += 1;
                    }
                } else {
                    let matching: Vec<ListenerHealthKey> = health
                        .listeners
                        .keys()
                        .filter(|k| k.source == source)
                        .cloned()
                        .collect();
                    for ln in matching {
                        let Some(info) = health.listeners.get_mut(&ln) else {
                            continue;
                        };
                        if let Some(p) = pr.port
                            && info.port != p
                        {
                            continue;
                        }
                        if ref_ns != route_ns && !info.allows_all_namespaces {
                            continue;
                        }
                        if !listener_accepts(info) {
                            continue;
                        }
                        if hostnames_intersect(&route_hostnames, &info.hostname) {
                            info.attached_routes += 1;
                        }
                    }
                }
            }
        }
    }
}

/// Build and publish the SNI-keyed TLS passthrough routing table from `TLSRoute`
/// resources bound to `protocol: TLS, tls.mode: Passthrough` Gateway listeners.
///
/// The proxy uses this table to route raw, still-encrypted TCP streams by the
/// ClientHello SNI — TLS is never terminated at the proxy on this path.
///
/// Returns per-(TLSRoute, parentRef) health so the controller can write
/// `Accepted` / `ResolvedRefs` status conditions on each route.
pub(super) fn build_passthrough_routes(
    stores: &ReflectorStores<'_>,
    owned_gateways: &HashSet<ObjectKey>,
    effective: &HashMap<ObjectKey, EffectiveGateway>,
    backend_grants: &HashSet<ReferenceGrantKey>,
    out: &SharedTlsPassthroughTable,
) -> RouteHealthMap {
    let tls_routes = stores.tls_routes.state();
    let gateways = stores.gateways.state();
    let vip_internal = stores.vip_internal;

    let mut builder = TlsPassthroughTableBuilder::new();

    for gw in &gateways {
        let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");
        let gw_name = gw.metadata.name.as_deref().unwrap_or("");
        let gw_key = ObjectKey::new(gw_ns, gw_name);
        if !owned_gateways.contains(&gw_key) {
            continue;
        }

        // Iterate the effective listener set — the Gateway's own listeners plus
        // any attached ListenerSets' (GEP-1713), each tagged with its source —
        // so a TLSRoute can attach to a TLS/Passthrough listener regardless of
        // which resource declared it. Falls back to nothing if the merge has no
        // entry for this owned Gateway (defensive; should not happen).
        let Some(eff) = effective.get(&gw_key) else {
            continue;
        };

        for listener in &eff.listeners {
            if listener.protocol != "TLS" {
                continue;
            }
            let is_passthrough = listener.tls.as_ref().is_some_and(|t| t.passthrough);
            if !is_passthrough {
                continue;
            }
            // Lost a port-compatibility conflict to a higher-precedence listener
            // (GEP-1713) — not programmed, so no routing entries.
            if listener.conflicted {
                continue;
            }

            let listener_port = listener.port as u16;
            // Spec port (above) matches the TLSRoute's parentRef.port; the bind
            // port (below) is what the proxy accepts on and keys routing by (#472).
            // A ListenerSet listener merges onto the parent Gateway's VIP, so the
            // bind port is still keyed by the parent Gateway's key.
            let bind_port = vip_internal
                .get(&(gw_key.clone(), listener_port))
                .copied()
                .unwrap_or(listener_port);
            let listener_hostname = listener.hostname.as_deref().unwrap_or("");
            let allows_all_ns = listener.allows_all_namespaces;
            // `from: Same` is relative to the resource that declared the listener:
            // the Gateway's namespace for a Gateway listener, the ListenerSet's
            // namespace for a ListenerSet listener.
            let owning_ns = listener.owning_namespace.as_str();
            let source = &listener.source;

            for route in &tls_routes {
                let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");

                if !allows_all_ns && route_ns != owning_ns {
                    continue;
                }

                let parent_refs = route.spec.parent_refs.as_deref().unwrap_or(&[]);
                let binds = parent_refs.iter().any(|pr| {
                    let pr_ns = pr.namespace.as_deref().unwrap_or(route_ns);
                    // Resolve the parentRef's target source (Gateway vs a specific
                    // ListenerSet) and require it to match the listener's source.
                    let pr_source = parent_listener_source(
                        pr.group.as_deref(),
                        pr.kind.as_deref(),
                        pr_ns,
                        &pr.name,
                    );
                    let target_ok = match (source, &pr_source) {
                        (ListenerSource::Gateway, ListenerSource::Gateway) => {
                            pr_ns == gw_ns && pr.name == gw_name
                        }
                        (ListenerSource::ListenerSet(a), ListenerSource::ListenerSet(b)) => a == b,
                        _ => false,
                    };
                    if !target_ok {
                        return false;
                    }
                    if let Some(sn) = pr.section_name.as_deref()
                        && sn != listener.name
                    {
                        return false;
                    }
                    if let Some(port) = pr.port
                        && port as u16 != listener_port
                    {
                        return false;
                    }
                    true
                });
                if !binds {
                    continue;
                }

                let route_hostnames: Vec<&str> =
                    route.spec.hostnames.iter().map(String::as_str).collect();
                if !hostnames_intersect(&route_hostnames, listener_hostname) {
                    continue;
                }

                // Effective SNI patterns: intersection of route hostnames and listener hostname.
                let effective: Vec<String> = if route_hostnames.is_empty() {
                    if listener_hostname.is_empty() {
                        vec![String::new()]
                    } else {
                        vec![listener_hostname.to_string()]
                    }
                } else if listener_hostname.is_empty() {
                    route_hostnames.iter().map(|s| s.to_string()).collect()
                } else {
                    route_hostnames
                        .iter()
                        .filter(|rh| hostnames_intersect(&[rh], listener_hostname))
                        .map(|rh| {
                            // The more-specific hostname is the effective SNI pattern.
                            if rh.starts_with("*.") && !listener_hostname.starts_with("*.") {
                                listener_hostname.to_string()
                            } else if rh.starts_with("*.")
                                && listener_hostname.starts_with("*.")
                                && listener_hostname.len() > rh.len()
                            {
                                // Both wildcards: the listener is more specific
                                // (longer suffix) → use the listener hostname.
                                listener_hostname.to_string()
                            } else {
                                rh.to_string()
                            }
                        })
                        .collect()
                };

                for rule in &route.spec.rules {
                    let weighted: Vec<(Vec<std::net::SocketAddr>, u16)> = rule
                        .backend_refs
                        .iter()
                        .filter_map(|b| {
                            let port = b.port?;
                            let weight = b.weight.unwrap_or(1);
                            if weight <= 0 {
                                return None;
                            }
                            let b_kind = b.kind.as_deref().unwrap_or("Service");
                            let b_group = b.group.as_deref().unwrap_or("");
                            if b_kind != "Service" || (!b_group.is_empty() && b_group != "core") {
                                return None;
                            }
                            let ns = b.namespace.as_deref().unwrap_or(route_ns);
                            if ns != route_ns
                                && !reference_grants::backend_ref_allowed(
                                    route_ns,
                                    ns,
                                    &b.name,
                                    backend_grants,
                                )
                            {
                                tracing::warn!(
                                    route_ns,
                                    backend_ns = ns,
                                    backend_svc = %b.name,
                                    "TLSRoute cross-namespace backendRef denied — no ReferenceGrant"
                                );
                                return None;
                            }
                            let resolved = endpoints::resolve(
                                ns,
                                &b.name,
                                port,
                                stores.slices,
                                stores.services,
                            );
                            Some((resolved.addrs, weight as u16))
                        })
                        .collect();

                    let group_name = rule
                        .backend_refs
                        .first()
                        .map(|b| b.name.clone())
                        .unwrap_or_default();
                    let bg = Arc::new(BackendGroup::weighted(group_name, weighted));

                    for hostname in &effective {
                        builder = builder.add_route(bind_port, hostname, Arc::clone(&bg));
                    }
                }
            }
        }
    }

    out.store(Arc::new(builder.build()));
    // Pass the effective set so a TLSRoute attached to a ListenerSet's
    // TLS/Passthrough listener (`parentRef.kind: ListenerSet`, GEP-1713) is keyed
    // under the ListenerSet and evaluated for Accepted/ResolvedRefs against its
    // listeners — matching the routing entries built above.
    TlsRouteReconciler::compute_route_health(
        &tls_routes,
        &gateways,
        owned_gateways,
        effective,
        backend_grants,
        stores.services,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gw_types::TlsRoute;
    use crate::gw_types::v::grpcroutes::{GrpcRouteParentRefs, GrpcRouteSpec};
    use crate::gw_types::v::httproutes::{HttpRouteParentRefs, HttpRouteSpec};
    use crate::gw_types::v::tlsroutes::{TlsRouteParentRefs, TlsRouteSpec};
    use kube::api::ObjectMeta;

    /// One Gateway-owned listener entry; `hostname == ""` matches all route hostnames.
    fn listener(
        name: &str,
        tls_outcome: ListenerTlsOutcome,
        port: u16,
    ) -> (ListenerHealthKey, ListenerInfo) {
        let mut info = ListenerInfo::default();
        info.tls_outcome = tls_outcome;
        info.port = port;
        (ListenerHealthKey::gateway(name), info)
    }

    /// A single-Gateway health map keyed `default/gw`.
    fn health(
        listeners: Vec<(ListenerHealthKey, ListenerInfo)>,
    ) -> HashMap<ObjectKey, GatewayListenerHealth> {
        let mut gw = GatewayListenerHealth::default();
        gw.listeners = listeners.into_iter().collect();
        std::iter::once((ObjectKey::new("default", "gw"), gw)).collect()
    }

    fn owned() -> HashSet<ObjectKey> {
        std::iter::once(ObjectKey::new("default", "gw")).collect()
    }

    fn http_route() -> Arc<HttpRoute> {
        Arc::new(HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(vec![HttpRouteParentRefs {
                    name: "gw".to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn grpc_route() -> Arc<GrpcRoute> {
        Arc::new(GrpcRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GrpcRouteSpec {
                parent_refs: Some(vec![GrpcRouteParentRefs {
                    name: "gw".to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn tls_route() -> Arc<TlsRoute> {
        Arc::new(TlsRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TlsRouteSpec {
                parent_refs: Some(vec![TlsRouteParentRefs {
                    name: "gw".to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn attached(map: &HashMap<ObjectKey, GatewayListenerHealth>, name: &str) -> i32 {
        map[&ObjectKey::new("default", "gw")].listeners[&ListenerHealthKey::gateway(name)]
            .attached_routes
    }

    #[test]
    fn grpc_route_increments_attached_routes_on_http_listener() {
        let mut map = health(vec![listener(
            "http",
            ListenerTlsOutcome::NotApplicable,
            80,
        )]);
        count_attached_routes(&[grpc_route()], &owned(), &HashMap::new(), &mut map, false);
        assert_eq!(
            attached(&map, "http"),
            1,
            "GRPCRoute must be counted against its HTTP listener"
        );
    }

    #[test]
    fn tls_route_increments_attached_routes_on_passthrough_listener() {
        let mut map = health(vec![listener(
            "tls",
            ListenerTlsOutcome::TlsPassthrough,
            443,
        )]);
        count_attached_routes(&[tls_route()], &owned(), &HashMap::new(), &mut map, true);
        assert_eq!(
            attached(&map, "tls"),
            1,
            "TLSRoute must be counted against its passthrough listener"
        );
    }

    #[test]
    fn tls_route_not_counted_against_terminate_listener() {
        let mut map = health(vec![listener("https", ListenerTlsOutcome::Resolved, 443)]);
        count_attached_routes(&[tls_route()], &owned(), &HashMap::new(), &mut map, true);
        assert_eq!(
            attached(&map, "https"),
            0,
            "TLSRoute must never attach to a TLS-terminate listener"
        );
    }

    #[test]
    fn http_route_not_counted_against_passthrough_listener() {
        let mut map = health(vec![listener(
            "tls",
            ListenerTlsOutcome::TlsPassthrough,
            443,
        )]);
        count_attached_routes(&[http_route()], &owned(), &HashMap::new(), &mut map, false);
        assert_eq!(
            attached(&map, "tls"),
            0,
            "HTTPRoute must never attach to a passthrough listener"
        );
    }

    /// A `TLSRoute` whose `parentRef.kind: ListenerSet` targets a passthrough
    /// listener declared on a ListenerSet (GEP-1713) — the listener health lives
    /// under the parent Gateway's key but is provenance-keyed to the ListenerSet,
    /// so it must be counted there and NOT against a same-named Gateway listener.
    #[test]
    fn tls_route_attaches_to_listener_set_passthrough_listener() {
        let ls_key = ObjectKey::new("default", "ls");
        // Parent Gateway health holds two same-named "tls" passthrough listeners:
        // one its own, one belonging to the ListenerSet.
        let mut gw = GatewayListenerHealth::default();
        let mut gw_info = ListenerInfo::default();
        gw_info.tls_outcome = ListenerTlsOutcome::TlsPassthrough;
        gw_info.port = 443;
        let mut ls_info = ListenerInfo::default();
        ls_info.tls_outcome = ListenerTlsOutcome::TlsPassthrough;
        ls_info.port = 8443;
        gw.listeners = [
            (ListenerHealthKey::gateway("tls"), gw_info),
            (
                ListenerHealthKey::listener_set(ls_key.clone(), "tls"),
                ls_info,
            ),
        ]
        .into_iter()
        .collect();
        let mut map: HashMap<ObjectKey, GatewayListenerHealth> =
            std::iter::once((ObjectKey::new("default", "gw"), gw)).collect();

        let route = Arc::new(TlsRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TlsRouteSpec {
                parent_refs: Some(vec![TlsRouteParentRefs {
                    group: Some("gateway.networking.k8s.io".to_string()),
                    kind: Some("ListenerSet".to_string()),
                    name: "ls".to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        });

        let ls_parent: HashMap<ObjectKey, ObjectKey> =
            std::iter::once((ls_key.clone(), ObjectKey::new("default", "gw"))).collect();
        count_attached_routes(&[route], &owned(), &ls_parent, &mut map, true);

        let gw_health = &map[&ObjectKey::new("default", "gw")];
        assert_eq!(
            gw_health.listeners[&ListenerHealthKey::listener_set(ls_key, "tls")].attached_routes,
            1,
            "TLSRoute via parentRef.kind: ListenerSet must attach to the ListenerSet's listener"
        );
        assert_eq!(
            gw_health.listeners[&ListenerHealthKey::gateway("tls")].attached_routes,
            0,
            "the same-named Gateway listener must NOT absorb a ListenerSet-targeted TLSRoute"
        );
    }

    /// A TLSRoute attached to a ListenerSet passthrough listener that LOST a
    /// port-compatibility conflict must NOT be marked `Accepted` — the listener is
    /// not programmed, so advertising Accepted would black-hole. Regression for the
    /// route-health/routing-table consistency gap (the routing builder skips
    /// conflicted listeners; route-health must too).
    #[test]
    fn tls_route_on_conflicted_listener_set_listener_is_not_accepted() {
        use crate::gw_types::v::gateways::{Gateway, GatewaySpec};
        use crate::keys::RouteParentKey;
        use crate::reconciler::listener_merge::{
            EffectiveGateway, EffectiveListener, EffectiveTls,
        };

        let gw_key = ObjectKey::new("default", "gw");
        let ls_key = ObjectKey::new("default", "ls");

        let gw = Arc::new(Gateway {
            metadata: ObjectMeta {
                name: Some("gw".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".to_string(),
                ..Default::default()
            },
            status: None,
        });

        // The ListenerSet's only passthrough listener is conflicted (lost the port).
        let conflicted = EffectiveListener {
            source: ListenerSource::ListenerSet(ls_key.clone()),
            owning_namespace: "default".to_string(),
            name: "ls-web".to_string(),
            port: 443,
            protocol: "TLS".to_string(),
            hostname: None,
            tls: Some(EffectiveTls {
                passthrough: true,
                certificate_refs: vec![],
            }),
            allows_all_namespaces: false,
            allowed_route_kinds: vec![],
            conflicted: true,
        };
        let effective: HashMap<ObjectKey, EffectiveGateway> = std::iter::once((
            gw_key.clone(),
            EffectiveGateway {
                gateway: Arc::clone(&gw),
                listeners: vec![conflicted],
            },
        ))
        .collect();

        let route = Arc::new(TlsRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: TlsRouteSpec {
                parent_refs: Some(vec![TlsRouteParentRefs {
                    group: Some("gateway.networking.k8s.io".to_string()),
                    kind: Some("ListenerSet".to_string()),
                    name: "ls".to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        });

        let mut svc =
            kube::runtime::reflector::store::Writer::<k8s_openapi::api::core::v1::Service>::default(
            );
        svc.apply_watcher_event(&kube::runtime::watcher::Event::InitDone);
        let services = svc.as_reader();

        let map = TlsRouteReconciler::compute_route_health(
            &[route],
            &[gw],
            &owned(),
            &effective,
            &HashSet::new(),
            &services,
        );

        let h = map
            .get(&RouteParentKey::new(
                "default",
                "route",
                "default",
                "ls",
                String::new(),
            ))
            .expect("health entry for the (route, ListenerSet) pair");
        assert!(
            !h.accepted,
            "TLSRoute on a conflicted ListenerSet listener must not be Accepted"
        );
        assert_eq!(h.accepted_reason, "NoMatchingParent");
    }
}
