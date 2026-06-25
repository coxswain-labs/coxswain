//! Routing-table and TLS-store builders driven by the [`super::proxy`] rebuild
//! loop. The orchestration (debounce, leader gating, dedicated-path management)
//! stays in `proxy.rs`; this module owns the pure "snapshot → table/store +
//! health" build steps it calls, communicating via the parameter-group DTOs
//! ([`ReflectorStores`], [`Ownership`], [`SharedOutputs`], [`IngressBuildConfig`])
//! defined alongside the loop.

use super::proxy::{
    IngressBuildConfig, IngressDefaultBackend, IngressEvent, Ownership, ReflectorStores,
    SharedOutputs, gateway_is_cut_over,
};
use crate::endpoints;
use crate::gateway_api::hostnames_intersect;
use crate::gateway_api::{
    GatewayApiReconciler, GrpcRouteReconciler, GrpcRouteResolution, ListenerBinding,
};
use crate::gw_types::{GrpcRoute, HttpRoute};
use crate::ingress::annotations::AnnotationIssue;
use crate::ingress::{IngressClassContext, IngressPorts, IngressReconciler, resolve_class_params};
use crate::keys::ListenerKey;
use crate::tls::GatewayListenerHealth;
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{
    BackendGroup, GatewayRoutingTableBuilder, IngressRoutingTableBuilder, RouteEntry, RoutingTable,
    RoutingTableBuilder, SharedGatewayRoutingTable, SharedIngressRoutingTable,
};
use coxswain_core::shared::Shared;
use coxswain_core::tls::{
    ClientCertStoreBuilder, ListenerHostnamesBuilder, SharedClientCertStore,
    SharedListenerHostnames, SharedTlsStore, TlsStoreBuilder,
};
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
    // Precompute ListenerKey → (hostname, port) from all owned gateway
    // listeners.
    let listener_info: HashMap<ListenerKey, ListenerBinding> = stores
        .gateways
        .state()
        .into_iter()
        .filter(|g| {
            ownership
                .gateway_classes
                .contains(&g.spec.gateway_class_name)
        })
        .filter(|g| !(skip_cut_over && gateway_is_cut_over(g)))
        .flat_map(|g| {
            let ns = g.metadata.namespace.clone().unwrap_or_default();
            let name = g.metadata.name.clone().unwrap_or_default();
            g.spec.listeners.clone().into_iter().map(move |l| {
                let key = ListenerKey::new(ns.clone(), name.clone(), l.name);
                let binding = ListenerBinding {
                    hostname: l.hostname.unwrap_or_default(),
                    port: l.port as u16,
                };
                (key, binding)
            })
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
    tls_shared: &SharedTlsStore,
    listener_hostnames_shared: &SharedListenerHostnames,
    skip_cut_over: bool,
) -> HashMap<ObjectKey, GatewayListenerHealth> {
    let mut tls_builder = TlsStoreBuilder::new();
    for ingress in ingresses {
        IngressReconciler::reconcile_tls(
            ingress,
            stores.secrets,
            ownership.ingress_classes,
            ownership.default_ingress_class,
            &mut tls_builder,
        );
    }

    let mut lh_builder = ListenerHostnamesBuilder::new();
    let mut gateway_tls_health: HashMap<ObjectKey, GatewayListenerHealth> = HashMap::new();
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
        let health = GatewayApiReconciler::reconcile_tls(
            &gw,
            stores.secrets,
            ownership.cert_grants,
            &mut tls_builder,
        );
        // Populate the per-port listener-hostname snapshot for
        // misdirected-request detection (GEP-3567, #96). Only
        // HTTPS-terminating listeners (Resolved cert) contribute.
        for li in health.listeners.values() {
            lh_builder.add_listener(li.port, &li.hostname, li.tls_outcome.is_https_terminate());
        }
        gateway_tls_health.insert(ObjectKey::new(ns, name), health);
    }

    let tls_store = tls_builder.build();
    let certs = tls_store.cert_count();
    let current = tls_shared.load();
    if *current != tls_store {
        tracing::debug!(certs, "TLS cert store swapped");
        tls_shared.store(Arc::new(tls_store));
    } else {
        tracing::trace!(certs, "TLS cert store unchanged, skip swap");
    }

    let lh = lh_builder.build();
    let current_lh = listener_hostnames_shared.load();
    if *current_lh != lh {
        tracing::debug!("listener-hostnames snapshot swapped");
        listener_hostnames_shared.store(Arc::new(lh));
    } else {
        tracing::trace!("listener-hostnames snapshot unchanged, skip swap");
    }

    gateway_tls_health
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
/// The function also annotates `gateway_tls_health` with
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
    gateway_tls_health: &mut HashMap<ObjectKey, GatewayListenerHealth>,
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
        let health = gateway_tls_health.entry(key).or_default();
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

/// Increment `attached_routes` counters for each gateway listener whose hostname
/// intersects with the route's hostnames. Only owned gateways are counted.
pub(super) fn count_attached_routes(
    routes: &[Arc<HttpRoute>],
    owned_gateways: &HashSet<ObjectKey>,
    gateway_tls_health: &mut HashMap<ObjectKey, GatewayListenerHealth>,
) {
    for route in routes {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let route_hostnames: Vec<&str> = route
            .spec
            .hostnames
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();

        for pr in route.spec.parent_refs.as_deref().unwrap_or(&[]) {
            let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
            let gw_name = pr.name.as_str();
            let key = ObjectKey::new(gw_ns, gw_name);
            if !owned_gateways.contains(&key) {
                continue;
            }
            if let Some(health) = gateway_tls_health.get_mut(&key) {
                let pr_port = pr.port.map(|p| p as u16);
                if let Some(sn) = pr.section_name.as_deref() {
                    let Some(info) = health.listeners.get_mut(sn) else {
                        continue;
                    };
                    if gw_ns != route_ns && !info.allows_all_namespaces {
                        continue;
                    }
                    if let Some(port) = pr_port
                        && info.port != port
                    {
                        continue;
                    }
                    if hostnames_intersect(&route_hostnames, &info.hostname) {
                        info.attached_routes += 1;
                    }
                } else {
                    let listener_names: Vec<String> = health.listeners.keys().cloned().collect();
                    for ln in listener_names {
                        let Some(info) = health.listeners.get_mut(&ln) else {
                            continue;
                        };
                        if let Some(p) = pr_port
                            && info.port != p
                        {
                            continue;
                        }
                        if gw_ns != route_ns && !info.allows_all_namespaces {
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
