//! Core Ingress reconciliation: maps rules to routing-table entries.

use super::IngressReconciler;
use super::backend::resolve_backend_port;
use super::class::claimed_ingress_class;
use super::ports::IngressPorts;
use crate::endpoints;
use crate::k8s_utils::metadata_created_at;
use coxswain_core::routing::{BackendGroup, RouteEntry, RoutingTableBuilder, WildcardKind};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::sync::Arc;

impl IngressReconciler {
    /// Skips the Ingress when it does not reference an owned IngressClass.
    /// When `owned_default_class` is `Some`, an Ingress with neither
    /// `spec.ingressClassName` nor the legacy annotation is also claimed.
    /// Never queries the API server.
    ///
    /// Routes are inserted on `http_port` and `https_port` (whichever are `Some`).
    /// When both are `None` the Ingress is skipped with a warning.
    pub fn reconcile(
        ingress: &Ingress,
        slices: &reflector::Store<EndpointSlice>,
        services: &reflector::Store<Service>,
        owned_classes: &HashSet<String>,
        owned_default_class: Option<&str>,
        ports: IngressPorts,
        builder: &mut RoutingTableBuilder,
    ) {
        let claimed_class = claimed_ingress_class(ingress);

        match claimed_class {
            None => match owned_default_class {
                Some(_) => {}
                None => {
                    tracing::debug!(name = ?ingress.metadata.name, "Skipping Ingress — no ingressClassName or annotation");
                    return;
                }
            },
            Some(class) if !owned_classes.contains(class) => {
                tracing::debug!(name = ?ingress.metadata.name, %class, "Skipping Ingress — class not owned by this controller");
                return;
            }
            Some(_) => {}
        }

        let ports: Vec<u16> = [ports.http, ports.https].into_iter().flatten().collect();
        if ports.is_empty() {
            tracing::warn!(
                name = ?ingress.metadata.name,
                "No HTTP or HTTPS listener port configured — skipping Ingress routes"
            );
            return;
        }

        let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");
        let ingress_name = ingress.metadata.name.as_deref().unwrap_or("unknown");
        let route_id = format!("{ns}/{ingress_name}");
        let created_at = metadata_created_at(&ingress.metadata);
        let spec = ingress.spec.as_ref();
        let rules = spec.and_then(|s| s.rules.as_deref()).unwrap_or(&[]);

        tracing::debug!(name = ?ingress.metadata.name, ns, rules = rules.len(), "Reconciling Ingress");

        for rule in rules {
            let http = match rule.http.as_ref() {
                Some(h) => h,
                None => continue,
            };

            for path_rule in &http.paths {
                let svc = match path_rule.backend.service.as_ref() {
                    Some(s) => s,
                    None => {
                        if let Some(resource) = path_rule.backend.resource.as_ref() {
                            tracing::warn!(
                                ingress = %route_id,
                                path = ?path_rule.path,
                                api_group = ?resource.api_group,
                                kind = %resource.kind,
                                name = %resource.name,
                                "Ingress path backend uses Resource type — only Service backends are supported; skipping path"
                            );
                        }
                        continue;
                    }
                };
                let port = match resolve_backend_port(ns, svc, services) {
                    Some(p) => p,
                    None => continue,
                };

                let resolved = endpoints::resolve(ns, &svc.name, port, slices, services);
                if resolved.addrs.is_empty() {
                    tracing::warn!(
                        ingress = ?ingress.metadata.name,
                        svc = %svc.name,
                        "No ready endpoints — skipping path"
                    );
                    continue;
                }
                let protocol = resolved.app_protocol;
                let group = Arc::new(
                    BackendGroup::new(format!("{ns}/{}", svc.name), resolved.addrs)
                        .with_protocol(protocol),
                );
                let path = path_rule.path.as_deref().unwrap_or("/");

                if !path.starts_with('/') {
                    tracing::warn!(
                        ingress = %route_id,
                        host = ?rule.host,
                        path = %path,
                        "Ingress path does not start with '/' — skipping rule"
                    );
                    continue;
                }

                let e = Arc::new(RouteEntry::path_only(group, route_id.clone(), created_at));
                // "Prefix" and "ImplementationSpecific" both map to prefix matching.
                for &listener_port in &ports {
                    let host_builder = builder
                        .for_port(listener_port)
                        .host_for(rule.host.as_deref(), WildcardKind::SingleLabel);
                    match path_rule.path_type.as_str() {
                        "Exact" => {
                            host_builder.add_exact_route(path, Arc::clone(&e));
                        }
                        _ => {
                            host_builder.add_prefix_route(path, Arc::clone(&e));
                        }
                    }
                }
            }
        }

        // Install spec.defaultBackend as prefix "/" on:
        //   - each rule host  → catches path-misses on hosts named in spec.rules
        //   - the catchall    → catches requests to hosts not named in any rule,
        //                       including rules-less Ingresses that claim all traffic
        //
        // Per-rule routes registered above are inserted as exact or as specific
        // prefix paths, so they outrank "/" via matchit's longest-match lookup.
        // The controller-wide --ingress-default-backend uses created_at = None
        // (sorts last), so this per-Ingress entry naturally wins on the catchall.
        if let Some(default_backend) = spec.and_then(|s| s.default_backend.as_ref()) {
            if let Some(default_svc) = default_backend.service.as_ref() {
                if let Some(port) = resolve_backend_port(ns, default_svc, services) {
                    let resolved =
                        endpoints::resolve(ns, &default_svc.name, port, slices, services);
                    if resolved.addrs.is_empty() {
                        tracing::warn!(
                            ingress = ?ingress.metadata.name,
                            svc = %default_svc.name,
                            "No ready endpoints for defaultBackend — skipping"
                        );
                    } else {
                        let protocol = resolved.app_protocol;
                        let group = Arc::new(
                            BackendGroup::new(format!("{ns}/{}", default_svc.name), resolved.addrs)
                                .with_protocol(protocol),
                        );
                        let make_entry = || {
                            Arc::new(RouteEntry::path_only(
                                Arc::clone(&group),
                                route_id.clone(),
                                created_at,
                            ))
                        };
                        for &listener_port in &ports {
                            for rule in rules {
                                builder
                                    .for_port(listener_port)
                                    .host_for(rule.host.as_deref(), WildcardKind::SingleLabel)
                                    .add_prefix_route("/", make_entry());
                            }
                            builder
                                .for_port(listener_port)
                                .host_for(None, WildcardKind::SingleLabel)
                                .add_prefix_route("/", make_entry());
                        }
                    }
                }
            } else if let Some(resource) = default_backend.resource.as_ref() {
                tracing::warn!(
                    ingress = %route_id,
                    api_group = ?resource.api_group,
                    kind = %resource.kind,
                    name = %resource.name,
                    "Ingress defaultBackend uses Resource type — only Service backends are supported; skipping"
                );
            }
        }
    }
}
