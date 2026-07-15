//! Decides which `(port, host)` routing-table partitions need recompiling
//! this rebuild, and which routes must be re-translated to do so (#511).
//!
//! [`plan`] replays the cheap attachment pass
//! (`gateway_api::compute_listener_bindings` /
//! `compute_grpc_listener_bindings`) for every route — no translation, no
//! endpoint resolution — to learn which `(port, host)` partitions each route
//! contributes to, then folds each route's
//! [`gateway_api::http_route_fingerprint`]/`grpc_route_fingerprint` into
//! every partition it binds to. A partition's fingerprint is therefore an
//! XOR-fold over exactly the routes bound to it: unrelated routes on other
//! partitions can never move it, and any change to a bound route (or a
//! dependency `route_fingerprint` tracks) always does.
//!
//! `global_epoch` (see [`super::cache`]) is folded into every partition
//! identically, so a change to the sources `route_fingerprint` can't
//! precisely attribute (targetRef-based policy attachment, a one-hop CR
//! reference) marks the whole table dirty for one pass rather than risking a
//! partition wrongly believing itself unaffected.
//!
//! A route with zero bindings this rebuild (unowned parentRef, no matching
//! listener) contributes to no partition and is skipped entirely — it was
//! already skipped by `reconcile` itself in the full-rebuild world, so this
//! changes nothing about *what* gets routed, only *when* the work happens.

use super::cache::{PartitionCache, PartitionKey};
use crate::MergedStore;
use crate::endpoints::pool::EndpointCache;
use crate::gateway_api::{
    self, GrpcRouteResolution, ListenerBinding, RouteResolution, compute_grpc_listener_bindings,
    compute_listener_bindings,
};
use crate::gw_types::{GrpcRoute, HttpRoute};
use crate::keys::ListenerKey;
use k8s_openapi::api::core::v1::Service;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Bundles [`plan`]'s inputs — kept under the workspace's 7-argument function
/// threshold, mirroring [`RouteResolution`]'s own rationale.
pub(crate) struct GatewayPartitionInputs<'a> {
    pub(crate) routes: &'a [Arc<HttpRoute>],
    pub(crate) grpc_routes: &'a [Arc<GrpcRoute>],
    pub(crate) listener_info: &'a HashMap<ListenerKey, ListenerBinding>,
    pub(crate) endpoint_cache: &'a EndpointCache,
    pub(crate) services: &'a MergedStore<Service>,
    pub(crate) resolution: &'a RouteResolution<'a>,
    pub(crate) grpc_resolution: &'a GrpcRouteResolution<'a>,
    pub(crate) global_epoch: u64,
}

/// Which `(port, host)` partitions changed this rebuild, and which routes
/// must be re-translated to recompute them.
pub(crate) struct GatewayPartitionPlan {
    /// Every partition observed this rebuild (from any route's bindings),
    /// mapped to its freshly-computed fingerprint. This is the authoritative
    /// "live partition" set for final-table assembly — a partition absent
    /// here has zero routes bound to it this rebuild and must not appear in
    /// the published table, however it was cached before.
    pub(crate) fingerprints: HashMap<PartitionKey, u64>,
    /// Subset of `fingerprints`' keys whose fingerprint differs from the
    /// cache (or is new) — these must come from a freshly-built
    /// `HostRouterBuilder` this pass, not the cache.
    pub(crate) dirty: HashSet<PartitionKey>,
    /// Indices into `inputs.routes` bound to at least one dirty partition —
    /// only these need `GatewayApiReconciler::reconcile` re-run. A route
    /// bound only to clean partitions is not re-translated at all.
    pub(crate) dirty_http: HashSet<usize>,
    /// Indices into `inputs.grpc_routes`, same meaning.
    pub(crate) dirty_grpc: HashSet<usize>,
}

/// Computes the plan. `cache` is read-only here — [`super::route_builder`]
/// updates it after assembling the final table, once the freshly-built
/// `Arc<HostRouter>`s for dirty partitions actually exist.
pub(crate) fn plan(
    inputs: &GatewayPartitionInputs<'_>,
    cache: &PartitionCache,
) -> GatewayPartitionPlan {
    let mut partition_fp: HashMap<PartitionKey, u64> = HashMap::new();
    let mut http_members: HashMap<PartitionKey, Vec<usize>> = HashMap::new();
    let mut grpc_members: HashMap<PartitionKey, Vec<usize>> = HashMap::new();

    fold_route_set(
        inputs.routes,
        &mut partition_fp,
        &mut http_members,
        |route| {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
            let hostnames: Vec<&str> = route
                .spec
                .hostnames
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(String::as_str)
                .collect();
            compute_listener_bindings(
                &hostnames,
                route.spec.parent_refs.as_deref().unwrap_or(&[]),
                route_ns,
                inputs.listener_info,
            )
        },
        |route| {
            gateway_api::http_route_fingerprint(
                route,
                inputs.endpoint_cache,
                inputs.services,
                inputs.resolution,
            )
        },
    );

    fold_route_set(
        inputs.grpc_routes,
        &mut partition_fp,
        &mut grpc_members,
        |route| {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
            let hostnames: Vec<&str> = route
                .spec
                .hostnames
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(String::as_str)
                .collect();
            compute_grpc_listener_bindings(
                &hostnames,
                route.spec.parent_refs.as_deref().unwrap_or(&[]),
                route_ns,
                inputs.listener_info,
            )
        },
        |route| {
            gateway_api::grpc_route_fingerprint(
                route,
                inputs.endpoint_cache,
                inputs.services,
                inputs.grpc_resolution,
            )
        },
    );

    let mut fingerprints = HashMap::with_capacity(partition_fp.len());
    let mut dirty = HashSet::new();
    let mut dirty_http = HashSet::new();
    let mut dirty_grpc = HashSet::new();

    for (key, route_fp) in partition_fp {
        let final_fp = route_fp ^ inputs.global_epoch;
        let is_dirty = cache.get(&key, final_fp).is_none();
        if is_dirty {
            if let Some(members) = http_members.get(&key) {
                dirty_http.extend(members.iter().copied());
            }
            if let Some(members) = grpc_members.get(&key) {
                dirty_grpc.extend(members.iter().copied());
            }
            dirty.insert(key.clone());
        }
        fingerprints.insert(key, final_fp);
    }

    GatewayPartitionPlan {
        fingerprints,
        dirty,
        dirty_http,
        dirty_grpc,
    }
}

/// Folds one route set's fingerprints into the partition map — the single
/// attribution rule shared by the HTTP and gRPC passes above, so a change to
/// it (how zero-binding routes are skipped, how contributions combine) can
/// never apply to one route type and not the other.
///
/// Per route: compute bindings (empty → the route contributes to no
/// partition, exactly as `reconcile` itself would skip it); compute the
/// fingerprint only for bound routes; `wrapping_add` it into every bound
/// partition (not XOR — two routes on one partition with equal fingerprints
/// would XOR-cancel, hiding both from dirtiness; see
/// [`crate::fingerprint::FingerprintAccumulator`]).
fn fold_route_set<R>(
    routes: &[Arc<R>],
    partition_fp: &mut HashMap<PartitionKey, u64>,
    members: &mut HashMap<PartitionKey, Vec<usize>>,
    bindings_of: impl Fn(&R) -> Vec<(Option<String>, u16)>,
    fingerprint_of: impl Fn(&R) -> u64,
) {
    for (i, route) in routes.iter().enumerate() {
        let bindings = bindings_of(route);
        if bindings.is_empty() {
            continue;
        }
        let fp = fingerprint_of(route);
        for (hostname_opt, port) in bindings {
            let key: PartitionKey = (port, hostname_opt);
            let slot = partition_fp.entry(key.clone()).or_insert(0);
            *slot = slot.wrapping_add(fp);
            members.entry(key).or_default().push(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gw_types::v::httproutes::{
        HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteSpec,
    };
    use crate::tests::fixtures::{empty_svc_store, endpoint_cache};
    use kube::api::ObjectMeta;

    fn route(ns: &str, hostnames: &[&str], svc: &str, resource_version: &str) -> HttpRoute {
        HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some(ns.to_string()),
                resource_version: Some(resource_version.to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(vec![HttpRouteParentRefs {
                    name: "gw".to_string(),
                    namespace: Some(ns.to_string()),
                    ..Default::default()
                }]),
                hostnames: Some(hostnames.iter().map(|h| h.to_string()).collect()),
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: svc.to_string(),
                        port: Some(80),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
            },
            ..Default::default()
        }
    }

    fn listener_info(
        ns: &str,
        listener_name: &str,
        hostname: &str,
        port: u16,
    ) -> HashMap<ListenerKey, ListenerBinding> {
        HashMap::from([(
            ListenerKey::new(ns, "gw", listener_name),
            ListenerBinding {
                hostname: hostname.to_string(),
                port,
                bind_port: port,
                route_namespaces: coxswain_core::listener_status::RouteNamespaceSet::All,
            },
        )])
    }

    /// Builds a `RouteResolution` with every store empty — these tests only
    /// exercise attachment + endpoint dependency tracking, no ExtensionRefs.
    macro_rules! empty_resolution {
        () => {
            RouteResolution {
                listener_info: &HashMap::new(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &crate::tests::fixtures::empty_rate_limit_store(),
                retry_policies: &crate::tests::fixtures::empty_retry_policy_store(),
                path_rewrites: &crate::tests::fixtures::empty_path_rewrite_store(),
                ip_access: &crate::tests::fixtures::empty_ip_access_store(),
                basic_auths: &crate::tests::fixtures::empty_basic_auth_store(),
                external_auths: &crate::tests::fixtures::empty_external_auth_store(),
                external_auth_gateway_index: &HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &crate::tests::fixtures::empty_secret_store(),
                basic_auth_secret_grants: &HashSet::new(),
                request_size_limits: &crate::tests::fixtures::empty_request_size_limit_store(),
                compressions: &crate::tests::fixtures::empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            }
        };
    }
    macro_rules! empty_grpc_resolution {
        () => {
            GrpcRouteResolution {
                listener_info: &HashMap::new(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &crate::tests::fixtures::empty_rate_limit_store(),
                retry_policies: &crate::tests::fixtures::empty_retry_policy_store(),
                ip_access: &crate::tests::fixtures::empty_ip_access_store(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
            }
        };
    }

    #[test]
    fn two_routes_on_different_hosts_yield_two_independent_partitions() {
        let a = route("ns", &["a.example.com"], "svc-a", "1");
        let b = route("ns", &["b.example.com"], "svc-b", "1");
        let li_a = listener_info("ns", "l1", "a.example.com", 80);
        let li_b = listener_info("ns", "l2", "b.example.com", 80);
        let mut listener_info_map = li_a;
        listener_info_map.extend(li_b);
        let cache = endpoint_cache(vec![]);
        let svcs = empty_svc_store();
        let resolution = empty_resolution!();
        let grpc_resolution = empty_grpc_resolution!();

        let routes = vec![Arc::new(a), Arc::new(b)];
        let grpc_routes: Vec<Arc<GrpcRoute>> = vec![];
        let cache_store = PartitionCache::default();
        let plan = plan(
            &GatewayPartitionInputs {
                routes: &routes,
                grpc_routes: &grpc_routes,
                listener_info: &listener_info_map,
                endpoint_cache: &cache,
                services: &svcs,
                resolution: &resolution,
                grpc_resolution: &grpc_resolution,
                global_epoch: 0,
            },
            &cache_store,
        );

        assert_eq!(
            plan.fingerprints.len(),
            2,
            "two distinct hosts → two partitions"
        );
        assert_eq!(plan.dirty.len(), 2, "both new (uncached) → both dirty");
        assert_eq!(plan.dirty_http, HashSet::from([0, 1]));
    }

    #[test]
    fn changing_one_route_dirties_only_its_own_partition() {
        let a = route("ns", &["a.example.com"], "svc-a", "1");
        let b = route("ns", &["b.example.com"], "svc-b", "1");
        let mut listener_info_map = listener_info("ns", "l1", "a.example.com", 80);
        listener_info_map.extend(listener_info("ns", "l2", "b.example.com", 80));
        let cache = endpoint_cache(vec![]);
        let svcs = empty_svc_store();
        let resolution = empty_resolution!();
        let grpc_resolution = empty_grpc_resolution!();
        let grpc_routes: Vec<Arc<GrpcRoute>> = vec![];

        // First pass: seed the cache with both partitions clean.
        let routes_v1 = vec![Arc::new(a.clone()), Arc::new(b.clone())];
        let mut cache_store = PartitionCache::default();
        let plan1 = plan(
            &GatewayPartitionInputs {
                routes: &routes_v1,
                grpc_routes: &grpc_routes,
                listener_info: &listener_info_map,
                endpoint_cache: &cache,
                services: &svcs,
                resolution: &resolution,
                grpc_resolution: &grpc_resolution,
                global_epoch: 0,
            },
            &cache_store,
        );
        for (key, fp) in &plan1.fingerprints {
            cache_store.insert(key.clone(), *fp, dummy_router(), Vec::new());
        }

        // Second pass: only route `a` changes (new resourceVersion).
        let mut a_v2 = a.clone();
        a_v2.metadata.resource_version = Some("2".to_string());
        let routes_v2 = vec![Arc::new(a_v2), Arc::new(b)];
        let plan2 = plan(
            &GatewayPartitionInputs {
                routes: &routes_v2,
                grpc_routes: &grpc_routes,
                listener_info: &listener_info_map,
                endpoint_cache: &cache,
                services: &svcs,
                resolution: &resolution,
                grpc_resolution: &grpc_resolution,
                global_epoch: 0,
            },
            &cache_store,
        );

        assert_eq!(
            plan2.dirty.len(),
            1,
            "only route a's own partition is dirty"
        );
        assert_eq!(
            plan2.dirty_http,
            HashSet::from([0]),
            "only index 0 (route a) is re-translated"
        );
    }

    #[test]
    fn global_epoch_change_dirties_every_partition() {
        let a = route("ns", &["a.example.com"], "svc-a", "1");
        let b = route("ns", &["b.example.com"], "svc-b", "1");
        let mut listener_info_map = listener_info("ns", "l1", "a.example.com", 80);
        listener_info_map.extend(listener_info("ns", "l2", "b.example.com", 80));
        let cache = endpoint_cache(vec![]);
        let svcs = empty_svc_store();
        let resolution = empty_resolution!();
        let grpc_resolution = empty_grpc_resolution!();
        let grpc_routes: Vec<Arc<GrpcRoute>> = vec![];
        let routes = vec![Arc::new(a), Arc::new(b)];

        let mut cache_store = PartitionCache::default();
        let plan1 = plan(
            &GatewayPartitionInputs {
                routes: &routes,
                grpc_routes: &grpc_routes,
                listener_info: &listener_info_map,
                endpoint_cache: &cache,
                services: &svcs,
                resolution: &resolution,
                grpc_resolution: &grpc_resolution,
                global_epoch: 0,
            },
            &cache_store,
        );
        for (key, fp) in &plan1.fingerprints {
            cache_store.insert(key.clone(), *fp, dummy_router(), Vec::new());
        }

        // Same routes, but the global epoch moved (e.g. a BasicAuth secret rotated).
        let plan2 = plan(
            &GatewayPartitionInputs {
                routes: &routes,
                grpc_routes: &grpc_routes,
                listener_info: &listener_info_map,
                endpoint_cache: &cache,
                services: &svcs,
                resolution: &resolution,
                grpc_resolution: &grpc_resolution,
                global_epoch: 42,
            },
            &cache_store,
        );

        assert_eq!(
            plan2.dirty.len(),
            2,
            "global epoch change dirties every partition"
        );
    }

    #[test]
    fn unowned_route_contributes_to_no_partition() {
        // No listener_info at all — compute_listener_bindings' fallback still
        // yields a binding (port 80 catchall) when listener_info is EMPTY
        // (tests/misconfigured convention), so use a non-matching hostname
        // against a populated listener_info instead to get a genuine
        // zero-binding route.
        let a = route("ns", &["nomatch.example.com"], "svc-a", "1");
        let listener_info_map = listener_info("ns", "l1", "a.example.com", 80);
        let cache = endpoint_cache(vec![]);
        let svcs = empty_svc_store();
        let resolution = empty_resolution!();
        let grpc_resolution = empty_grpc_resolution!();
        let grpc_routes: Vec<Arc<GrpcRoute>> = vec![];
        let routes = vec![Arc::new(a)];
        let cache_store = PartitionCache::default();

        let plan_result = plan(
            &GatewayPartitionInputs {
                routes: &routes,
                grpc_routes: &grpc_routes,
                listener_info: &listener_info_map,
                endpoint_cache: &cache,
                services: &svcs,
                resolution: &resolution,
                grpc_resolution: &grpc_resolution,
                global_epoch: 0,
            },
            &cache_store,
        );

        assert!(
            plan_result.fingerprints.is_empty(),
            "a route with zero listener matches must contribute to no partition"
        );
        assert!(plan_result.dirty_http.is_empty());
    }

    /// `HostRouterBuilder::build` is `pub(crate)` to `coxswain-core` — build a
    /// throwaway single-host table via the public `RoutingTableBuilder` path
    /// instead and extract its compiled `Arc<HostRouter>`.
    fn dummy_router() -> Arc<coxswain_core::routing::HostRouter> {
        let mut builder = coxswain_core::routing::GatewayRoutingTableBuilder::new();
        builder.for_port(80).exact_host("dummy");
        let table = builder.build().expect("empty router builds cleanly");
        table
            .get_compiled(
                80,
                Some("dummy"),
                coxswain_core::routing::WildcardKind::MultiLabel,
            )
            .expect("just-inserted host is present")
    }
}
