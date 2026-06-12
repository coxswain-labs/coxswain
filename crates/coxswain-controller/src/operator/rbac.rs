//! Per-namespace `RoleBinding` and cluster-wide `ClusterRoleBinding`
//! reconciliation for dedicated-mode Gateway proxies (#209, #229).
//!
//! ## Why this module exists
//!
//! Each provisioned dedicated proxy runs as its own `ServiceAccount` in the
//! Gateway's namespace. To serve traffic, the proxy needs `get/list/watch` on
//! `Services`, `EndpointSlices`, `Secrets`, `ConfigMaps`, `HTTPRoutes`,
//! `ReferenceGrants`, `BackendTLSPolicies`, and `Gateways` — but **only** in
//! the namespaces the target Gateway actually routes traffic into. Granting
//! cluster-wide reads regresses the v0.2 least-privilege story for
//! multi-tenant Gateways.
//!
//! For listeners with `allowedRoutes.namespaces.from: All` or `from: Selector`
//! the proxy additionally needs cluster-wide `HTTPRoute` reads (so it can see
//! routes from any namespace) and optionally cluster-wide `Namespace` reads
//! (for future `namespaceSelector` evaluation). These broader grants are
//! derived automatically from the Gateway spec — no separate operator opt-in
//! field is required — via [`derive_proxy_rbac`] and managed as
//! `ClusterRoleBinding`s alongside the per-namespace `RoleBinding`s.
//!
//! ## Naming and labels (no owner references)
//!
//! Per-namespace `RoleBinding`s are named `coxswain-<gw-namespace>-<gw-name>`
//! and carry three labels for reconcile-driven discovery:
//!
//! - `app.kubernetes.io/managed-by: coxswain`
//! - `gateway.networking.k8s.io/gateway-name: <gw-name>` (GEP-1762)
//! - `gateway.coxswain-labs.dev/gateway-namespace: <gw-ns>`
//!
//! Cluster-wide `ClusterRoleBinding`s use the same label set but are named
//! `coxswain-<gw-namespace>-<gw-name>-cluster-wide-routes` and
//! `coxswain-<gw-namespace>-<gw-name>-cluster-wide-namespaces`.
//!
//! **No owner references.** A binding in tenant-b cannot be owner-referenced
//! to a `Gateway` in tenant-a — Kubernetes treats cross-namespace owner refs
//! as orphaned and the GC silently deletes the dependent. All cleanup is
//! reconcile-driven via the label selector above. The finalizer on the parent
//! Gateway guarantees cleanup runs synchronously before the Gateway is removed.
//!
//! ## Desired namespace set
//!
//! [`desired_namespaces_for_gateway`] computes the union of:
//!
//! 1. The Gateway's own namespace (always — Gateway + listener TLS Secrets).
//! 2. Each attached HTTPRoute's own namespace. When `allow_cross_namespace_routes`
//!    is true (any listener has `from: All` or `from: Selector`), routes from
//!    all namespaces are included; otherwise only same-namespace routes qualify.
//! 3. Each cross-namespace `backendRef` target, gated by
//!    [`coxswain_core::reference_grants::backend_ref_allowed`].
//! 4. Each Gateway listener TLS `certificateRef` target, gated by the same
//!    helper for the `Gateway → Secret` flavour of grant.
//!
//! Item 5 ("BackendTLSPolicy `caCertificateRef` target namespaces, cross-ns
//! via `ReferenceGrant`") is a known incomplete edge case. The dedicated
//! proxy will fail to resolve cross-namespace policy CA bundles until a
//! follow-up walks `BackendTLSPolicy` stores and expands the set.
//!
//! The same helper is consumed by the renderer (`super::render`) so the
//! proxy's `--proxy-watch-namespaces` arg list and the controller's binding
//! set are derived from the same computation — they cannot drift.

use coxswain_core::reference_grants::backend_ref_allowed;
use coxswain_reflector::gw_types::HttpRoute;
use coxswain_reflector::gw_types::v::gateways::{
    Gateway, GatewayListenersAllowedRoutesNamespacesFrom as From,
};
use coxswain_reflector::gw_types::v::referencegrants::ReferenceGrant;
use coxswain_reflector::reference_grants::flatten_grants;
use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, RoleBinding, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::reflector::Store;
use kube::{Api, Client};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;

/// Name of the static `ClusterRole` the controller binds in every managed
/// namespace. Defined in `deploy/manifests/dedicated-proxy-clusterrole.yaml`
/// and `charts/coxswain/templates/dedicated-proxy-clusterrole.yaml`. Renaming
/// this constant requires coordinated changes to both YAMLs.
pub(super) const PROXY_CLUSTER_ROLE_NAME: &str = "coxswain-gateway-proxy-reader";

/// `ClusterRole` granting cluster-wide `get/list/watch` on `httproutes`,
/// bound when any listener has `allowedRoutes.namespaces.from: All` or
/// `from: Selector`.
pub(super) const PROXY_CLUSTER_WIDE_ROUTE_ROLE_NAME: &str =
    "coxswain-gateway-proxy-cluster-wide-route-reader";

/// `ClusterRole` granting cluster-wide `get/list/watch` on `namespaces`,
/// bound when any listener has `allowedRoutes.namespaces.from: Selector`.
pub(super) const PROXY_CLUSTER_WIDE_NAMESPACE_ROLE_NAME: &str =
    "coxswain-gateway-proxy-cluster-wide-namespace-reader";

/// RBAC scope derived from the Gateway's listener specs.
///
/// Pure function of the Gateway object — no I/O. `true` means at least one
/// listener declares the corresponding cross-namespace attachment mode, so the
/// controller must provision the matching cluster-wide `ClusterRoleBinding`
/// and pass the corresponding CLI flag to the proxy Deployment.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct DerivedProxyRbac {
    /// Any listener has `allowedRoutes.namespaces.from: All` or `from: Selector`.
    /// Triggers cluster-wide `HTTPRoute` reads and the
    /// `--allow-cluster-wide-route-read` proxy flag.
    pub(super) allow_cluster_wide_route_read: bool,
    /// Any listener has `allowedRoutes.namespaces.from: Selector`.
    /// Triggers cluster-wide `Namespace` reads and the
    /// `--allow-cluster-wide-namespace-read` proxy flag.
    pub(super) allow_cluster_wide_namespace_read: bool,
}

/// Derive the RBAC scope required by the Gateway's listeners.
///
/// OR-folds across all listeners: a single `from: All` listener is enough to
/// set `allow_cluster_wide_route_read`; a single `from: Selector` listener
/// sets both flags (cluster-wide routes AND namespaces are needed to evaluate
/// the selector against route namespaces).
#[must_use]
pub(super) fn derive_proxy_rbac(gateway: &Gateway) -> DerivedProxyRbac {
    let mut result = DerivedProxyRbac::default();
    for listener in &gateway.spec.listeners {
        let Some(allowed) = listener.allowed_routes.as_ref() else {
            continue;
        };
        let Some(ns_spec) = allowed.namespaces.as_ref() else {
            continue;
        };
        match ns_spec.from {
            Some(From::All) => result.allow_cluster_wide_route_read = true,
            Some(From::Selector) => {
                result.allow_cluster_wide_route_read = true;
                result.allow_cluster_wide_namespace_read = true;
            }
            _ => {}
        }
    }
    result
}

/// Field manager string used for server-side-apply of every managed
/// `RoleBinding`. Same identifier the rest of the operator uses
/// (see [`super::apply::FIELD_MANAGER`]); pulled into a constant here for
/// independence of `super::apply`'s module-private visibility.
const FIELD_MANAGER: &str = "coxswain-controller";

/// Label keys used for reconcile-driven binding discovery.
mod labels {
    /// The K8s-canonical "what owns this object" label, set to `coxswain`.
    pub(super) const MANAGED_BY: &str = "app.kubernetes.io/managed-by";
    /// GEP-1762 — name of the Gateway this binding is owned by.
    pub(super) const GATEWAY_NAME: &str = "gateway.networking.k8s.io/gateway-name";
    /// Coxswain extension — namespace of the Gateway this binding is owned
    /// by. Required because the binding lives in the *target* namespace, not
    /// the Gateway's; combined with [`GATEWAY_NAME`] this disambiguates
    /// same-named Gateways in different namespaces.
    pub(super) const GATEWAY_NAMESPACE: &str = "gateway.coxswain-labs.dev/gateway-namespace";
}

/// Constant value of [`labels::MANAGED_BY`] for bindings this controller
/// owns. Used both when writing the label and when filtering listings.
const MANAGED_BY_VALUE: &str = "coxswain";

/// Errors returned by the binding reconcile + cleanup paths.
///
/// Each variant wraps the underlying [`kube::Error`] so callers can surface
/// the apiserver message. The reconciler converts these into a re-queue via
/// its `error_policy`; the apiserver never sees them.
#[non_exhaustive]
#[derive(Debug, Error)]
pub(super) enum RbacError {
    /// SSA of a `RoleBinding` failed.
    #[error("apply RoleBinding {namespace}/{name}: {source}")]
    Apply {
        /// Target namespace of the apply.
        namespace: String,
        /// Name of the binding.
        name: String,
        /// Underlying apiserver error.
        #[source]
        source: kube::Error,
    },
    /// Delete of a `RoleBinding` failed (not 404 — those are filtered to
    /// `Ok(())`).
    #[error("delete RoleBinding {namespace}/{name}: {source}")]
    Delete {
        /// Namespace of the binding.
        namespace: String,
        /// Name of the binding.
        name: String,
        /// Underlying apiserver error.
        #[source]
        source: kube::Error,
    },
    /// `LIST` of managed bindings (used to compute the actual set) failed.
    #[error("list managed RoleBindings: {0}")]
    List(#[source] kube::Error),
    /// SSA of a `ClusterRoleBinding` failed.
    #[error("apply ClusterRoleBinding {name}: {source}")]
    ApplyClusterBinding {
        /// Name of the cluster-wide binding.
        name: String,
        /// Underlying apiserver error.
        #[source]
        source: kube::Error,
    },
    /// Delete of a `ClusterRoleBinding` failed (not 404 — those are filtered).
    #[error("delete ClusterRoleBinding {name}: {source}")]
    DeleteClusterBinding {
        /// Name of the cluster-wide binding.
        name: String,
        /// Underlying apiserver error.
        #[source]
        source: kube::Error,
    },
}

/// Compute the desired set of namespaces a dedicated Gateway's proxy needs
/// per-namespace reads in.
///
/// Pure function over the reflector store snapshots — easy to unit-test with
/// table-driven fixtures. Reused by both the binding reconciler (to compute
/// the desired binding set) and the proxy-Deployment renderer (to compute
/// the `--proxy-watch-namespaces` arg list).
///
/// `allow_cross_namespace_routes` should be true when any listener has
/// `allowedRoutes.namespaces.from: All` or `from: Selector` — i.e.
/// [`derive_proxy_rbac`]'s `allow_cluster_wide_route_read` flag. When true,
/// routes from all namespaces contribute their backend namespaces to the
/// desired set; when false only same-namespace routes are considered.
///
/// See the module docs for the union sources and the known incomplete edge
/// case around `BackendTLSPolicy` CA ref expansion.
#[must_use]
pub(super) fn desired_namespaces_for_gateway(
    gateway: &Gateway,
    routes_store: &Store<HttpRoute>,
    grants_store: &Store<ReferenceGrant>,
    allow_cross_namespace_routes: bool,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();

    let gw_name = gateway.metadata.name.as_deref().unwrap_or("");
    let gw_namespace = gateway.metadata.namespace.as_deref().unwrap_or("");
    out.insert(gw_namespace.to_string());

    let grants_vec: Vec<Arc<ReferenceGrant>> = grants_store.state();
    let (backend_grants, cert_grants) = flatten_grants(&grants_vec);

    // Listener TLS certRef target namespaces (source #4).
    for listener in &gateway.spec.listeners {
        let Some(tls) = listener.tls.as_ref() else {
            continue;
        };
        let Some(refs) = tls.certificate_refs.as_deref() else {
            continue;
        };
        for r in refs {
            // Only Secret refs are meaningful for TLS termination; other
            // kinds are reserved/unsupported. Match the data plane's behavior
            // and skip non-Secret refs entirely.
            let kind = r.kind.as_deref().unwrap_or("Secret");
            let group = r.group.as_deref().unwrap_or("");
            if kind != "Secret" || !group.is_empty() {
                continue;
            }
            let target_ns = r.namespace.as_deref().unwrap_or(gw_namespace);
            if target_ns == gw_namespace {
                // Already covered by source #1; no grant check needed.
                continue;
            }
            if backend_ref_allowed(gw_namespace, target_ns, &r.name, &cert_grants) {
                out.insert(target_ns.to_string());
            }
        }
    }

    // HTTPRoute attachment + backendRefs (sources #2 and #3).
    let routes: Vec<Arc<HttpRoute>> = routes_store.state();
    for route in routes {
        if !route_attaches_to(&route, gw_name, gw_namespace) {
            continue;
        }
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("");

        // Source #2 — route attachment from a different namespace. Included
        // when any listener has `from: All` or `from: Selector`
        // (`allow_cross_namespace_routes = true`). Otherwise only
        // same-namespace routes contribute their backend namespaces.
        if !allow_cross_namespace_routes && route_ns != gw_namespace {
            continue;
        }
        out.insert(route_ns.to_string());

        // Source #3 — every backendRef's target namespace, gated by the
        // `HTTPRoute → Service` flavour of grant for cross-namespace refs.
        let Some(rules) = route.spec.rules.as_deref() else {
            continue;
        };
        for rule in rules {
            let Some(brefs) = rule.backend_refs.as_deref() else {
                continue;
            };
            for b in brefs {
                let target_ns = b.namespace.as_deref().unwrap_or(route_ns);
                if target_ns == route_ns {
                    continue;
                }
                let kind = b.kind.as_deref().unwrap_or("Service");
                let group = b.group.as_deref().unwrap_or("");
                if kind != "Service" || !group.is_empty() {
                    continue;
                }
                if backend_ref_allowed(route_ns, target_ns, &b.name, &backend_grants) {
                    out.insert(target_ns.to_string());
                }
            }
        }
    }

    out
}

/// Apply the desired set of `RoleBinding`s for a dedicated Gateway: create or
/// SSA-patch one binding per namespace in the desired set; delete any
/// bindings that previously existed for this Gateway but are no longer
/// desired.
///
/// `proxy_sa_name` is the ServiceAccount name the controller's renderer
/// produces (today: `<gw-name>-<gateway-class>`); we pass it in rather than
/// re-derive so the caller stays the single source of truth for resource
/// naming.
///
/// # Errors
///
/// Returns [`RbacError::List`] if the initial list of managed bindings
/// fails, [`RbacError::Apply`] on SSA failure for any desired binding, or
/// [`RbacError::Delete`] on delete failure for any binding being removed.
/// Failures abort the reconcile after the first error — the kube-rs Controller
/// re-queues, and the next reconcile retries.
pub(super) async fn reconcile_rbac(
    client: &Client,
    gateway: &Gateway,
    proxy_sa_name: &str,
    desired_namespaces: &BTreeSet<String>,
) -> Result<(), RbacError> {
    let gw_namespace = gateway.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    let gw_name =
        gateway.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    let binding_name = binding_name(gw_namespace, gw_name);

    let actual: BTreeSet<String> =
        list_managed_namespaces(client, gw_namespace, gw_name, &binding_name).await?;

    // Apply desired bindings (idempotent server-side; SSA with force=true).
    for ns in desired_namespaces {
        apply_binding(
            client,
            ns,
            &binding_name,
            gw_namespace,
            gw_name,
            proxy_sa_name,
        )
        .await?;
    }

    // Delete stale bindings (in actual but not desired).
    for ns in actual.difference(desired_namespaces) {
        delete_binding(client, ns, &binding_name).await?;
    }

    Ok(())
}

/// Delete every `RoleBinding` this controller has created for the given
/// Gateway across all namespaces. Used by the finalizer cleanup path and
/// when a Gateway transitions out of dedicated mode.
///
/// # Errors
///
/// Returns [`RbacError::List`] / [`RbacError::Delete`] on apiserver failure.
/// Idempotent: a missing binding (404) is treated as `Ok`.
pub(super) async fn delete_all_for_gateway(
    client: &Client,
    gw_namespace: &str,
    gw_name: &str,
) -> Result<(), RbacError> {
    let binding_name = binding_name(gw_namespace, gw_name);
    let namespaces = list_managed_namespaces(client, gw_namespace, gw_name, &binding_name).await?;
    for ns in &namespaces {
        delete_binding(client, ns, &binding_name).await?;
    }
    Ok(())
}

/// Reconcile the two optional `ClusterRoleBinding`s granting the dedicated
/// proxy cluster-wide reads. Each binding is created when the corresponding
/// flag in `derived` is true, and deleted when it is false or when the
/// Gateway is removed. Idempotent — SSA on the desired bindings, delete on
/// the undesired ones.
///
/// # Errors
///
/// Returns [`RbacError::ApplyClusterBinding`] or
/// [`RbacError::DeleteClusterBinding`] on apiserver failure.
pub(super) async fn reconcile_cluster_rbac(
    client: &Client,
    gateway: &Gateway,
    proxy_sa_name: &str,
    derived: DerivedProxyRbac,
) -> Result<(), RbacError> {
    let gw_namespace = gateway.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    let gw_name =
        gateway.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });

    let route_binding = cluster_binding_name(gw_namespace, gw_name, "cluster-wide-routes");
    let ns_binding = cluster_binding_name(gw_namespace, gw_name, "cluster-wide-namespaces");

    if derived.allow_cluster_wide_route_read {
        apply_cluster_binding(
            client,
            &route_binding,
            PROXY_CLUSTER_WIDE_ROUTE_ROLE_NAME,
            gw_namespace,
            gw_name,
            proxy_sa_name,
        )
        .await?;
    } else {
        delete_cluster_binding(client, &route_binding).await?;
    }

    if derived.allow_cluster_wide_namespace_read {
        apply_cluster_binding(
            client,
            &ns_binding,
            PROXY_CLUSTER_WIDE_NAMESPACE_ROLE_NAME,
            gw_namespace,
            gw_name,
            proxy_sa_name,
        )
        .await?;
    } else {
        delete_cluster_binding(client, &ns_binding).await?;
    }

    Ok(())
}

/// Delete both cluster-wide `ClusterRoleBinding`s for the given Gateway.
/// Called from the finalizer cleanup path and when a Gateway transitions out
/// of dedicated mode.
///
/// # Errors
///
/// Returns [`RbacError::DeleteClusterBinding`] on apiserver failure.
/// Idempotent: a missing binding (404) is treated as `Ok`.
pub(super) async fn delete_all_cluster_bindings_for_gateway(
    client: &Client,
    gw_namespace: &str,
    gw_name: &str,
) -> Result<(), RbacError> {
    let route_binding = cluster_binding_name(gw_namespace, gw_name, "cluster-wide-routes");
    let ns_binding = cluster_binding_name(gw_namespace, gw_name, "cluster-wide-namespaces");
    delete_cluster_binding(client, &route_binding).await?;
    delete_cluster_binding(client, &ns_binding).await?;
    Ok(())
}

/// Compute the binding name for a given Gateway. Encoded as
/// `coxswain-<gw-namespace>-<gw-name>` so two Gateways with the same name in
/// different namespaces cannot collide when both route into the same backend
/// namespace.
fn binding_name(gw_namespace: &str, gw_name: &str) -> String {
    format!("coxswain-{gw_namespace}-{gw_name}")
}

/// Compute the `ClusterRoleBinding` name for a given Gateway and suffix.
fn cluster_binding_name(gw_namespace: &str, gw_name: &str, suffix: &str) -> String {
    format!("coxswain-{gw_namespace}-{gw_name}-{suffix}")
}

/// Returns true iff the route has any `parentRef` pointing at the given
/// Gateway (matched by name + effective namespace, where missing
/// `parentRef.namespace` defaults to the route's namespace per Gateway API
/// spec).
fn route_attaches_to(route: &HttpRoute, gw_name: &str, gw_namespace: &str) -> bool {
    let route_ns = route.metadata.namespace.as_deref().unwrap_or("");
    let Some(parents) = route.spec.parent_refs.as_deref() else {
        return false;
    };
    for p in parents {
        let group = p.group.as_deref().unwrap_or("gateway.networking.k8s.io");
        let kind = p.kind.as_deref().unwrap_or("Gateway");
        if group != "gateway.networking.k8s.io" || kind != "Gateway" {
            continue;
        }
        let target_ns = p.namespace.as_deref().unwrap_or(route_ns);
        if p.name == gw_name && target_ns == gw_namespace {
            return true;
        }
    }
    false
}

async fn list_managed_namespaces(
    client: &Client,
    gw_namespace: &str,
    gw_name: &str,
    binding_name_expected: &str,
) -> Result<BTreeSet<String>, RbacError> {
    let api: Api<RoleBinding> = Api::all(client.clone());
    let selector = format!(
        "{}={MANAGED_BY_VALUE},{}={gw_name},{}={gw_namespace}",
        labels::MANAGED_BY,
        labels::GATEWAY_NAME,
        labels::GATEWAY_NAMESPACE,
    );
    let lp = ListParams::default().labels(&selector);
    let list = api.list(&lp).await.map_err(RbacError::List)?;

    let mut out = BTreeSet::new();
    for rb in list.items {
        // Defense-in-depth: only include bindings whose name matches our
        // canonical naming. If a stale binding with the right labels but
        // wrong name slipped through (e.g. an out-of-band write predating
        // this rename, or an unrelated tool that copied the label keys), we
        // ignore it rather than risk deleting an operator-managed object.
        if rb.metadata.name.as_deref() != Some(binding_name_expected) {
            continue;
        }
        let Some(ns) = rb.metadata.namespace else {
            continue;
        };
        out.insert(ns);
    }
    Ok(out)
}

async fn apply_binding(
    client: &Client,
    namespace: &str,
    binding_name: &str,
    gw_namespace: &str,
    gw_name: &str,
    proxy_sa_name: &str,
) -> Result<(), RbacError> {
    let mut labels = BTreeMap::new();
    labels.insert(labels::MANAGED_BY.to_string(), MANAGED_BY_VALUE.to_string());
    labels.insert(labels::GATEWAY_NAME.to_string(), gw_name.to_string());
    labels.insert(
        labels::GATEWAY_NAMESPACE.to_string(),
        gw_namespace.to_string(),
    );

    let binding = RoleBinding {
        metadata: ObjectMeta {
            name: Some(binding_name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: PROXY_CLUSTER_ROLE_NAME.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: proxy_sa_name.to_string(),
            namespace: Some(gw_namespace.to_string()),
            api_group: None,
        }]),
    };

    let api: Api<RoleBinding> = Api::namespaced(client.clone(), namespace);
    let params = PatchParams::apply(FIELD_MANAGER).force();
    api.patch(binding_name, &params, &Patch::Apply(&binding))
        .await
        .map_err(|source| RbacError::Apply {
            namespace: namespace.to_string(),
            name: binding_name.to_string(),
            source,
        })?;
    Ok(())
}

async fn delete_binding(
    client: &Client,
    namespace: &str,
    binding_name: &str,
) -> Result<(), RbacError> {
    let api: Api<RoleBinding> = Api::namespaced(client.clone(), namespace);
    match api
        .delete(binding_name, &kube::api::DeleteParams::default())
        .await
    {
        Ok(_) => Ok(()),
        // 404 means the binding was already gone (concurrent deletion or
        // never created). Treat as success — the desired state is satisfied.
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(source) => Err(RbacError::Delete {
            namespace: namespace.to_string(),
            name: binding_name.to_string(),
            source,
        }),
    }
}

async fn apply_cluster_binding(
    client: &Client,
    binding_name: &str,
    cluster_role_name: &str,
    gw_namespace: &str,
    gw_name: &str,
    proxy_sa_name: &str,
) -> Result<(), RbacError> {
    let mut labels = BTreeMap::new();
    labels.insert(labels::MANAGED_BY.to_string(), MANAGED_BY_VALUE.to_string());
    labels.insert(labels::GATEWAY_NAME.to_string(), gw_name.to_string());
    labels.insert(
        labels::GATEWAY_NAMESPACE.to_string(),
        gw_namespace.to_string(),
    );

    let binding = ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(binding_name.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: cluster_role_name.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: proxy_sa_name.to_string(),
            namespace: Some(gw_namespace.to_string()),
            api_group: None,
        }]),
    };

    let api: Api<ClusterRoleBinding> = Api::all(client.clone());
    let params = PatchParams::apply(FIELD_MANAGER).force();
    api.patch(binding_name, &params, &Patch::Apply(&binding))
        .await
        .map_err(|source| RbacError::ApplyClusterBinding {
            name: binding_name.to_string(),
            source,
        })?;
    Ok(())
}

async fn delete_cluster_binding(client: &Client, binding_name: &str) -> Result<(), RbacError> {
    let api: Api<ClusterRoleBinding> = Api::all(client.clone());
    match api
        .delete(binding_name, &kube::api::DeleteParams::default())
        .await
    {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(source) => Err(RbacError::DeleteClusterBinding {
            name: binding_name.to_string(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_reflector::gw_types::v::gateways::{
        GatewayListeners, GatewayListenersTls, GatewayListenersTlsCertificateRefs, GatewaySpec,
    };
    use coxswain_reflector::gw_types::v::httproutes::{
        HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteSpec,
    };
    use coxswain_reflector::gw_types::v::referencegrants::{
        ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo,
    };
    use kube::api::ObjectMeta;

    fn gateway_with_listeners(
        namespace: &str,
        name: &str,
        listeners: Vec<GatewayListeners>,
    ) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(format!("uid-{name}")),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".to_string(),
                listeners,
                ..Default::default()
            },
            status: None,
        }
    }

    fn simple_gateway(namespace: &str, name: &str) -> Gateway {
        gateway_with_listeners(
            namespace,
            name,
            vec![GatewayListeners {
                name: "http".into(),
                port: 80,
                protocol: "HTTP".into(),
                hostname: None,
                tls: None,
                allowed_routes: None,
            }],
        )
    }

    fn route_to_gateway(
        route_ns: &str,
        route_name: &str,
        gateway_namespace: &str,
        gateway_name: &str,
        backend_refs: Vec<HttpRouteRulesBackendRefs>,
    ) -> HttpRoute {
        HttpRoute {
            metadata: ObjectMeta {
                name: Some(route_name.to_string()),
                namespace: Some(route_ns.to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(vec![HttpRouteParentRefs {
                    group: Some("gateway.networking.k8s.io".to_string()),
                    kind: Some("Gateway".to_string()),
                    name: gateway_name.to_string(),
                    namespace: Some(gateway_namespace.to_string()),
                    port: None,
                    section_name: None,
                }]),
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(backend_refs),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            status: None,
        }
    }

    fn backend_ref(name: &str, namespace: Option<&str>) -> HttpRouteRulesBackendRefs {
        HttpRouteRulesBackendRefs {
            name: name.to_string(),
            namespace: namespace.map(String::from),
            group: None,
            kind: None,
            port: Some(80),
            weight: None,
            filters: None,
        }
    }

    fn build_routes_store(routes: Vec<HttpRoute>) -> Store<HttpRoute> {
        let (reader, mut writer) = kube::runtime::reflector::store::<HttpRoute>();
        // `Writer::apply_watcher_event` is not stable on the public surface;
        // simulate a Restart event so the reader's state contains all routes.
        let owned: Vec<HttpRoute> = routes;
        writer.apply_watcher_event(&kube::runtime::watcher::Event::Init);
        for r in &owned {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::InitApply(r.clone()));
        }
        writer.apply_watcher_event(&kube::runtime::watcher::Event::InitDone);
        reader
    }

    fn build_grants_store(grants: Vec<ReferenceGrant>) -> Store<ReferenceGrant> {
        let (reader, mut writer) = kube::runtime::reflector::store::<ReferenceGrant>();
        writer.apply_watcher_event(&kube::runtime::watcher::Event::Init);
        for g in &grants {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::InitApply(g.clone()));
        }
        writer.apply_watcher_event(&kube::runtime::watcher::Event::InitDone);
        reader
    }

    fn grant(
        to_ns: &str,
        from_kind: &str,
        from_ns: &str,
        to_kind: &str,
        to_name: Option<&str>,
    ) -> ReferenceGrant {
        ReferenceGrant {
            metadata: ObjectMeta {
                name: Some(format!("grant-{to_ns}-{from_ns}")),
                namespace: Some(to_ns.to_string()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![ReferenceGrantFrom {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: from_kind.to_string(),
                    namespace: from_ns.to_string(),
                }],
                to: vec![ReferenceGrantTo {
                    group: String::new(),
                    kind: to_kind.to_string(),
                    name: to_name.map(String::from),
                }],
            },
        }
    }

    /// A Gateway with no routes still produces its own namespace in the set.
    #[test]
    fn no_routes_includes_own_namespace_only() {
        let gw = simple_gateway("tenant-a", "my-gw");
        let routes = build_routes_store(vec![]);
        let grants = build_grants_store(vec![]);
        let ns = desired_namespaces_for_gateway(&gw, &routes, &grants, false);
        assert_eq!(
            ns,
            ["tenant-a".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    /// A route in the same namespace pointing at a same-namespace backend
    /// produces the gateway's own namespace only.
    #[test]
    fn same_namespace_backend_no_extra_namespace() {
        let gw = simple_gateway("tenant-a", "my-gw");
        let route = route_to_gateway(
            "tenant-a",
            "r1",
            "tenant-a",
            "my-gw",
            vec![backend_ref("svc-a", None)],
        );
        let routes = build_routes_store(vec![route]);
        let grants = build_grants_store(vec![]);
        let ns = desired_namespaces_for_gateway(&gw, &routes, &grants, false);
        assert_eq!(
            ns,
            ["tenant-a".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    /// Cross-namespace backend without a matching ReferenceGrant is NOT
    /// added to the desired set — overscoping would leak reads.
    #[test]
    fn cross_namespace_backend_without_grant_is_excluded() {
        let gw = simple_gateway("tenant-a", "my-gw");
        let route = route_to_gateway(
            "tenant-a",
            "r1",
            "tenant-a",
            "my-gw",
            vec![backend_ref("svc-b", Some("shared-services"))],
        );
        let routes = build_routes_store(vec![route]);
        let grants = build_grants_store(vec![]);
        let ns = desired_namespaces_for_gateway(&gw, &routes, &grants, false);
        assert_eq!(
            ns,
            ["tenant-a".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    /// Cross-namespace backend with a matching ReferenceGrant IS added.
    #[test]
    fn cross_namespace_backend_with_grant_is_included() {
        let gw = simple_gateway("tenant-a", "my-gw");
        let route = route_to_gateway(
            "tenant-a",
            "r1",
            "tenant-a",
            "my-gw",
            vec![backend_ref("svc-b", Some("shared-services"))],
        );
        let g = grant("shared-services", "HTTPRoute", "tenant-a", "Service", None);
        let routes = build_routes_store(vec![route]);
        let grants = build_grants_store(vec![g]);
        let ns = desired_namespaces_for_gateway(&gw, &routes, &grants, false);
        assert_eq!(
            ns,
            ["tenant-a".to_string(), "shared-services".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>(),
        );
    }

    /// Routes that don't attach to this Gateway don't contribute to its set.
    #[test]
    fn unrelated_routes_are_ignored() {
        let gw = simple_gateway("tenant-a", "my-gw");
        let other_route = route_to_gateway(
            "tenant-a",
            "other",
            "tenant-a",
            "other-gw",
            vec![backend_ref("svc-c", Some("shared-services"))],
        );
        let g = grant("shared-services", "HTTPRoute", "tenant-a", "Service", None);
        let routes = build_routes_store(vec![other_route]);
        let grants = build_grants_store(vec![g]);
        let ns = desired_namespaces_for_gateway(&gw, &routes, &grants, false);
        assert_eq!(
            ns,
            ["tenant-a".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    /// Routes attached from a different namespace are excluded when
    /// `allow_cross_namespace_routes = false` (the default `from: Same` case).
    #[test]
    fn cross_namespace_route_excluded_without_flag() {
        let gw = simple_gateway("tenant-a", "my-gw");
        let route = route_to_gateway(
            "tenant-b",
            "r1",
            "tenant-a",
            "my-gw",
            vec![backend_ref("svc-c", None)],
        );
        let routes = build_routes_store(vec![route]);
        let grants = build_grants_store(vec![]);
        let ns = desired_namespaces_for_gateway(&gw, &routes, &grants, false);
        assert_eq!(
            ns,
            ["tenant-a".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    /// When `allow_cross_namespace_routes = true`, a route from another namespace
    /// contributes its own namespace (and any cross-namespace backends it has)
    /// to the desired set.
    #[test]
    fn cross_namespace_route_included_with_flag() {
        let gw = simple_gateway("tenant-a", "my-gw");
        let route = route_to_gateway(
            "tenant-b",
            "r1",
            "tenant-a",
            "my-gw",
            vec![backend_ref("svc-c", None)],
        );
        let routes = build_routes_store(vec![route]);
        let grants = build_grants_store(vec![]);
        let ns = desired_namespaces_for_gateway(&gw, &routes, &grants, true);
        assert_eq!(
            ns,
            ["tenant-a".to_string(), "tenant-b".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    /// A listener with TLS certRef in a different namespace, gated by a
    /// `Gateway → Secret` grant, expands the desired set.
    #[test]
    fn cross_namespace_tls_certref_with_grant_is_included() {
        let gw = gateway_with_listeners(
            "tenant-a",
            "my-gw",
            vec![GatewayListeners {
                name: "https".into(),
                port: 443,
                protocol: "HTTPS".into(),
                hostname: None,
                tls: Some(GatewayListenersTls {
                    certificate_refs: Some(vec![GatewayListenersTlsCertificateRefs {
                        group: None,
                        kind: Some("Secret".to_string()),
                        name: "cert".to_string(),
                        namespace: Some("certs-ns".to_string()),
                    }]),
                    mode: None,
                    options: None,
                }),
                allowed_routes: None,
            }],
        );
        let g = grant("certs-ns", "Gateway", "tenant-a", "Secret", None);
        let routes = build_routes_store(vec![]);
        let grants = build_grants_store(vec![g]);
        let ns = desired_namespaces_for_gateway(&gw, &routes, &grants, false);
        assert_eq!(
            ns,
            ["tenant-a".to_string(), "certs-ns".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>(),
        );
    }

    /// Binding name format is stable; tests pin it to catch accidental
    /// renames that would orphan existing bindings in the cluster.
    #[test]
    fn binding_name_is_collision_safe() {
        assert_eq!(
            binding_name("tenant-a", "public-gw"),
            "coxswain-tenant-a-public-gw"
        );
        assert_ne!(
            binding_name("tenant-a", "public-gw"),
            binding_name("tenant-b", "public-gw"),
            "same-named gateways in different namespaces must not collide"
        );
    }
}
