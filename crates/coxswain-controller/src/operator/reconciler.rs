//! `kube_runtime::Controller`-based reconcile loop for the dedicated-mode
//! provisioning operator.
//!
//! Primary resource: [`Gateway`]. Cross-watches: [`GatewayClass`] (changes to
//! a class trigger reconcile for every Gateway in that class) and
//! [`CoxswainGatewayParameters`] (any params change triggers reconcile for
//! every Gateway — the population is small enough by design that re-checking
//! all is cheaper than tracking which Gateways resolve to which params).
//!
//! ## Step 9 scope: server-side-apply
//!
//! Every reconcile renders the desired Deployment/Service/ServiceAccount and
//! server-side-applies all three under field manager `"coxswain-controller"`
//! with `force=true` — the controller is the authoritative owner of the
//! generated resources (see [`super::apply`] for the source-of-truth
//! contract). The hash check from Step 8 is preserved but only suppresses
//! the INFO log on no-change reconciles; SSA still fires every time so any
//! out-of-band `kubectl edit` is reverted on the next reconcile.
//!
//! ## Leader gating
//!
//! Every reconcile checks the shared leader [`AtomicBool`] (owned by the
//! existing [`crate::Controller`]'s leader-election machinery). Non-leader
//! pods short-circuit and re-queue; only the elected leader applies.
//!
//! ## Missing parametersRef target
//!
//! [`params::resolve`] surfaces this as `Err(ParamsError::NotFound)`. The
//! reconciler publishes an `AcceptedReason::InvalidParameters` override into
//! the shared [`AcceptedOverrides`] map; the status writer in
//! [`crate::controller`] consults the map on every Gateway reconcile and
//! emits `Accepted=False, reason=InvalidParameters` (Gateway API spec). On a
//! successful resolve we clear the override so the writer returns to
//! emitting `Accepted=True`.

use super::{apply, params, rbac, render};
use crate::AcceptedOverrides;
use crate::AcceptedReason;
use async_trait::async_trait;
use coxswain_core::crd::CoxswainGatewayParameters;
use coxswain_core::ownership::ObjectKey;
use coxswain_reflector::gw_types::HttpRoute;
use coxswain_reflector::gw_types::v::gatewayclasses::GatewayClass;
use coxswain_reflector::gw_types::v::gateways::Gateway;
use coxswain_reflector::gw_types::v::referencegrants::ReferenceGrant;
use futures::StreamExt;
use k8s_openapi::api::rbac::v1::RoleBinding;
use kube::{
    Api, Client, Resource as _,
    api::{Patch, PatchParams},
    runtime::{
        WatchStreamExt,
        controller::{Action, Controller},
        reflector::{self, ObjectRef, Store},
        watcher,
    },
};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash as _, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::task::JoinSet;

/// Re-queue interval when the operator's pod isn't the leader. Long enough to
/// avoid hot-spinning the reconcile loop, short enough that promotion to
/// leader translates into action quickly (the existing status writer's lease
/// TTL defaults to 15 s).
const NON_LEADER_REQUEUE: Duration = Duration::from_secs(20);

/// Default re-queue after a reconcile error. Short backoff is fine — most
/// errors here are transient (apiserver hiccup, missing object that's about
/// to be created).
const ERROR_REQUEUE: Duration = Duration::from_secs(15);

/// Errors that can be returned from [`reconcile`]. They are observed only by
/// the controller framework's error policy (which converts them into a
/// re-queue) and the operator's own logs — the K8s API does not see them.
#[non_exhaustive]
#[derive(Debug, Error)]
pub(super) enum ReconcileError {
    /// Kubernetes API error encountered outside the SSA path (e.g. by future
    /// pre-flight reads of provisioned resources). The SSA path's failures
    /// land in [`ReconcileError::Apply`] instead.
    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),
    /// SSA of one of the three rendered resources failed.
    #[error("apply: {0}")]
    Apply(#[from] apply::ApplyError),
    /// Per-namespace `RoleBinding` reconcile or cleanup failed (#209).
    #[error("rbac: {0}")]
    Rbac(#[from] rbac::RbacError),
}

/// Bundle of inputs the operator's [`BackgroundService::start`] needs from
/// the bin layer. Carries the leader flag so the operator shares one
/// truth-source with the [`crate::Controller`] status writer.
///
/// Not `#[non_exhaustive]` — same rationale as
/// [`crate::StatusWriterConfig`]: it's an internal wiring struct that only
/// `coxswain-bin` instantiates.
pub struct OperatorConfig {
    /// `GatewayClass.spec.controllerName` claim — same string the status
    /// writer uses; we only reconcile Gateways whose class matches.
    pub controller_name: String,
    /// Image for the rendered proxy container when
    /// `CoxswainGatewayParameters.spec.image` is unset. Typically the
    /// controller's own image so dedicated proxies stay version-pinned to
    /// the controller without operator-level coordination.
    pub controller_image: String,
    /// Shared leader-election flag the status writer flips on `Acquire`.
    /// Reconcile is a no-op (re-queue) when this is `false`.
    pub leader: Arc<AtomicBool>,
    /// Shared override channel that the operator publishes into when a
    /// Gateway's `parametersRef` resolves to a missing target. The bin layer
    /// must wire this to the *same* [`AcceptedOverrides`] instance held by
    /// the [`crate::ControllerConfig`] so the status writer can read what
    /// the operator publishes.
    pub accepted_overrides: AcceptedOverrides,
}

/// Provisioning operator. Registered as a Pingora `BackgroundService` next
/// to the [`crate::Controller`] in `serve controller` and `serve dev`;
/// shares the controller pod's process and leader-election truth-source but
/// owns its own kube-rs `Controller` and reflector stores.
pub struct Operator {
    config: OperatorConfig,
}

impl Operator {
    /// Construct a new operator instance (does not start the watch loop).
    #[must_use]
    pub fn new(config: OperatorConfig) -> Self {
        Self { config }
    }
}

/// Reconcile context shared across all per-Gateway reconcile invocations.
/// `std::sync::Mutex` (not `tokio::sync::Mutex`) because the lock is held
/// only briefly inside the reconcile body and never across `.await` — the
/// async one would make the reconcile future `!Unpin` for no benefit.
struct ReconcileContext {
    controller_name: String,
    controller_image: String,
    leader: Arc<AtomicBool>,
    accepted_overrides: AcceptedOverrides,
    client: Client,
    class_store: Store<GatewayClass>,
    params_store: Store<CoxswainGatewayParameters>,
    routes_store: Store<HttpRoute>,
    grants_store: Store<ReferenceGrant>,
    last_hashes: Mutex<HashMap<ObjectKey, u64>>,
}

/// Finalizer key the operator places on every dedicated-mode Gateway. The
/// reconcile clears cross-namespace `RoleBinding`s (and provisioned same-ns
/// resources will GC via owner-ref) before removing this finalizer; without
/// it K8s would delete the Gateway before we can clean up the bindings,
/// leaving stale RBAC across the cluster.
const CLEANUP_FINALIZER: &str = "gateway.coxswain-labs.dev/dedicated-cleanup";

/// Short re-queue used after adding the finalizer on a fresh dedicated
/// Gateway. The follow-up reconcile sees the patched object (with the
/// finalizer in place) and proceeds to apply + bind in one body.
const POST_FINALIZER_REQUEUE: Duration = Duration::from_millis(50);

fn gateway_key(gw: &Gateway) -> ObjectKey {
    ObjectKey::new(
        gw.metadata.namespace.clone().unwrap_or_default(),
        gw.metadata.name.clone().unwrap_or_default(),
    )
}

#[async_trait]
impl BackgroundService for Operator {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "operator: failed to initialise Kubernetes client; will not run");
                return;
            }
        };

        // Spawn the cross-watched reflector stores in parallel with the
        // Controller. Their `Store`s are shared into the reconcile Context.
        let mut tasks = JoinSet::new();
        let (class_reader, class_writer) = reflector::store::<GatewayClass>();
        tasks.spawn({
            let api = Api::<GatewayClass>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    class_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        let (params_reader, params_writer) = reflector::store::<CoxswainGatewayParameters>();
        tasks.spawn({
            let api = Api::<CoxswainGatewayParameters>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    params_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        let (routes_reader, routes_writer) = reflector::store::<HttpRoute>();
        tasks.spawn({
            let api = Api::<HttpRoute>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    routes_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });
        let (grants_reader, grants_writer) = reflector::store::<ReferenceGrant>();
        tasks.spawn({
            let api = Api::<ReferenceGrant>::all(client.clone());
            async move {
                let stream = reflector::reflector(
                    grants_writer,
                    watcher(api, watcher::Config::default()).default_backoff(),
                );
                tokio::pin!(stream);
                while stream.next().await.is_some() {}
            }
        });

        let ctx = Arc::new(ReconcileContext {
            controller_name: self.config.controller_name.clone(),
            controller_image: self.config.controller_image.clone(),
            leader: Arc::clone(&self.config.leader),
            accepted_overrides: self.config.accepted_overrides.clone(),
            client: client.clone(),
            class_store: class_reader,
            params_store: params_reader,
            routes_store: routes_reader,
            grants_store: grants_reader,
            last_hashes: Mutex::new(HashMap::new()),
        });

        // Build the kube-rs Controller. We don't `.owns(Deployment)` yet —
        // Step 8 writes nothing, so there are no owned Deployments to
        // observe. Step 9 (#208) adds `.owns(api_deployments, ...)`.
        let api_gateways: Api<Gateway> = Api::all(client.clone());
        let api_classes: Api<GatewayClass> = Api::all(client.clone());
        let api_params: Api<CoxswainGatewayParameters> = Api::all(client.clone());
        let api_routes: Api<HttpRoute> = Api::all(client.clone());
        let api_grants: Api<ReferenceGrant> = Api::all(client.clone());
        let api_bindings: Api<RoleBinding> = Api::all(client);
        let class_store_for_watches = ctx.class_store.clone();
        let routes_store_for_watches = ctx.routes_store.clone();

        let controller = Controller::new(api_gateways, watcher::Config::default());
        let gateway_store = controller.store();

        let controller = controller
            .watches(api_classes, watcher::Config::default(), {
                let gateway_store = gateway_store.clone();
                move |class: GatewayClass| -> Vec<ObjectRef<Gateway>> {
                    let Some(class_name) = class.meta().name.clone() else {
                        return vec![];
                    };
                    gateway_store
                        .state()
                        .into_iter()
                        .filter(|gw| gw.spec.gateway_class_name == class_name)
                        .map(|gw| ObjectRef::from_obj(gw.as_ref()))
                        .collect()
                }
            })
            .watches(api_params, watcher::Config::default(), {
                // Any params change triggers reconcile for every owned
                // Gateway. With per-Gateway tracking we could narrow this to
                // the affected Gateways only, but the population is small by
                // design (#218 / architecture plan: tens of dedicated
                // Gateways at most), so re-checking all is cheaper than
                // maintaining the cross-index.
                let gateway_store = gateway_store.clone();
                let class_store = class_store_for_watches.clone();
                move |_p: CoxswainGatewayParameters| -> Vec<ObjectRef<Gateway>> {
                    let owned_class_names: std::collections::HashSet<String> = class_store
                        .state()
                        .into_iter()
                        .filter_map(|gc| gc.meta().name.clone())
                        .collect();
                    gateway_store
                        .state()
                        .into_iter()
                        .filter(|gw| owned_class_names.contains(&gw.spec.gateway_class_name))
                        .map(|gw| ObjectRef::from_obj(gw.as_ref()))
                        .collect()
                }
            })
            // HTTPRoute → Gateway: every parentRef pointing at a Gateway
            // we manage triggers a reconcile for that Gateway. Precise
            // mapping — no fan-out.
            .watches(api_routes, watcher::Config::default(), {
                move |route: HttpRoute| -> Vec<ObjectRef<Gateway>> {
                    let route_ns = route
                        .metadata
                        .namespace
                        .as_deref()
                        .unwrap_or("")
                        .to_string();
                    let Some(parents) = route.spec.parent_refs.as_deref() else {
                        return vec![];
                    };
                    parents
                        .iter()
                        .filter(|p| {
                            let group = p.group.as_deref().unwrap_or("gateway.networking.k8s.io");
                            let kind = p.kind.as_deref().unwrap_or("Gateway");
                            group == "gateway.networking.k8s.io" && kind == "Gateway"
                        })
                        .map(|p| {
                            let ns = p.namespace.clone().unwrap_or_else(|| route_ns.clone());
                            ObjectRef::new(&p.name).within(&ns)
                        })
                        .collect()
                }
            })
            // ReferenceGrant → Gateway: filter to those whose routes have a
            // backendRef into the grant's namespace. Engineering-correct
            // precise mapping; we deliberately do not broad fan-out — the
            // cost of maintaining the index closure is bounded
            // (dedicated_gateways × routes × backend_refs) and the precise
            // mapping scales naturally past today's "tens of Gateways" cap.
            .watches(api_grants, watcher::Config::default(), {
                let gateway_store = gateway_store.clone();
                let routes_store = routes_store_for_watches.clone();
                move |grant: ReferenceGrant| -> Vec<ObjectRef<Gateway>> {
                    let Some(target_ns) = grant.metadata.namespace.clone() else {
                        return vec![];
                    };
                    let routes: Vec<Arc<HttpRoute>> = routes_store.state();
                    gateway_store
                        .state()
                        .into_iter()
                        .filter(|gw| {
                            let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("");
                            let gw_name = gw.metadata.name.as_deref().unwrap_or("");
                            gateway_routes_into(&routes, gw_ns, gw_name, &target_ns)
                        })
                        .map(|gw| ObjectRef::from_obj(gw.as_ref()))
                        .collect()
                }
            })
            // RoleBinding → Gateway: managed-by label filter; mapper reads
            // the gateway-namespace/gateway-name labels to identify the
            // owning Gateway. Drives drift detection — an out-of-band delete
            // re-creates within watch latency rather than waiting for the
            // next natural reconcile trigger.
            .watches(
                api_bindings,
                watcher::Config::default().labels("app.kubernetes.io/managed-by=coxswain"),
                |rb: RoleBinding| -> Vec<ObjectRef<Gateway>> {
                    let Some(labels) = rb.metadata.labels.as_ref() else {
                        return vec![];
                    };
                    let Some(name) = labels.get("gateway.networking.k8s.io/gateway-name") else {
                        return vec![];
                    };
                    let Some(ns) = labels.get("gateway.coxswain-labs.dev/gateway-namespace") else {
                        return vec![];
                    };
                    vec![ObjectRef::new(name).within(ns)]
                },
            );

        let stream = controller.run(reconcile, error_policy, ctx);
        // The controller stream contains `!Unpin` futures internally
        // (kube-runtime's `applier`); pinning to the stack here lets
        // `tokio::select!` poll it across iterations.
        tokio::pin!(stream);

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                next = stream.next() => match next {
                    Some(Ok(_)) => {}
                    Some(Err(e)) => tracing::debug!(error = %e, "operator: controller stream error"),
                    None => {
                        tracing::warn!("operator: controller stream ended; tearing down");
                        break;
                    }
                },
            }
        }
        tasks.shutdown().await;
    }
}

async fn reconcile(gw: Arc<Gateway>, ctx: Arc<ReconcileContext>) -> Result<Action, ReconcileError> {
    if !ctx.leader.load(Ordering::Acquire) {
        // Non-leader pods don't apply. Re-queue rather than `await_change()`
        // so the operator catches up promptly on leader promotion.
        return Ok(Action::requeue(NON_LEADER_REQUEUE));
    }

    let key = gateway_key(&gw);
    let gw_namespace = gw.metadata.namespace.as_deref().unwrap_or("");
    let gw_name = gw.metadata.name.as_deref().unwrap_or("");

    // ----- Finalizer / deletion path ------------------------------------
    //
    // A Gateway with `deletionTimestamp` set is being deleted; if it carries
    // our finalizer, we own the synchronous cleanup of cross-namespace
    // `RoleBinding`s before K8s can finalize the delete. Provisioned
    // resources (Deployment/Service/SA) in the Gateway's own namespace
    // GC via owner-refs — independent of this finalizer.
    if gw.metadata.deletion_timestamp.is_some() {
        if has_our_finalizer(&gw) {
            tracing::info!(
                gateway = %gateway_id(&gw),
                "operator: cleaning up dedicated-mode bindings for terminating Gateway"
            );
            rbac::delete_all_for_gateway(&ctx.client, gw_namespace, gw_name).await?;
            remove_finalizer(&ctx.client, &gw).await?;
            // GC of in-namespace resources is owner-ref driven; nothing else
            // to do here.
            ctx.last_hashes
                .lock()
                .unwrap_or_else(|e| panic!("invariant: hash-tracking mutex poisoned: {e}"))
                .remove(&key);
        }
        return Ok(Action::await_change());
    }

    let class_name = &gw.spec.gateway_class_name;
    let Some(class) = ctx
        .class_store
        .state()
        .into_iter()
        .find(|gc| gc.meta().name.as_deref() == Some(class_name.as_str()))
    else {
        // Class not yet observed — wait for its reflector to sync; the
        // GatewayClass cross-watch will re-queue this Gateway when the class
        // appears.
        return Ok(Action::await_change());
    };
    if class.spec.controller_name != ctx.controller_name {
        // Different controller's Gateway; not ours to provision.
        return Ok(Action::await_change());
    }

    // Resolve effective parameters. The lookup closure reads the snapshot of
    // the params reflector store; the store's interior `ArcSwap` makes this
    // a cheap atomic load per call.
    let effective = match params::resolve(&gw, &class, |r: &params::ParamsRef| {
        ctx.params_store
            .state()
            .iter()
            .find(|p| {
                p.meta().namespace.as_deref() == Some(r.namespace.as_str())
                    && p.meta().name.as_deref() == Some(r.name.as_str())
            })
            .map(|p| p.spec.clone())
    }) {
        Ok(Some(e)) => e,
        Ok(None) => {
            // Not dedicated mode. If we previously placed our finalizer on
            // this Gateway (it was dedicated, now isn't), clean up bindings
            // and the finalizer too so the Gateway can transition cleanly
            // back to the shared pool.
            if has_our_finalizer(&gw) {
                tracing::info!(
                    gateway = %gateway_id(&gw),
                    "operator: Gateway transitioned out of dedicated mode; cleaning bindings"
                );
                rbac::delete_all_for_gateway(&ctx.client, gw_namespace, gw_name).await?;
                remove_finalizer(&ctx.client, &gw).await?;
            }
            ctx.accepted_overrides.clear(&key);
            return Ok(Action::await_change());
        }
        Err(params::ParamsError::NotFound(ns, name)) => {
            tracing::warn!(
                gateway = %gateway_id(&gw),
                missing = %format!("{ns}/{name}"),
                "operator: parametersRef target not found; publishing \
                 Accepted=False, reason=InvalidParameters and re-queuing"
            );
            ctx.accepted_overrides
                .set(key, AcceptedReason::InvalidParameters);
            return Ok(Action::requeue(ERROR_REQUEUE));
        }
    };

    // Dedicated-mode Gateway. Ensure the finalizer is in place before doing
    // any provisioning — if anything goes wrong before the finalizer is
    // patched, a delete can race past us. Add → requeue → continue.
    if !has_our_finalizer(&gw) {
        add_finalizer(&ctx.client, &gw).await?;
        return Ok(Action::requeue(POST_FINALIZER_REQUEUE));
    }

    // Compute the desired namespace set once and share between rbac.rs and
    // (future) the rendered `--proxy-watch-namespaces` arg.
    let desired = rbac::desired_namespaces_for_gateway(&gw, &ctx.routes_store, &ctx.grants_store);

    let rendered = render::render(&render::RenderInputs {
        gateway: &gw,
        params: &effective,
        controller_image: &ctx.controller_image,
        gateway_class_name: class_name,
        watch_namespaces: &desired,
    });

    // Stage 1 — provisioning (Deployment/Service/SA). SSA with force=true
    // re-asserts ownership on every reconcile; the apply order is SA →
    // Service → Deployment so the ServiceAccount exists before any
    // RoleBinding references it.
    apply::apply_rendered(&ctx.client, &gw, &rendered).await?;

    // Stage 2 — per-namespace RoleBindings. The proxy SA name matches the
    // rendered SA's name (GEP-1762 `<NAME>-<GATEWAY CLASS>`); we pass it in
    // explicitly so reconciler.rs stays the single source of truth for
    // resource naming.
    let proxy_sa_name = rendered
        .service_account
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| panic!("invariant: rendered ServiceAccount has no name"));
    rbac::reconcile_rbac(&ctx.client, &gw, proxy_sa_name, &desired).await?;

    // Successful resolve + apply → clear any prior `InvalidParameters`
    // override (e.g. user just created the missing
    // `CoxswainGatewayParameters` object) so the status writer can return
    // the Gateway to `Accepted=True` on its next reconcile.
    ctx.accepted_overrides.clear(&key);

    let new_hash = hash_rendered(&rendered);
    let changed = {
        let mut hashes = ctx
            .last_hashes
            .lock()
            .unwrap_or_else(|e| panic!("invariant: hash-tracking mutex must not be poisoned: {e}"));
        let prior = hashes.get(&key).copied();
        let changed = prior != Some(new_hash);
        if changed {
            hashes.insert(key, new_hash);
        }
        changed
        // Lock guard drops at the closing brace — well before any further
        // .await point.
    };
    if changed {
        log_rendered_change(&gw, &rendered);
    } else {
        tracing::debug!(
            gateway = %gateway_id(&gw),
            "operator: re-render produced identical specs; SSA was a no-op server-side"
        );
    }

    Ok(Action::await_change())
}

/// Returns true iff the Gateway carries our cleanup finalizer.
fn has_our_finalizer(gw: &Gateway) -> bool {
    gw.metadata
        .finalizers
        .as_ref()
        .is_some_and(|f| f.iter().any(|s| s == CLEANUP_FINALIZER))
}

/// Patch the Gateway to add our finalizer to `metadata.finalizers`.
/// Idempotent server-side: if the finalizer is already present, the patched
/// state matches and the apiserver accepts the no-op.
async fn add_finalizer(client: &Client, gw: &Gateway) -> Result<(), kube::Error> {
    let namespace = gw.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    let name =
        gw.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    // Construct the desired finalizer set: existing + ours. SSA's strategic
    // merge handles deduplication when we list our finalizer alongside
    // pre-existing ones.
    let mut finalizers: Vec<String> = gw.metadata.finalizers.clone().unwrap_or_default();
    if !finalizers.iter().any(|s| s == CLEANUP_FINALIZER) {
        finalizers.push(CLEANUP_FINALIZER.to_string());
    }
    let patch = serde_json::json!({
        "metadata": {
            "finalizers": finalizers,
        }
    });
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    let params = PatchParams::default();
    api.patch(name, &params, &Patch::Merge(&patch)).await?;
    Ok(())
}

/// Patch the Gateway to remove our finalizer. Idempotent — if the finalizer
/// isn't present, we still write the resulting list back; the apiserver
/// accepts the no-op.
async fn remove_finalizer(client: &Client, gw: &Gateway) -> Result<(), kube::Error> {
    let namespace = gw.metadata.namespace.as_deref().unwrap_or_else(|| {
        panic!("invariant: Gateway has no namespace; the API server requires it")
    });
    let name =
        gw.metadata.name.as_deref().unwrap_or_else(|| {
            panic!("invariant: Gateway has no name; the API server requires it")
        });
    let finalizers: Vec<String> = gw
        .metadata
        .finalizers
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s != CLEANUP_FINALIZER)
        .collect();
    let patch = serde_json::json!({
        "metadata": {
            "finalizers": finalizers,
        }
    });
    let api: Api<Gateway> = Api::namespaced(client.clone(), namespace);
    let params = PatchParams::default();
    api.patch(name, &params, &Patch::Merge(&patch)).await?;
    Ok(())
}

/// Returns true iff any HTTPRoute attached to the given Gateway has a
/// `backendRef` whose target namespace equals `target_ns`. Used by the
/// ReferenceGrant cross-watch mapper to filter affected Gateways precisely.
fn gateway_routes_into(
    routes: &[Arc<HttpRoute>],
    gw_namespace: &str,
    gw_name: &str,
    target_ns: &str,
) -> bool {
    for route in routes {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("");
        let Some(parents) = route.spec.parent_refs.as_deref() else {
            continue;
        };
        let attaches = parents.iter().any(|p| {
            let group = p.group.as_deref().unwrap_or("gateway.networking.k8s.io");
            let kind = p.kind.as_deref().unwrap_or("Gateway");
            let ns = p.namespace.as_deref().unwrap_or(route_ns);
            group == "gateway.networking.k8s.io"
                && kind == "Gateway"
                && p.name == gw_name
                && ns == gw_namespace
        });
        if !attaches {
            continue;
        }
        let Some(rules) = route.spec.rules.as_deref() else {
            continue;
        };
        for rule in rules {
            let Some(brefs) = rule.backend_refs.as_deref() else {
                continue;
            };
            for b in brefs {
                let ns = b.namespace.as_deref().unwrap_or(route_ns);
                if ns == target_ns {
                    return true;
                }
            }
        }
    }
    false
}

fn error_policy(obj: Arc<Gateway>, err: &ReconcileError, _ctx: Arc<ReconcileContext>) -> Action {
    tracing::warn!(
        gateway = %gateway_id(&obj),
        error = %err,
        "operator: reconcile error; backing off"
    );
    Action::requeue(ERROR_REQUEUE)
}

fn gateway_id(gw: &Gateway) -> String {
    format!(
        "{}/{}",
        gw.metadata.namespace.as_deref().unwrap_or(""),
        gw.metadata.name.as_deref().unwrap_or("")
    )
}

fn hash_rendered(rendered: &render::RenderedSpecs) -> u64 {
    let mut hasher = DefaultHasher::new();
    // Hash via JSON round-trip: structural equivalence we care about
    // (`Deployment` field set, container args, label values, etc.) is
    // exactly what `serde_json::to_value` exposes. Bypasses the lack of
    // `Hash` impls on k8s-openapi types.
    let payload = serde_json::json!({
        "deployment": serde_json::to_value(&rendered.deployment).unwrap_or_default(),
        "service": serde_json::to_value(&rendered.service).unwrap_or_default(),
        "service_account": serde_json::to_value(&rendered.service_account).unwrap_or_default(),
    });
    payload.to_string().hash(&mut hasher);
    hasher.finish()
}

fn log_rendered_change(gw: &Gateway, rendered: &render::RenderedSpecs) {
    let deployment_yaml = serde_yaml::to_string(&rendered.deployment)
        .unwrap_or_else(|e| format!("# yaml serialise failed: {e}"));
    let service_yaml = serde_yaml::to_string(&rendered.service)
        .unwrap_or_else(|e| format!("# yaml serialise failed: {e}"));
    let service_account_yaml = serde_yaml::to_string(&rendered.service_account)
        .unwrap_or_else(|e| format!("# yaml serialise failed: {e}"));
    tracing::info!(
        gateway = %gateway_id(gw),
        deployment = %deployment_yaml,
        service = %service_yaml,
        service_account = %service_account_yaml,
        "operator: dedicated-proxy specs changed; SSA succeeded"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_key_uses_namespace_and_name() {
        let gw = Gateway {
            metadata: kube::api::ObjectMeta {
                namespace: Some("tenant-a".into()),
                name: Some("my-gw".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let k = gateway_key(&gw);
        assert_eq!(k.ns, "tenant-a");
        assert_eq!(k.name, "my-gw");
    }

    #[test]
    fn hash_changes_on_replica_change() {
        use crate::operator::params::EffectiveParams;
        use crate::operator::render;
        use coxswain_reflector::gw_types::v::gateways::{GatewayListeners, GatewaySpec};

        let gw = Gateway {
            metadata: kube::api::ObjectMeta {
                namespace: Some("default".into()),
                name: Some("my-gw".into()),
                uid: Some("uid-my-gw".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".into(),
                listeners: vec![GatewayListeners {
                    name: "http".into(),
                    port: 80,
                    protocol: "HTTP".into(),
                    hostname: None,
                    tls: None,
                    allowed_routes: None,
                }],
                ..Default::default()
            },
            status: None,
        };
        let params_a = EffectiveParams {
            replicas: Some(1),
            ..Default::default()
        };
        let params_b = EffectiveParams {
            replicas: Some(3),
            ..Default::default()
        };
        let r_a = render::render(&render::RenderInputs {
            gateway: &gw,
            params: &params_a,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            watch_namespaces: &std::collections::BTreeSet::new(),
        });
        let r_b = render::render(&render::RenderInputs {
            gateway: &gw,
            params: &params_b,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            watch_namespaces: &std::collections::BTreeSet::new(),
        });
        assert_ne!(
            hash_rendered(&r_a),
            hash_rendered(&r_b),
            "replica count is part of the rendered Deployment; hashes must differ"
        );
    }

    #[test]
    fn hash_stable_across_identical_renders() {
        use crate::operator::params::EffectiveParams;
        use crate::operator::render;
        use coxswain_reflector::gw_types::v::gateways::GatewaySpec;

        let gw = Gateway {
            metadata: kube::api::ObjectMeta {
                namespace: Some("default".into()),
                name: Some("my-gw".into()),
                uid: Some("uid-my-gw".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "coxswain".into(),
                listeners: vec![],
                ..Default::default()
            },
            status: None,
        };
        let params = EffectiveParams::default();
        let empty_ns = std::collections::BTreeSet::new();
        let inputs = render::RenderInputs {
            gateway: &gw,
            params: &params,
            controller_image: "coxswain:v0.2",
            gateway_class_name: "coxswain",
            watch_namespaces: &empty_ns,
        };
        let r1 = render::render(&inputs);
        let r2 = render::render(&inputs);
        assert_eq!(hash_rendered(&r1), hash_rendered(&r2));
    }
}
