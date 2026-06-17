//! RAII guards for test-scoped `Namespace` and `IngressClass` resources.

use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::networking::v1::IngressClass;
use kube::{
    Api, Client,
    api::{DeleteParams, ObjectMeta, PostParams},
};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// RAII guard for a test-scoped Kubernetes namespace; deletes the namespace on drop.
pub struct NamespaceGuard {
    /// Name of the created namespace.
    pub name: String,
}

impl NamespaceGuard {
    /// Create a uniquely-named namespace with the given `prefix` and return its guard.
    ///
    /// Carries the `coxswain-e2e=true` label so the bootstrap's "purge
    /// leftover e2e namespaces" step removes it between tests if the
    /// `NamespaceGuard`'s `Drop` deletion hasn't completed yet. Use
    /// [`Self::create_persistent`] when the namespace must survive a
    /// `Harness::start()` mid-test (controller-restart-idempotency tests).
    pub async fn create(client: &Client, prefix: &str) -> anyhow::Result<Self> {
        Self::create_inner(client, prefix, /* purgeable = */ true).await
    }

    /// Same as [`Self::create`] but omits the `coxswain-e2e=true` label so
    /// the bootstrap purge does not target this namespace. Intended for
    /// tests that call `Harness::start()` more than once and need the
    /// namespace's resources to persist across the second start (i.e. the
    /// SSA-idempotency test for controller restarts). Cleanup still runs on
    /// `Drop`, so a normal end-of-test path deletes the namespace; a panic
    /// or interrupt leaves it behind until the next manual cleanup
    /// (`kubectl delete ns <name>`).
    pub async fn create_persistent(client: &Client, prefix: &str) -> anyhow::Result<Self> {
        Self::create_inner(client, prefix, /* purgeable = */ false).await
    }

    async fn create_inner(client: &Client, prefix: &str, purgeable: bool) -> anyhow::Result<Self> {
        // Include the process ID so names are unique across test runs even when
        // a previous run left namespaces in Terminating state.
        let pid = std::process::id();
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("{prefix}-{pid}-{id}");
        let labels = if purgeable {
            Some([("coxswain-e2e".to_string(), "true".to_string())].into())
        } else {
            None
        };
        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                labels,
                ..Default::default()
            },
            ..Default::default()
        };
        let api: Api<Namespace> = Api::all(client.clone());
        api.create(&PostParams::default(), &ns).await?;
        tracing::debug!(namespace = %name, "created test namespace");
        Ok(Self { name })
    }
}

impl Drop for NamespaceGuard {
    fn drop(&mut self) {
        // Use `kubectl delete ns -l coxswain-e2e=true` to clean up after an interrupt.
        delete_resource::<Namespace>(self.name.clone(), "namespace");
    }
}

/// Issue a blocking `DELETE` for a cluster-scoped resource on a dedicated
/// thread that owns a fresh runtime *and* a fresh kube `Client`.
///
/// Two footguns this navigates, both rooted in `#[tokio::test]` building a
/// current-thread runtime that is torn down the instant the test fn returns:
///
/// 1. A `tokio::spawn`ed deletion in `Drop` is dropped before it ever issues the
///    DELETE — cleanup silently never runs, so namespaces (and their pods)
///    accumulate across the whole parallel pass and exhaust the node.
/// 2. A kube `Client`'s hyper connection pool is bound to the runtime it was
///    built on. Driving the test's client from another runtime leaves its IO
///    registered on a reactor nobody polls, so the request hangs forever. Hence
///    a brand-new client is constructed *inside* this runtime.
///
/// The thread is `join`ed so the DELETE completes before the (process-per-test)
/// test process exits. Errors are logged, not propagated: a failed delete is
/// backstopped by the bootstrap's label-purge, and a guard's `Drop` must not panic.
fn delete_resource<K>(name: String, kind: &'static str)
where
    K: kube::Resource<Scope = k8s_openapi::ClusterResourceScope>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned,
    K::DynamicType: Default,
{
    let handle = std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::warn!(error = %e, kind, %name, "could not build cleanup runtime");
                return;
            }
        };
        rt.block_on(async move {
            // Fresh client bound to THIS runtime — see footgun #2 above.
            let client = match Client::try_default().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, kind, %name, "could not build cleanup client");
                    return;
                }
            };
            let api: Api<K> = Api::all(client);
            match api.delete(&name, &DeleteParams::default()).await {
                Ok(_) => tracing::debug!(kind, %name, "deleted test resource"),
                Err(e) => tracing::warn!(error = %e, kind, %name, "failed to delete test resource"),
            }
        });
    });
    let _ = handle.join();
}

/// RAII guard for a cluster-scoped `IngressClass`. Deletes the IngressClass on
/// drop so test-only classes don't leak between runs.
pub struct IngressClassGuard {
    /// Name of the created IngressClass.
    pub name: String,
}

impl IngressClassGuard {
    /// Wrap an existing `IngressClass` name in a drop guard (does not create it).
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Drop for IngressClassGuard {
    fn drop(&mut self) {
        // Synchronous cleanup on an independent runtime — see [`delete_resource`]
        // for why a `tokio::spawn` here would silently never run.
        delete_resource::<IngressClass>(self.name.clone(), "ingressclass");
    }
}
