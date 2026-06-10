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
    client: Client,
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
        Ok(Self {
            name,
            client: client.clone(),
        })
    }
}

impl Drop for NamespaceGuard {
    fn drop(&mut self) {
        let client = self.client.clone();
        let name = self.name.clone();
        // Fire-and-forget deletion. Unique names mean a slow deletion never
        // affects the next test. Use `kubectl delete ns -l coxswain-e2e=true`
        // to clean up if tests were interrupted.
        tokio::spawn(async move {
            let api: Api<Namespace> = Api::all(client);
            let _ = api.delete(&name, &DeleteParams::default()).await;
            tracing::debug!(namespace = %name, "deleted test namespace");
        });
    }
}

/// RAII guard for a cluster-scoped `IngressClass`. Deletes the IngressClass on
/// drop so test-only classes don't leak between runs.
/// RAII guard for a cluster-scoped `IngressClass`. Deletes the IngressClass on
/// drop so test-only classes don't leak between runs.
pub struct IngressClassGuard {
    /// Name of the created IngressClass.
    pub name: String,
    client: Client,
}

impl IngressClassGuard {
    /// Wrap an existing `IngressClass` name in a drop guard (does not create it).
    pub fn new(client: &Client, name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            client: client.clone(),
        }
    }
}

impl Drop for IngressClassGuard {
    fn drop(&mut self) {
        let client = self.client.clone();
        let name = self.name.clone();
        tokio::spawn(async move {
            let api: Api<IngressClass> = Api::all(client);
            let _ = api.delete(&name, &DeleteParams::default()).await;
            tracing::debug!(ingress_class = %name, "deleted test IngressClass");
        });
    }
}
