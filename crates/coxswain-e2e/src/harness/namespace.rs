use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::networking::v1::IngressClass;
use kube::{
    Api, Client,
    api::{DeleteParams, ObjectMeta, PostParams},
};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct NamespaceGuard {
    pub name: String,
    client: Client,
}

impl NamespaceGuard {
    pub async fn create(client: &Client, prefix: &str) -> anyhow::Result<Self> {
        // Include the process ID so names are unique across test runs even when
        // a previous run left namespaces in Terminating state.
        let pid = std::process::id();
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("{prefix}-{pid}-{id}");
        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                labels: Some([("coxswain-e2e".to_string(), "true".to_string())].into()),
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
pub struct IngressClassGuard {
    pub name: String,
    client: Client,
}

impl IngressClassGuard {
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
