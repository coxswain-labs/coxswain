use k8s_openapi::api::core::v1::Namespace;
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
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("{prefix}-{id}");
        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                labels: Some(
                    [("coxswain-e2e".to_string(), "true".to_string())].into(),
                ),
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
