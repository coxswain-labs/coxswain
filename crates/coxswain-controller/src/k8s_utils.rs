use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Client, api::Api};
use std::time::SystemTime;

/// Returns a namespaced API when `ns` is `Some`, a cluster-wide API when `None`.
pub(crate) fn scoped_api<T>(client: Client, ns: Option<&str>) -> Api<T>
where
    T: kube::Resource<Scope = kube::core::NamespaceResourceScope>,
    T::DynamicType: Default,
{
    match ns {
        Some(ns) => Api::namespaced(client, ns),
        None => Api::all(client),
    }
}

/// Converts a Kubernetes `ObjectMeta.creation_timestamp` to a `SystemTime`, if present.
pub(crate) fn metadata_created_at(meta: &ObjectMeta) -> Option<SystemTime> {
    meta.creation_timestamp
        .as_ref()
        .and_then(|t| t.0.as_millisecond().try_into().ok())
        .map(|ms: u64| SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms))
}
