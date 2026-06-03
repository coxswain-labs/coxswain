use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::time::SystemTime;

/// Converts a Kubernetes `ObjectMeta.creation_timestamp` to a `SystemTime`, if present.
pub(crate) fn metadata_created_at(meta: &ObjectMeta) -> Option<SystemTime> {
    meta.creation_timestamp
        .as_ref()
        .and_then(|t| t.0.as_millisecond().try_into().ok())
        .map(|ms: u64| SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms))
}
