//! Kubernetes ownership helpers — object identity keys and Gateway ownership tracking.

use crate::shared::Shared;
use std::collections::HashSet;

/// A key identifying a specific Kubernetes object by namespace and name.
///
/// "Object" is the K8s term for an instance (a Pod, a Gateway); "resource" refers to
/// the API endpoint type. Matches the terminology used by `kube`'s `ObjectRef`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectKey {
    /// Kubernetes namespace.
    pub ns: String,
    /// Resource name within the namespace.
    pub name: String,
}

impl ObjectKey {
    /// Construct an [`ObjectKey`] from namespace and name strings.
    pub fn new(ns: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            ns: ns.into(),
            name: name.into(),
        }
    }
}

/// Shared snapshot of Gateway objects managed by Coxswain.
pub type OwnedGateways = Shared<HashSet<ObjectKey>>;

/// Returns true if the given `ParentReference` fields refer to a Gateway managed by Coxswain.
///
/// Applies the Gateway API defaults:
///   - `group` defaults to `"gateway.networking.k8s.io"`
///   - `kind` defaults to `"Gateway"`
///   - `namespace` defaults to `default_ns` (the HTTPRoute's own namespace)
pub fn parent_ref_owned(
    group: Option<&str>,
    kind: Option<&str>,
    namespace: Option<&str>,
    name: &str,
    default_ns: &str,
    owned: &HashSet<ObjectKey>,
) -> bool {
    let group = group.unwrap_or("gateway.networking.k8s.io");
    let kind = kind.unwrap_or("Gateway");
    if group != "gateway.networking.k8s.io" || kind != "Gateway" {
        return false;
    }
    let ns = namespace.unwrap_or(default_ns);
    owned.contains(&ObjectKey::new(ns, name))
}
