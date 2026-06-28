//! Kubernetes ownership helpers — object identity keys and Gateway ownership tracking.

use crate::shared::Shared;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::HashSet;

/// A key identifying a specific Kubernetes object by namespace and name.
///
/// "Object" is the K8s term for an instance (a Pod, a Gateway); "resource" refers to
/// the API endpoint type. Matches the terminology used by `kube`'s `ObjectRef`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

    /// Construct an [`ObjectKey`] from a Kubernetes [`ObjectMeta`], returning
    /// `None` if either `namespace` or `name` is absent.
    ///
    /// Convenience for the common `filter_map` pattern:
    /// ```ignore
    /// resources.filter_map(|r| ObjectKey::from_meta(&r.metadata))
    /// ```
    #[must_use]
    pub fn from_meta(meta: &ObjectMeta) -> Option<Self> {
        Some(Self::new(meta.namespace.as_deref()?, meta.name.as_deref()?))
    }
}

/// Formats as `"namespace/name"` for use in wire-protocol object keys and log messages.
impl std::fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ns, self.name)
    }
}

/// Parses `"namespace/name"` from a wire-protocol object key.
///
/// # Errors
///
/// Returns an error if the string does not contain exactly one `/`.
impl std::str::FromStr for ObjectKey {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ns, name) = s.split_once('/').ok_or(())?;
        Ok(Self::new(ns, name))
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
    owned.iter().any(|k| k.ns == ns && k.name == name)
}

#[cfg(test)]
mod tests {
    use crate::ownership::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn owned(pairs: &[(&str, &str)]) -> HashSet<ObjectKey> {
        pairs
            .iter()
            .map(|(ns, name)| ObjectKey::new(*ns, *name))
            .collect()
    }

    #[test]
    fn defaults_group_and_kind() {
        let set = owned(&[("default", "gw")]);
        assert!(parent_ref_owned(None, None, None, "gw", "default", &set));
    }

    #[test]
    fn explicit_correct_group_and_kind() {
        let set = owned(&[("default", "gw")]);
        assert!(parent_ref_owned(
            Some("gateway.networking.k8s.io"),
            Some("Gateway"),
            None,
            "gw",
            "default",
            &set
        ));
    }

    #[test]
    fn wrong_group_returns_false() {
        let set = owned(&[("default", "gw")]);
        assert!(!parent_ref_owned(
            Some("networking.istio.io"),
            None,
            None,
            "gw",
            "default",
            &set
        ));
    }

    #[test]
    fn wrong_kind_returns_false() {
        let set = owned(&[("default", "gw")]);
        assert!(!parent_ref_owned(
            None,
            Some("GatewayClass"),
            None,
            "gw",
            "default",
            &set
        ));
    }

    #[test]
    fn uses_default_ns_when_namespace_is_none() {
        let set = owned(&[("infra", "gw")]);
        assert!(parent_ref_owned(None, None, None, "gw", "infra", &set));
        assert!(!parent_ref_owned(None, None, None, "gw", "default", &set));
    }

    #[test]
    fn explicit_cross_namespace() {
        let set = owned(&[("infra", "gw")]);
        assert!(parent_ref_owned(
            None,
            None,
            Some("infra"),
            "gw",
            "default",
            &set
        ));
    }

    #[test]
    fn unknown_gateway_returns_false() {
        let set = owned(&[("default", "gw")]);
        assert!(!parent_ref_owned(
            None, None, None, "other-gw", "default", &set
        ));
    }

    #[test]
    fn owned_gateways_store_and_load() {
        let og = OwnedGateways::new();
        assert!(og.load().is_empty());
        let mut set = HashSet::new();
        set.insert(ObjectKey::new("ns", "gw"));
        og.store(Arc::new(set));
        assert!(og.load().contains(&ObjectKey::new("ns", "gw")));
    }

    #[test]
    fn owned_gateways_clone_shares_state() {
        let og = OwnedGateways::new();
        let og2 = og.clone();
        let mut set = HashSet::new();
        set.insert(ObjectKey::new("ns", "gw"));
        og.store(Arc::new(set));
        assert!(og2.load().contains(&ObjectKey::new("ns", "gw")));
    }
}
