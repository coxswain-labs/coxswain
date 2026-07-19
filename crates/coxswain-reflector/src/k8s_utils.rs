//! Small Kubernetes API helpers shared across controller sub-modules.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Client, api::Api};
use std::time::SystemTime;
use thiserror::Error;

/// Returns a namespaced API when `ns` is `Some`, a cluster-wide API when `None`.
pub fn scoped_api<T>(client: Client, ns: Option<&str>) -> Api<T>
where
    T: kube::Resource<Scope = kube::core::NamespaceResourceScope>,
    T::DynamicType: Default,
{
    match ns {
        Some(ns) => Api::namespaced(client, ns),
        None => Api::all(client),
    }
}

/// Which Kubernetes namespaces the controller's reflectors watch.
///
/// Built once at the argument boundary from `--watch-namespace`
/// (parse-don't-validate, [`WatchScope::parse`]). Downstream code never
/// re-parses the raw flag: [`ClusterWide`](WatchScope::ClusterWide) means one
/// cluster-wide `Api::all` watch per resource type, and
/// [`Namespaces`](WatchScope::Namespaces) means one namespaced watch per listed
/// namespace per type (merged into a single logical store). This is the
/// least-privilege lockdown surface — a static namespace list maps to a
/// namespaced `Role` per entry, so the controller needs no cluster-wide read.
///
/// Cluster-scoped resources (e.g. `GatewayClass`, `Namespace`) are always
/// watched cluster-wide regardless of this scope; only namespaced resources
/// honour it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchScope {
    /// Watch every namespace (`Api::all`). The flag was omitted or empty.
    ClusterWide,
    /// Watch only the listed namespaces. Non-empty, de-duplicated, order
    /// preserved (invariant upheld by [`WatchScope::parse`]).
    Namespaces(Vec<String>),
}

/// Error returned by [`WatchScope::parse`].
#[derive(Debug, Error)]
pub enum WatchScopeError {
    /// A comma-delimited `--watch-namespace` entry was empty after trimming
    /// (e.g. `ns1,,ns2` or a trailing comma) — a likely typo that would
    /// otherwise silently drop a namespace from the watch set.
    #[error("--watch-namespace contains an empty namespace entry")]
    EmptyEntry,
}

impl WatchScope {
    /// Parse a raw `--watch-namespace` value into a scope.
    ///
    /// `None` (flag omitted) and an all-whitespace value both yield
    /// [`WatchScope::ClusterWide`]. Otherwise the value is split on `,`, each
    /// entry trimmed; order is preserved and duplicates removed. A single-entry
    /// list is the exact equivalent of the pre-list single-namespace behaviour.
    ///
    /// # Errors
    ///
    /// Returns [`WatchScopeError::EmptyEntry`] when any comma-delimited entry is
    /// empty after trimming, rather than silently dropping it.
    #[must_use = "the parsed watch scope selects which namespaces are watched; dropping it silently watches cluster-wide"]
    pub fn parse(raw: Option<&str>) -> Result<Self, WatchScopeError> {
        let Some(raw) = raw else {
            return Ok(Self::ClusterWide);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(Self::ClusterWide);
        }
        let mut namespaces: Vec<String> = Vec::new();
        for part in trimmed.split(',') {
            let ns = part.trim();
            if ns.is_empty() {
                return Err(WatchScopeError::EmptyEntry);
            }
            if !namespaces.iter().any(|existing| existing == ns) {
                namespaces.push(ns.to_string());
            }
        }
        Ok(Self::Namespaces(namespaces))
    }

    /// Return this scope widened to also include `ns`, for namespaced resources
    /// whose objects can live in the controller's own namespace as well as the
    /// watched tenant namespaces — e.g. `Pod` (the shared-proxy fleet pods live
    /// in `coxswain-system`, dedicated-proxy pods in the tenant namespaces) and
    /// the `CoxswainGatewayParameters` / `CoxswainIngressClassParameters` CRs a
    /// `parametersRef` may resolve to cluster infra. Scoping these to
    /// `watched ∪ {own}` — rather than cluster-wide — is what lets the lockdown
    /// grant a namespaced `Role` instead of cluster-wide read (#59).
    ///
    /// [`ClusterWide`](WatchScope::ClusterWide) is returned unchanged: with no
    /// tenant restriction there is nothing to widen. A `ns` already in the list
    /// is not duplicated.
    #[must_use]
    pub fn with_namespace(&self, ns: &str) -> Self {
        match self {
            Self::ClusterWide => Self::ClusterWide,
            Self::Namespaces(namespaces) => {
                let mut extended = namespaces.clone();
                // Guard against an empty `ns` (e.g. an unset `pod_namespace`):
                // widening with `""` would spawn a malformed `Api::namespaced(_, "")`
                // watch whose readiness barrier never completes. Never widen with it.
                if !ns.is_empty() && !extended.iter().any(|existing| existing == ns) {
                    extended.push(ns.to_string());
                }
                Self::Namespaces(extended)
            }
        }
    }

    /// The per-store namespace scopes to spawn reflectors for: a single `None`
    /// (one cluster-wide watch) for [`ClusterWide`](WatchScope::ClusterWide), or
    /// one `Some(ns)` per listed namespace. Each item maps to exactly one
    /// reflector + store; the results are merged into one logical store.
    ///
    /// Runs once at startup, so the small `Vec` allocation is not hot-path.
    #[must_use]
    pub fn api_scopes(&self) -> Vec<Option<&str>> {
        match self {
            Self::ClusterWide => vec![None],
            Self::Namespaces(namespaces) => namespaces.iter().map(|ns| Some(ns.as_str())).collect(),
        }
    }
}

/// Converts a Kubernetes `ObjectMeta.creation_timestamp` to a `SystemTime`, if present.
pub fn metadata_created_at(meta: &ObjectMeta) -> Option<SystemTime> {
    meta.creation_timestamp
        .as_ref()
        .and_then(|t| t.0.as_millisecond().try_into().ok())
        .map(|ms: u64| SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms))
}

#[cfg(test)]
mod tests {
    use super::{WatchScope, WatchScopeError};

    #[test]
    fn omitted_flag_is_cluster_wide() {
        assert_eq!(WatchScope::parse(None).unwrap(), WatchScope::ClusterWide);
    }

    #[test]
    fn empty_and_whitespace_value_is_cluster_wide() {
        assert_eq!(
            WatchScope::parse(Some("")).unwrap(),
            WatchScope::ClusterWide
        );
        assert_eq!(
            WatchScope::parse(Some("   ")).unwrap(),
            WatchScope::ClusterWide
        );
    }

    #[test]
    fn single_namespace_is_a_one_element_list() {
        assert_eq!(
            WatchScope::parse(Some("team-a")).unwrap(),
            WatchScope::Namespaces(vec!["team-a".to_string()])
        );
    }

    #[test]
    fn comma_list_is_trimmed_and_order_preserved() {
        assert_eq!(
            WatchScope::parse(Some(" ns1 , ns2 ,ns3")).unwrap(),
            WatchScope::Namespaces(vec![
                "ns1".to_string(),
                "ns2".to_string(),
                "ns3".to_string(),
            ])
        );
    }

    #[test]
    fn duplicates_are_removed_preserving_first_position() {
        assert_eq!(
            WatchScope::parse(Some("ns1,ns2,ns1")).unwrap(),
            WatchScope::Namespaces(vec!["ns1".to_string(), "ns2".to_string()])
        );
    }

    #[test]
    fn empty_entry_is_rejected() {
        assert!(matches!(
            WatchScope::parse(Some("ns1,,ns2")),
            Err(WatchScopeError::EmptyEntry)
        ));
        assert!(matches!(
            WatchScope::parse(Some("ns1,")),
            Err(WatchScopeError::EmptyEntry)
        ));
    }

    #[test]
    fn api_scopes_cluster_wide_is_single_none() {
        assert_eq!(WatchScope::ClusterWide.api_scopes(), vec![None]);
    }

    #[test]
    fn api_scopes_lists_each_namespace() {
        let scope = WatchScope::Namespaces(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(scope.api_scopes(), vec![Some("a"), Some("b")]);
    }

    #[test]
    fn with_namespace_leaves_cluster_wide_unchanged() {
        assert_eq!(
            WatchScope::ClusterWide.with_namespace("coxswain-system"),
            WatchScope::ClusterWide
        );
    }

    #[test]
    fn with_namespace_appends_own_namespace_to_a_list() {
        let scope = WatchScope::Namespaces(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(
            scope.with_namespace("coxswain-system"),
            WatchScope::Namespaces(vec![
                "a".to_string(),
                "b".to_string(),
                "coxswain-system".to_string(),
            ])
        );
    }

    #[test]
    fn with_namespace_does_not_duplicate_an_already_watched_namespace() {
        let scope = WatchScope::Namespaces(vec!["a".to_string(), "coxswain-system".to_string()]);
        assert_eq!(
            scope.with_namespace("coxswain-system"),
            WatchScope::Namespaces(vec!["a".to_string(), "coxswain-system".to_string()])
        );
    }

    #[test]
    fn with_namespace_ignores_an_empty_namespace() {
        let scope = WatchScope::Namespaces(vec!["a".to_string()]);
        assert_eq!(
            scope.with_namespace(""),
            WatchScope::Namespaces(vec!["a".to_string()]),
            "an empty namespace must never be added — it would spawn a malformed watch"
        );
    }
}
