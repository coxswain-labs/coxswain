//! `ReferenceGrant` flattening shared by the shared-proxy reconciler and the
//! dedicated-mode controller's RBAC reconciler.
//!
//! Both consumers must derive identical permitted-reference sets from the
//! same input: divergence means the controller grants Kubernetes RBAC for a
//! reference the data plane refuses to honour (or vice versa), producing
//! Gateway API ReferenceGrant conformance violations. Centralising the
//! flatten logic here makes that divergence impossible by construction.

use crate::gw_types::v::referencegrants::ReferenceGrant;
use coxswain_core::reference_grants::ReferenceGrantKey;
use std::collections::HashSet;
use std::sync::Arc;

/// A flattened set of permitted cross-namespace references, keyed for O(1)
/// lookup via [`ReferenceGrantKey`].
pub type GrantSet = HashSet<ReferenceGrantKey>;

/// Flatten `ReferenceGrant` objects into the two O(1) sets every consumer
/// needs for cross-namespace reference checks:
///
/// - `backend_grants`: `HTTPRoute → Service` (used by the routing-table
///   builder when resolving HTTPRoute `backendRefs` across namespaces).
/// - `cert_grants`: `Gateway → Secret` (used by the TLS store builder and
///   the dedicated-mode controller when resolving listener `certificateRefs`
///   across namespaces).
///
/// The filter rules mirror the Gateway API spec: `from.group` must be
/// `gateway.networking.k8s.io` and `to.group` must be empty (core API group)
/// or the literal `"core"`. A `to.name` of `None` flattens to a wildcard
/// [`ReferenceGrantKey::wildcard`]; a `Some(name)` flattens to a
/// [`ReferenceGrantKey::specific`].
#[must_use]
pub fn flatten_grants(grants: &[Arc<ReferenceGrant>]) -> (GrantSet, GrantSet) {
    let backend_grants = flatten(grants, "HTTPRoute", "Service");
    let cert_grants = flatten(grants, "Gateway", "Secret");
    (backend_grants, cert_grants)
}

fn flatten(grants: &[Arc<ReferenceGrant>], from_kind: &str, to_kind: &str) -> GrantSet {
    grants
        .iter()
        .filter_map(|grant| {
            let to_ns = grant.metadata.namespace.clone()?;
            Some((grant, to_ns))
        })
        .flat_map(|(grant, to_ns)| {
            let from_entries: Vec<_> = grant
                .spec
                .from
                .iter()
                .filter(|f| f.group == "gateway.networking.k8s.io" && f.kind == from_kind)
                .map(|f| f.namespace.clone())
                .collect();
            let to_entries: Vec<_> = grant
                .spec
                .to
                .iter()
                .filter(|t| (t.group.is_empty() || t.group == "core") && t.kind == to_kind)
                .map(|t| t.name.clone())
                .collect();
            from_entries.into_iter().flat_map(move |from_ns| {
                let to_ns = to_ns.clone();
                to_entries
                    .clone()
                    .into_iter()
                    .map(move |to_name| match to_name {
                        Some(name) => {
                            ReferenceGrantKey::specific(from_ns.clone(), to_ns.clone(), name)
                        }
                        None => ReferenceGrantKey::wildcard(from_ns.clone(), to_ns.clone()),
                    })
            })
        })
        .collect()
}
