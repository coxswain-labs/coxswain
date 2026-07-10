//! [`RouteLike`] impl for `TCPRoute` — the TCPRoute-specific projections.
//! The kind-generic `Accepted`/`ResolvedRefs` algorithm lives in [`super::route_status`].

use super::route_status::{BackendRefView, ParentRefView, RouteLike};
use crate::gw_types::TcpRoute;

impl RouteLike for TcpRoute {
    fn route_namespace(&self) -> Option<&str> {
        self.metadata.namespace.as_deref()
    }

    fn route_name(&self) -> Option<&str> {
        self.metadata.name.as_deref()
    }

    fn route_hostnames(&self) -> Vec<&str> {
        // TCPRoute has no `hostnames` field — routing is by listener port only.
        Vec::new()
    }

    fn route_parent_refs(&self) -> Vec<ParentRefView<'_>> {
        self.spec
            .parent_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|pr| ParentRefView {
                namespace: pr.namespace.as_deref(),
                name: pr.name.as_str(),
                section_name: pr.section_name.as_deref(),
                port: pr.port.map(|p| p as u16),
                group: pr.group.as_deref(),
                kind: pr.kind.as_deref(),
            })
            .collect()
    }

    fn has_unsupported_filter(&self) -> bool {
        false
    }

    fn health_backend_refs(&self) -> Vec<BackendRefView<'_>> {
        self.spec
            .rules
            .iter()
            .flat_map(|rule| {
                rule.backend_refs.iter().map(|b| BackendRefView {
                    kind: b.kind.as_deref().unwrap_or("Service"),
                    group: b.group.as_deref().unwrap_or(""),
                    namespace: b.namespace.as_deref(),
                    name: &b.name,
                    has_port: b.port.is_some(),
                })
            })
            .collect()
    }
}
