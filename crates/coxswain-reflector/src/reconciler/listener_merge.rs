//! GEP-1713 ListenerSet → Gateway listener merge.
//!
//! Builds each owned Gateway's **effective** listener set: its own
//! `spec.listeners` concatenated with the listeners of every attached
//! [`ListenerSet`], gated by the parent Gateway's `spec.allowedListeners` and
//! ordered by the spec precedence (parent first, then ListenerSets oldest-first,
//! then alphabetical by `{namespace}/{name}`). Listeners that lose a
//! port-compatibility conflict to a higher-precedence listener are flagged
//! [`EffectiveListener::conflicted`] and are not programmed.
//!
//! The two spec listener types (`GatewayListeners` and `ListenerSetListeners`)
//! are distinct generated structs with identical fields; both are normalised into
//! one [`EffectiveListener`] carrying its [`ListenerSource`] provenance and the
//! namespace its `certificateRefs` resolve in (the Gateway's own namespace for a
//! Gateway listener, the ListenerSet's namespace for a ListenerSet listener).

use crate::MergedStore;
use std::collections::HashMap;

use k8s_openapi::api::core::v1::Namespace;
#[cfg(test)]
use kube::runtime::reflector;

use crate::gw_types::ListenerSet;
use crate::gw_types::v::gateways::{
    Gateway, GatewayAllowedListenersNamespacesFrom, GatewayListeners, GatewayListenersTlsMode,
};
use crate::gw_types::v::listenersets::{ListenerSetListeners, ListenerSetListenersTlsMode};
use crate::status::{ConflictReason, ListenerSource, RouteNamespaceSet};
use coxswain_core::ownership::ObjectKey;

/// One normalised `certificateRefs` entry (Gateway/ListenerSet share the shape).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EffectiveCertRef {
    /// Ref group; `None`/empty/`core` → the core API group.
    pub group: Option<String>,
    /// Ref kind; `None` → `Secret`.
    pub kind: Option<String>,
    /// Secret name.
    pub name: String,
    /// Secret namespace; `None` → the listener's owning namespace.
    pub namespace: Option<String>,
}

/// Normalised listener TLS config (mode + cert refs), shared across spec types.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EffectiveTls {
    /// `true` for `tls.mode: Passthrough`; `false` for `Terminate` (the default).
    pub passthrough: bool,
    /// `certificateRefs`, normalised. Resolved in the listener's owning namespace.
    pub certificate_refs: Vec<EffectiveCertRef>,
}

/// One listener in a Gateway's effective set, normalised from either spec type
/// and tagged with its provenance and cert-resolution namespace (GEP-1713).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EffectiveListener {
    /// Which resource declared this listener (drives status attribution + the
    /// per-listener status key [`crate::status::ListenerStatusKey`]).
    pub source: ListenerSource,
    /// Namespace this listener's `certificateRefs` resolve in: the Gateway's own
    /// namespace for a Gateway listener, the ListenerSet's namespace otherwise.
    pub owning_namespace: String,
    /// Listener name, unique only within its `source`.
    pub name: String,
    /// Listener port.
    pub port: i32,
    /// Network protocol (`HTTP`, `HTTPS`, `TLS`, …).
    pub protocol: String,
    /// Hostname match; `None`/empty matches all.
    pub hostname: Option<String>,
    /// TLS config when `protocol` is `HTTPS`/`TLS`.
    pub tls: Option<EffectiveTls>,
    /// Resolved `allowedRoutes.namespaces` policy (`from` + `selector`), resolved
    /// against the cluster Namespace store at merge time — see [`RouteNamespaceSet`].
    pub route_namespaces: RouteNamespaceSet,
    /// `allowedRoutes.kinds` as `(group, kind)` pairs (empty = use the protocol
    /// default). Carried so route-health can compute per-listener `allows_kind`
    /// for routes attached via this listener (GEP-1713).
    pub allowed_route_kinds: Vec<(Option<String>, String)>,
    /// Port-compatibility conflict reason, if any (GEP-1713).
    ///
    /// [`ConflictReason::None`] means the listener programs normally. Any other
    /// variant means it lost a conflict to a higher-precedence listener and must
    /// NOT be programmed; the reason drives the per-listener `Conflicted` condition.
    pub conflict: ConflictReason,
}

/// An owned Gateway plus its computed effective listener set.
#[non_exhaustive]
pub(crate) struct EffectiveGateway {
    /// The parent Gateway (carries class, namespace, infra, frontend/backend TLS).
    pub gateway: std::sync::Arc<Gateway>,
    /// Effective listeners in precedence order; conflicts flagged, not removed.
    pub listeners: Vec<EffectiveListener>,
}

/// Build the effective listener set for every owned Gateway (GEP-1713).
///
/// Seeds each owned Gateway with its own listeners, attaches each ListenerSet's
/// listeners to its parent Gateway when the parent's `allowedListeners` permits
/// it, orders by spec precedence, then flags port-compatibility conflicts. The
/// returned map is keyed by Gateway [`ObjectKey`].
pub(crate) fn merge_effective_gateways(
    gateways: &[std::sync::Arc<Gateway>],
    listener_sets: &[std::sync::Arc<ListenerSet>],
    owned_gateway_classes: &std::collections::HashSet<String>,
    namespaces: &MergedStore<Namespace>,
) -> HashMap<ObjectKey, EffectiveGateway> {
    // 1. Seed owned Gateways with their own listeners.
    let mut effective: HashMap<ObjectKey, EffectiveGateway> = HashMap::new();
    for gw in gateways {
        if !owned_gateway_classes.contains(&gw.spec.gateway_class_name) {
            continue;
        }
        let (Some(ns), Some(name)) = (gw.metadata.namespace.clone(), gw.metadata.name.clone())
        else {
            continue;
        };
        let key = ObjectKey::new(ns.clone(), name);
        let listeners = gw
            .spec
            .listeners
            .iter()
            .map(|l| from_gateway_listener(l, &ns, namespaces))
            .collect();
        effective.insert(
            key,
            EffectiveGateway {
                gateway: std::sync::Arc::clone(gw),
                listeners,
            },
        );
    }

    // 2. Group accepted ListenerSets by parent Gateway. Each entry carries the
    //    ListenerSet so step 3 can order by creationTimestamp then key.
    let mut by_parent: HashMap<ObjectKey, Vec<std::sync::Arc<ListenerSet>>> = HashMap::new();
    for ls in listener_sets {
        let (Some(ls_ns), Some(_)) = (
            ls.metadata.namespace.as_deref(),
            ls.metadata.name.as_deref(),
        ) else {
            continue;
        };
        let parent = parent_key(ls, ls_ns);
        // Parent must be an owned Gateway present in the effective map.
        let Some(parent_gw) = effective.get(&parent) else {
            continue;
        };
        if !listener_set_allowed(&parent_gw.gateway, ls_ns, namespaces) {
            continue;
        }
        by_parent
            .entry(parent)
            .or_default()
            .push(std::sync::Arc::clone(ls));
    }

    // 3. Append each parent's ListenerSets in precedence order
    //    (creationTimestamp ASC, then "{ns}/{name}" ASC).
    for (parent, mut sets) in by_parent {
        sets.sort_by(|a, b| {
            let ta = a.metadata.creation_timestamp.as_ref();
            let tb = b.metadata.creation_timestamp.as_ref();
            ta.cmp(&tb).then_with(|| ls_key(a).cmp(&ls_key(b)))
        });
        let Some(eff) = effective.get_mut(&parent) else {
            continue;
        };
        for ls in sets {
            let ls_obj_key = ls_object_key(&ls);
            let ls_ns = ls.metadata.namespace.clone().unwrap_or_default();
            for l in &ls.spec.listeners {
                eff.listeners.push(from_listenerset_listener(
                    l,
                    &ls_ns,
                    &ls_obj_key,
                    namespaces,
                ));
            }
        }
    }

    // 4. Flag port-compatibility conflicts (precedence order is already set).
    for eff in effective.values_mut() {
        flag_conflicts(&mut eff.listeners);
    }

    effective
}

/// One programmed effective listener's port identity, consumed by the
/// provisioning operator (GEP-1713, #93).
///
/// The operator must expose a Service port and allocate an internal port for the
/// Gateway's own listeners **and** every attached ListenerSet's listeners — not
/// just `spec.listeners` — or a ListenerSet listener on a new port is never
/// reachable. This carries the minimum the operator needs (`name`, `port`,
/// `protocol`); the heavier `EffectiveGateway`/`EffectiveListener` stay
/// crate-private.
// intentionally open: a port-identity DTO that may gain fields (e.g. appProtocol).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveListenerPort {
    /// ServicePort name — unique within the returned set (collisions from
    /// duplicate listener names across the Gateway and its ListenerSets are
    /// resolved by suffixing the port).
    pub name: String,
    /// Advertised listener port.
    pub port: u16,
    /// Listener protocol (`HTTP`, `HTTPS`, `TLS`, …); carried for parity with the
    /// existing per-listener Service-port rendering.
    pub protocol: String,
}

/// Per owned Gateway, the programmed effective listener ports — the Gateway's own
/// listeners plus those merged from attached ListenerSets (GEP-1713), in
/// precedence order, deduplicated on port and with collision-free names.
///
/// Reuses `merge_effective_gateways` so the provisioning operator and the data
/// plane derive identical port sets and can never drift. Conflicted listeners
/// (which lost a port-compatibility conflict and are not programmed) are omitted.
/// Precedence-first dedup means a Gateway listener's name and port survive over a
/// same-port ListenerSet listener, so existing Services don't churn — only new
/// ListenerSet ports are added.
#[must_use]
pub fn effective_listener_ports(
    gateways: &[std::sync::Arc<Gateway>],
    listener_sets: &[std::sync::Arc<ListenerSet>],
    owned_gateway_classes: &std::collections::HashSet<String>,
    namespaces: &MergedStore<Namespace>,
) -> HashMap<ObjectKey, Vec<EffectiveListenerPort>> {
    let effective =
        merge_effective_gateways(gateways, listener_sets, owned_gateway_classes, namespaces);
    effective
        .into_iter()
        .map(|(key, eg)| {
            let mut seen_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
            let mut seen_names: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            let mut ports = Vec::new();
            for l in eg.listeners {
                if l.conflict.is_conflicted() {
                    continue;
                }
                let Ok(port) = u16::try_from(l.port) else {
                    continue;
                };
                if !seen_ports.insert(port) {
                    continue;
                }
                // ServicePort names must be unique within a Service; duplicate
                // listener names are legal across a Gateway + its ListenerSets, so
                // suffix the port on collision.
                let mut name = l.name;
                if !seen_names.insert(name.clone()) {
                    name = format!("{name}-{port}");
                    seen_names.insert(name.clone());
                }
                ports.push(EffectiveListenerPort {
                    name,
                    port,
                    protocol: l.protocol,
                });
            }
            (key, ports)
        })
        .collect()
}

/// Resolve a ListenerSet's `spec.parentRef` to the parent Gateway [`ObjectKey`].
/// `parentRef.namespace` defaults to the ListenerSet's own namespace.
fn parent_key(ls: &ListenerSet, ls_ns: &str) -> ObjectKey {
    let pr = &ls.spec.parent_ref;
    let ns = pr.namespace.clone().unwrap_or_else(|| ls_ns.to_string());
    ObjectKey::new(ns, pr.name.clone())
}

/// The ListenerSet's own [`ObjectKey`] (`{namespace}/{name}`).
fn ls_object_key(ls: &ListenerSet) -> ObjectKey {
    ObjectKey::new(
        ls.metadata.namespace.clone().unwrap_or_default(),
        ls.metadata.name.clone().unwrap_or_default(),
    )
}

/// `"{namespace}/{name}"` precedence tie-break key for a ListenerSet.
fn ls_key(ls: &ListenerSet) -> String {
    ls_object_key(ls).to_string()
}

/// Whether `parent`'s `spec.allowedListeners` permits a ListenerSet in `ls_ns`.
///
/// Default (field absent) is `None` → reject. `Same` accepts only same-namespace
/// ListenerSets; `All` accepts any; `Selector` matches the ListenerSet's
/// namespace labels against the selector.
fn listener_set_allowed(
    parent: &Gateway,
    ls_ns: &str,
    namespaces: &MergedStore<Namespace>,
) -> bool {
    let from = parent
        .spec
        .allowed_listeners
        .as_ref()
        .and_then(|al| al.namespaces.as_ref())
        .and_then(|n| n.from.as_ref());
    match from {
        None | Some(GatewayAllowedListenersNamespacesFrom::None) => false,
        Some(GatewayAllowedListenersNamespacesFrom::All) => true,
        Some(GatewayAllowedListenersNamespacesFrom::Same) => {
            parent.metadata.namespace.as_deref() == Some(ls_ns)
        }
        Some(GatewayAllowedListenersNamespacesFrom::Selector) => {
            let Some(selector) = parent
                .spec
                .allowed_listeners
                .as_ref()
                .and_then(|al| al.namespaces.as_ref())
                .and_then(|n| n.selector.as_ref())
            else {
                return false; // Selector requires a selector; absent → match nothing.
            };
            let labels = namespace_labels(namespaces, ls_ns);
            selector_matches(
                selector.match_labels.as_ref(),
                selector.match_expressions.as_deref(),
                &labels,
            )
        }
    }
}

/// Read the labels of namespace `ns` from the cluster-wide Namespace store.
fn namespace_labels(
    namespaces: &MergedStore<Namespace>,
    ns: &str,
) -> std::collections::BTreeMap<String, String> {
    namespaces
        .state()
        .into_iter()
        .find(|n| n.metadata.name.as_deref() == Some(ns))
        .and_then(|n| n.metadata.labels.clone())
        .unwrap_or_default()
}

/// Evaluate a Kubernetes label selector against a label set, on already-normalised
/// `matchExpressions` (`(key, operator, values)` tuples) ANDed with `matchLabels`.
/// An empty selector matches everything. Codegen produces a distinct selector type
/// per call site (Gateway `allowedListeners`, Gateway/ListenerSet `allowedRoutes`),
/// so callers normalise into this one evaluator.
fn labels_match_selector(
    match_labels: Option<&std::collections::BTreeMap<String, String>>,
    match_expressions: &[(&str, &str, &[String])],
    labels: &std::collections::BTreeMap<String, String>,
) -> bool {
    if let Some(ml) = match_labels {
        for (k, v) in ml {
            if labels.get(k) != Some(v) {
                return false;
            }
        }
    }
    for (key, operator, values) in match_expressions {
        let present = labels.get(*key);
        let ok = match *operator {
            "In" => present.is_some_and(|v| values.iter().any(|x| x == v)),
            "NotIn" => present.is_none_or(|v| !values.iter().any(|x| x == v)),
            "Exists" => present.is_some(),
            "DoesNotExist" => present.is_none(),
            // Unknown operator: fail closed (do not attach).
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Evaluate a Gateway `allowedListeners` namespace selector against a label set.
fn selector_matches(
    match_labels: Option<&std::collections::BTreeMap<String, String>>,
    match_expressions: Option<
        &[crate::gw_types::v::gateways::GatewayAllowedListenersNamespacesSelectorMatchExpressions],
    >,
    labels: &std::collections::BTreeMap<String, String>,
) -> bool {
    let exprs: Vec<(&str, &str, &[String])> = match_expressions
        .unwrap_or(&[])
        .iter()
        .map(|e| {
            (
                e.key.as_str(),
                e.operator.as_str(),
                e.values.as_deref().unwrap_or(&[]),
            )
        })
        .collect();
    labels_match_selector(match_labels, &exprs, labels)
}

/// Normalised `allowedRoutes.namespaces.from` (Gateway and ListenerSet share these
/// three values; unlike `allowedListeners` there is no `None`, and absent → `Same`).
enum RouteNsFrom {
    All,
    Same,
    Selector,
}

/// Resolve an `allowedRoutes.namespaces` policy to a concrete [`RouteNamespaceSet`]
/// against the cluster Namespace store. `Selector` is materialised to the set of
/// matching namespace names NOW; a later namespace label change re-drives the merge
/// (the Namespace reflector is a rebuild trigger), so the set stays current.
fn resolve_route_namespaces(
    from: RouteNsFrom,
    match_labels: Option<&std::collections::BTreeMap<String, String>>,
    match_expressions: &[(&str, &str, &[String])],
    owning_ns: &str,
    namespaces: &MergedStore<Namespace>,
) -> RouteNamespaceSet {
    match from {
        RouteNsFrom::All => RouteNamespaceSet::All,
        RouteNsFrom::Same => {
            RouteNamespaceSet::Only(std::iter::once(owning_ns.to_string()).collect())
        }
        RouteNsFrom::Selector => {
            let mut set = std::collections::BTreeSet::new();
            for ns in namespaces.state() {
                let Some(name) = ns.metadata.name.as_deref() else {
                    continue;
                };
                let labels = ns.metadata.labels.clone().unwrap_or_default();
                if labels_match_selector(match_labels, match_expressions, &labels) {
                    set.insert(name.to_string());
                }
            }
            RouteNamespaceSet::Only(set)
        }
    }
}

/// Normalise a Gateway's own listener.
fn from_gateway_listener(
    l: &GatewayListeners,
    gw_ns: &str,
    namespaces: &MergedStore<Namespace>,
) -> EffectiveListener {
    let tls = l.tls.as_ref().map(|t| EffectiveTls {
        passthrough: matches!(t.mode, Some(GatewayListenersTlsMode::Passthrough)),
        certificate_refs: t
            .certificate_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|r| EffectiveCertRef {
                group: r.group.clone(),
                kind: r.kind.clone(),
                name: r.name.clone(),
                namespace: r.namespace.clone(),
            })
            .collect(),
    });
    EffectiveListener {
        source: ListenerSource::Gateway,
        owning_namespace: gw_ns.to_string(),
        name: l.name.clone(),
        port: l.port,
        protocol: l.protocol.clone(),
        hostname: l.hostname.clone(),
        tls,
        route_namespaces: gw_route_namespaces(l, gw_ns, namespaces),
        allowed_route_kinds: l
            .allowed_routes
            .as_ref()
            .and_then(|ar| ar.kinds.as_ref())
            .map(|kinds| {
                kinds
                    .iter()
                    .map(|k| (k.group.clone(), k.kind.clone()))
                    .collect()
            })
            .unwrap_or_default(),
        conflict: ConflictReason::None,
    }
}

/// Normalise a ListenerSet listener, tagging it with its source ListenerSet and
/// the namespace its `certificateRefs` resolve in (the ListenerSet's own).
fn from_listenerset_listener(
    l: &ListenerSetListeners,
    ls_ns: &str,
    ls_key: &ObjectKey,
    namespaces: &MergedStore<Namespace>,
) -> EffectiveListener {
    let tls = l.tls.as_ref().map(|t| EffectiveTls {
        passthrough: matches!(t.mode, Some(ListenerSetListenersTlsMode::Passthrough)),
        certificate_refs: t
            .certificate_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|r| EffectiveCertRef {
                group: r.group.clone(),
                kind: r.kind.clone(),
                name: r.name.clone(),
                namespace: r.namespace.clone(),
            })
            .collect(),
    });
    EffectiveListener {
        source: ListenerSource::ListenerSet(ls_key.clone()),
        owning_namespace: ls_ns.to_string(),
        name: l.name.clone(),
        port: l.port,
        protocol: l.protocol.clone(),
        hostname: l.hostname.clone(),
        tls,
        route_namespaces: ls_route_namespaces(l, ls_ns, namespaces),
        allowed_route_kinds: l
            .allowed_routes
            .as_ref()
            .and_then(|ar| ar.kinds.as_ref())
            .map(|kinds| {
                kinds
                    .iter()
                    .map(|k| (k.group.clone(), k.kind.clone()))
                    .collect()
            })
            .unwrap_or_default(),
        conflict: ConflictReason::None,
    }
}

/// Resolve a Gateway listener's `allowedRoutes.namespaces` to a [`RouteNamespaceSet`].
fn gw_route_namespaces(
    l: &GatewayListeners,
    gw_ns: &str,
    namespaces: &MergedStore<Namespace>,
) -> RouteNamespaceSet {
    use crate::gw_types::v::gateways::GatewayListenersAllowedRoutesNamespacesFrom as F;
    let cfg = l
        .allowed_routes
        .as_ref()
        .and_then(|ar| ar.namespaces.as_ref());
    let from = match cfg.and_then(|ns| ns.from.as_ref()) {
        Some(F::All) => RouteNsFrom::All,
        Some(F::Selector) => RouteNsFrom::Selector,
        // `Some(Same)` or absent → `Same` (the Gateway API default).
        _ => RouteNsFrom::Same,
    };
    let selector = cfg.and_then(|ns| ns.selector.as_ref());
    let match_labels = selector.and_then(|s| s.match_labels.as_ref());
    let exprs: Vec<(&str, &str, &[String])> = selector
        .and_then(|s| s.match_expressions.as_deref())
        .unwrap_or(&[])
        .iter()
        .map(|e| {
            (
                e.key.as_str(),
                e.operator.as_str(),
                e.values.as_deref().unwrap_or(&[]),
            )
        })
        .collect();
    resolve_route_namespaces(from, match_labels, &exprs, gw_ns, namespaces)
}

/// Resolve a ListenerSet listener's `allowedRoutes.namespaces` to a [`RouteNamespaceSet`].
fn ls_route_namespaces(
    l: &ListenerSetListeners,
    ls_ns: &str,
    namespaces: &MergedStore<Namespace>,
) -> RouteNamespaceSet {
    use crate::gw_types::v::listenersets::ListenerSetListenersAllowedRoutesNamespacesFrom as F;
    let cfg = l
        .allowed_routes
        .as_ref()
        .and_then(|ar| ar.namespaces.as_ref());
    let from = match cfg.and_then(|ns| ns.from.as_ref()) {
        Some(F::All) => RouteNsFrom::All,
        Some(F::Selector) => RouteNsFrom::Selector,
        _ => RouteNsFrom::Same,
    };
    let selector = cfg.and_then(|ns| ns.selector.as_ref());
    let match_labels = selector.and_then(|s| s.match_labels.as_ref());
    let exprs: Vec<(&str, &str, &[String])> = selector
        .and_then(|s| s.match_expressions.as_deref())
        .unwrap_or(&[])
        .iter()
        .map(|e| {
            (
                e.key.as_str(),
                e.operator.as_str(),
                e.values.as_deref().unwrap_or(&[]),
            )
        })
        .collect();
    resolve_route_namespaces(from, match_labels, &exprs, ls_ns, namespaces)
}

/// Flag listeners that are incompatible with a higher-precedence listener on the
/// same port. `listeners` is already in precedence order; the first listener to
/// claim a `(port)` wins, and a later listener on that port conflicts unless it
/// is compatible (same protocol AND a distinct, non-empty hostname).
///
/// Known limitation (GEP-3567 × GEP-1713): two compatible same-port listeners from
/// *different* sources (a Gateway listener and one of its ListenerSet's listeners)
/// both program and share the parent Gateway's bind port, but the routing-table
/// listener-isolation pass scopes misdirected-request (421) isolation per source.
/// So a route on the broader listener is not isolated from a more-specific
/// sibling on the other source. Accepted as a follow-up; not "cannot happen".
fn flag_conflicts(listeners: &mut [EffectiveListener]) {
    // Winners per port: (protocol, hostname) of every listener that programmed.
    let mut claimed: HashMap<i32, Vec<(String, String)>> = HashMap::new();
    for l in listeners.iter_mut() {
        let host = l.hostname.clone().unwrap_or_default();
        let entry = claimed.entry(l.port).or_default();
        if entry.iter().all(|(proto, h)| {
            // Compatible when the protocol matches and the hostnames are DISTINCT
            // strings. Gateway API allows many listeners on one port as long as
            // each has a different `hostname` — including an empty (catch-all)
            // hostname alongside specific ones (GEP-3567 listener isolation routes
            // by most-specific match, then 421s misdirected requests). Only an
            // identical hostname (two empties, or two equal hosts) overlaps and
            // conflicts; overlapping-but-distinct hosts (`*.x` vs `a.x`) do not.
            proto == &l.protocol && h != &host
        }) {
            entry.push((l.protocol.clone(), host));
        } else {
            // Protocol conflict: any winner on this port has a different protocol.
            // Hostname conflict: all winners share the same protocol but hostnames
            // overlap (either empty/wildcard or identical).
            l.conflict = if entry.iter().any(|(proto, _)| proto != &l.protocol) {
                ConflictReason::ProtocolConflict
            } else {
                ConflictReason::HostnameConflict
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gw_types::v::gateways::{
        GatewayAllowedListeners, GatewayAllowedListenersNamespaces,
        GatewayListenersAllowedRoutesNamespacesFrom, GatewaySpec,
    };
    use crate::gw_types::v::listenersets::{ListenerSetParentRef, ListenerSetSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::api::ObjectMeta;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn gw_listener(
        name: &str,
        port: i32,
        protocol: &str,
        hostname: Option<&str>,
    ) -> GatewayListeners {
        GatewayListeners {
            name: name.to_string(),
            port,
            protocol: protocol.to_string(),
            hostname: hostname.map(str::to_string),
            ..Default::default()
        }
    }

    fn ls_listener(
        name: &str,
        port: i32,
        protocol: &str,
        hostname: Option<&str>,
    ) -> ListenerSetListeners {
        ListenerSetListeners {
            name: name.to_string(),
            port,
            protocol: protocol.to_string(),
            hostname: hostname.map(str::to_string),
            ..Default::default()
        }
    }

    /// Build a Gateway in `default` ns with class `cox` and a given `from` opt-in.
    fn gateway(
        name: &str,
        from: Option<GatewayAllowedListenersNamespacesFrom>,
        listeners: Vec<GatewayListeners>,
    ) -> Arc<Gateway> {
        Arc::new(Gateway {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "cox".to_string(),
                listeners,
                allowed_listeners: from.map(|f| GatewayAllowedListeners {
                    namespaces: Some(GatewayAllowedListenersNamespaces {
                        from: Some(f),
                        selector: None,
                    }),
                }),
                ..Default::default()
            },
            status: None,
        })
    }

    /// A `Time` at `ms` epoch-milliseconds (this k8s_openapi uses jiff timestamps).
    fn ts(ms: i64) -> Time {
        Time(k8s_openapi::jiff::Timestamp::from_millisecond(ms).expect("valid test timestamp"))
    }

    /// Build a ListenerSet attaching to Gateway `parent` (in `default`).
    fn listener_set(
        name: &str,
        ns: &str,
        parent: &str,
        created: Option<i64>,
        listeners: Vec<ListenerSetListeners>,
    ) -> Arc<ListenerSet> {
        Arc::new(ListenerSet {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                creation_timestamp: created.map(ts),
                ..Default::default()
            },
            spec: ListenerSetSpec {
                parent_ref: ListenerSetParentRef {
                    name: parent.to_string(),
                    namespace: Some("default".to_string()),
                    ..Default::default()
                },
                listeners,
            },
            status: None,
        })
    }

    fn owned() -> HashSet<String> {
        HashSet::from(["cox".to_string()])
    }

    fn empty_ns_store() -> MergedStore<Namespace> {
        MergedStore::single(reflector::store::<Namespace>().0)
    }

    /// A populated Namespace store: `(name, &[(label_key, label_val)])`.
    fn ns_store_with(specs: &[(&str, &[(&str, &str)])]) -> MergedStore<Namespace> {
        let (reader, mut writer) = reflector::store::<Namespace>();
        for (name, labels) in specs {
            let ns = Namespace {
                metadata: ObjectMeta {
                    name: Some((*name).to_string()),
                    labels: Some(
                        labels
                            .iter()
                            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                            .collect(),
                    ),
                    ..Default::default()
                },
                ..Default::default()
            };
            writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(ns));
        }
        MergedStore::single(reader)
    }

    /// Build a Gateway listener with `allowedRoutes.namespaces.{from,selector}`.
    fn gw_listener_with_ns(
        name: &str,
        from: GatewayListenersAllowedRoutesNamespacesFrom,
        match_label: Option<(&str, &str)>,
    ) -> GatewayListeners {
        use crate::gw_types::v::gateways::{
            GatewayListenersAllowedRoutes, GatewayListenersAllowedRoutesNamespaces,
            GatewayListenersAllowedRoutesNamespacesSelector,
        };
        let selector = match_label.map(|(k, v)| GatewayListenersAllowedRoutesNamespacesSelector {
            match_labels: Some(std::iter::once((k.to_string(), v.to_string())).collect()),
            match_expressions: None,
        });
        GatewayListeners {
            allowed_routes: Some(GatewayListenersAllowedRoutes {
                namespaces: Some(GatewayListenersAllowedRoutesNamespaces {
                    from: Some(from),
                    selector,
                }),
                kinds: None,
            }),
            ..gw_listener(name, 80, "HTTP", None)
        }
    }

    #[test]
    fn gw_route_namespaces_resolves_same_all_selector() {
        use crate::gw_types::v::gateways::GatewayListenersAllowedRoutesNamespacesFrom as F;
        let store = ns_store_with(&[("team-a", &[("team", "a")]), ("team-b", &[("team", "b")])]);

        // Absent `allowedRoutes` → Same (the Gateway API default) → only the owner ns.
        assert_eq!(
            gw_route_namespaces(&gw_listener("l", 80, "HTTP", None), "gw-ns", &store),
            RouteNamespaceSet::Only(std::iter::once("gw-ns".to_string()).collect()),
        );
        // `from: All` → every namespace.
        assert_eq!(
            gw_route_namespaces(&gw_listener_with_ns("l", F::All, None), "gw-ns", &store),
            RouteNamespaceSet::All,
        );
        // `from: Same` → only the declaring (owner) namespace.
        assert_eq!(
            gw_route_namespaces(&gw_listener_with_ns("l", F::Same, None), "gw-ns", &store),
            RouteNamespaceSet::Only(std::iter::once("gw-ns".to_string()).collect()),
        );
        // `from: Selector team=a` → only the matching namespace (NOT all — the bug).
        assert_eq!(
            gw_route_namespaces(
                &gw_listener_with_ns("l", F::Selector, Some(("team", "a"))),
                "gw-ns",
                &store,
            ),
            RouteNamespaceSet::Only(std::iter::once("team-a".to_string()).collect()),
        );
    }

    fn names(eff: &EffectiveGateway) -> Vec<(ListenerSource, String, bool)> {
        eff.listeners
            .iter()
            .map(|l| (l.source.clone(), l.name.clone(), l.conflict.is_conflicted()))
            .collect()
    }

    #[test]
    fn default_opt_out_rejects_listener_set() {
        // No allowedListeners → from defaults to None → ListenerSet not merged.
        let gw = gateway("gw", None, vec![gw_listener("web", 80, "HTTP", None)]);
        let ls = listener_set(
            "team",
            "default",
            "gw",
            Some(1),
            vec![ls_listener("extra", 8080, "HTTP", None)],
        );
        let eff = merge_effective_gateways(&[gw], &[ls], &owned(), &empty_ns_store());
        let g = eff.get(&ObjectKey::new("default", "gw")).expect("gateway");
        assert_eq!(
            g.listeners.len(),
            1,
            "only the Gateway's own listener merges"
        );
        assert_eq!(g.listeners[0].name, "web");
    }

    #[test]
    fn same_namespace_opt_in_merges_same_ns_only() {
        let gw = gateway(
            "gw",
            Some(GatewayAllowedListenersNamespacesFrom::Same),
            vec![gw_listener("web", 80, "HTTP", None)],
        );
        let same = listener_set(
            "same",
            "default",
            "gw",
            Some(1),
            vec![ls_listener("a", 8080, "HTTP", None)],
        );
        let other = listener_set(
            "other",
            "apps",
            "gw",
            Some(2),
            vec![ls_listener("b", 8081, "HTTP", None)],
        );
        let eff = merge_effective_gateways(&[gw], &[same, other], &owned(), &empty_ns_store());
        let g = eff.get(&ObjectKey::new("default", "gw")).expect("gateway");
        let merged: Vec<&str> = g.listeners.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(merged, vec!["web", "a"], "only same-ns ListenerSet merges");
    }

    #[test]
    fn all_opt_in_merges_cross_namespace() {
        let gw = gateway(
            "gw",
            Some(GatewayAllowedListenersNamespacesFrom::All),
            vec![gw_listener("web", 80, "HTTP", None)],
        );
        let ls = listener_set(
            "team",
            "apps",
            "gw",
            Some(1),
            vec![ls_listener("a", 8080, "HTTP", None)],
        );
        let eff = merge_effective_gateways(&[gw], &[ls], &owned(), &empty_ns_store());
        let g = eff.get(&ObjectKey::new("default", "gw")).expect("gateway");
        assert_eq!(g.listeners.len(), 2);
        assert_eq!(
            g.listeners[1].source,
            ListenerSource::ListenerSet(ObjectKey::new("apps", "team"))
        );
        assert_eq!(g.listeners[1].owning_namespace, "apps");
    }

    #[test]
    fn precedence_orders_gateway_then_oldest_listener_set() {
        let gw = gateway(
            "gw",
            Some(GatewayAllowedListenersNamespacesFrom::All),
            vec![gw_listener("web", 80, "HTTP", None)],
        );
        // newer ts first in input, older second — output must be oldest-first.
        let newer = listener_set(
            "z-newer",
            "apps",
            "gw",
            Some(20),
            vec![ls_listener("n", 8081, "HTTP", None)],
        );
        let older = listener_set(
            "a-older",
            "apps",
            "gw",
            Some(10),
            vec![ls_listener("o", 8082, "HTTP", None)],
        );
        let eff = merge_effective_gateways(&[gw], &[newer, older], &owned(), &empty_ns_store());
        let g = eff.get(&ObjectKey::new("default", "gw")).expect("gateway");
        let merged: Vec<&str> = g.listeners.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(
            merged,
            vec!["web", "o", "n"],
            "Gateway first, then oldest LS"
        );
    }

    #[test]
    fn duplicate_name_distinct_port_both_program() {
        // Gateway listener "web":80 and a ListenerSet listener "web":8080 coexist.
        let gw = gateway(
            "gw",
            Some(GatewayAllowedListenersNamespacesFrom::All),
            vec![gw_listener("web", 80, "HTTP", None)],
        );
        let ls = listener_set(
            "team",
            "apps",
            "gw",
            Some(1),
            vec![ls_listener("web", 8080, "HTTP", None)],
        );
        let eff = merge_effective_gateways(&[gw], &[ls], &owned(), &empty_ns_store());
        let g = eff.get(&ObjectKey::new("default", "gw")).expect("gateway");
        let got = names(g);
        assert_eq!(got.len(), 2);
        assert!(
            got.iter().all(|(_, _, conflicted)| !conflicted),
            "neither conflicts"
        );
        assert_eq!(got[0].0, ListenerSource::Gateway);
        assert!(matches!(got[1].0, ListenerSource::ListenerSet(_)));
    }

    #[test]
    fn shared_port_incompatible_listener_set_is_conflicted() {
        // Gateway claims :80 HTTP (no hostname); the ListenerSet listener on the
        // same port overlaps (empty hostname) → lower-precedence LS conflicts.
        let gw = gateway(
            "gw",
            Some(GatewayAllowedListenersNamespacesFrom::All),
            vec![gw_listener("web", 80, "HTTP", None)],
        );
        let ls = listener_set(
            "team",
            "apps",
            "gw",
            Some(1),
            vec![ls_listener("dup", 80, "HTTP", None)],
        );
        let eff = merge_effective_gateways(&[gw], &[ls], &owned(), &empty_ns_store());
        let g = eff.get(&ObjectKey::new("default", "gw")).expect("gateway");
        assert!(
            !g.listeners[0].conflict.is_conflicted(),
            "Gateway listener wins"
        );
        assert!(
            g.listeners[1].conflict.is_conflicted(),
            "ListenerSet listener loses the port"
        );
    }

    #[test]
    fn shared_port_distinct_hostnames_are_compatible() {
        let gw = gateway(
            "gw",
            Some(GatewayAllowedListenersNamespacesFrom::All),
            vec![gw_listener("a", 443, "HTTPS", Some("a.example.com"))],
        );
        let ls = listener_set(
            "team",
            "apps",
            "gw",
            Some(1),
            vec![ls_listener("b", 443, "HTTPS", Some("b.example.com"))],
        );
        let eff = merge_effective_gateways(&[gw], &[ls], &owned(), &empty_ns_store());
        let g = eff.get(&ObjectKey::new("default", "gw")).expect("gateway");
        assert!(
            g.listeners.iter().all(|l| !l.conflict.is_conflicted()),
            "distinct hostnames share a port"
        );
    }

    #[test]
    fn shared_port_empty_catchall_coexists_with_specific_hostnames() {
        // GEP-3567 listener isolation: an empty (catch-all) hostname listener on a
        // port coexists with specific- and wildcard-hostname listeners — all
        // program. Routing picks the most specific; misdirected requests 421. Only
        // an IDENTICAL hostname conflicts. Regression: the old rule flagged any
        // empty-hostname listener as conflicting, leaving the Gateway not Programmed
        // and breaking GatewayHTTPListenerIsolation conformance.
        let gw = gateway(
            "gw",
            Some(GatewayAllowedListenersNamespacesFrom::All),
            vec![
                gw_listener("wild", 80, "HTTP", Some("*.example.com")),
                gw_listener("foo", 80, "HTTP", Some("foo.example.com")),
                gw_listener("catchall", 80, "HTTP", None),
            ],
        );
        let eff = merge_effective_gateways(&[gw], &[], &owned(), &empty_ns_store());
        let g = eff.get(&ObjectKey::new("default", "gw")).expect("gateway");
        assert!(
            g.listeners.iter().all(|l| !l.conflict.is_conflicted()),
            "empty catch-all + distinct specific/wildcard hostnames must all program; got {:?}",
            g.listeners
                .iter()
                .map(|l| (l.name.clone(), l.conflict.clone()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn unowned_parent_class_is_skipped() {
        let mut gw = gateway(
            "gw",
            Some(GatewayAllowedListenersNamespacesFrom::All),
            vec![gw_listener("web", 80, "HTTP", None)],
        );
        Arc::make_mut(&mut gw).spec.gateway_class_name = "other".to_string();
        let ls = listener_set(
            "team",
            "apps",
            "gw",
            Some(1),
            vec![ls_listener("a", 8080, "HTTP", None)],
        );
        let eff = merge_effective_gateways(&[gw], &[ls], &owned(), &empty_ns_store());
        assert!(
            eff.is_empty(),
            "Gateway of an unowned class is not in the effective map"
        );
    }

    // ── effective_listener_ports (operator port provisioning, #93) ────────────

    #[test]
    fn effective_ports_include_attached_listener_set_ports() {
        let gw = gateway(
            "gw",
            Some(GatewayAllowedListenersNamespacesFrom::All),
            vec![gw_listener("web", 80, "HTTP", None)],
        );
        let ls = listener_set(
            "team",
            "apps",
            "gw",
            Some(1),
            vec![ls_listener("extra", 8080, "HTTP", None)],
        );
        let map = effective_listener_ports(&[gw], &[ls], &owned(), &empty_ns_store());
        let ports = map.get(&ObjectKey::new("default", "gw")).expect("gateway");
        let got: Vec<u16> = ports.iter().map(|p| p.port).collect();
        assert_eq!(
            got,
            vec![80, 8080],
            "the Gateway's own port AND the attached ListenerSet's new port are provisioned"
        );
    }

    #[test]
    fn effective_ports_omit_unattached_listener_set() {
        // No allowedListeners → ListenerSet rejected → only the Gateway's port.
        let gw = gateway("gw", None, vec![gw_listener("web", 80, "HTTP", None)]);
        let ls = listener_set(
            "team",
            "default",
            "gw",
            Some(1),
            vec![ls_listener("extra", 8080, "HTTP", None)],
        );
        let map = effective_listener_ports(&[gw], &[ls], &owned(), &empty_ns_store());
        let ports = map.get(&ObjectKey::new("default", "gw")).expect("gateway");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 80);
    }

    #[test]
    fn effective_ports_give_duplicate_names_unique_serviceport_names() {
        // Gateway "web":80 + ListenerSet "web":8080 — names legally duplicate, but
        // ServicePort names must be unique; the later (LS) one is port-suffixed.
        let gw = gateway(
            "gw",
            Some(GatewayAllowedListenersNamespacesFrom::All),
            vec![gw_listener("web", 80, "HTTP", None)],
        );
        let ls = listener_set(
            "team",
            "apps",
            "gw",
            Some(1),
            vec![ls_listener("web", 8080, "HTTP", None)],
        );
        let map = effective_listener_ports(&[gw], &[ls], &owned(), &empty_ns_store());
        let ports = map.get(&ObjectKey::new("default", "gw")).expect("gateway");
        let names: Vec<&str> = ports.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["web", "web-8080"],
            "duplicate names disambiguated"
        );
        // All names unique.
        let unique: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(
            unique.len(),
            names.len(),
            "ServicePort names must be unique"
        );
    }
}
