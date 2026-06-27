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

use std::collections::HashMap;

use k8s_openapi::api::core::v1::Namespace;
use kube::runtime::reflector;

use crate::gw_types::ListenerSet;
use crate::gw_types::v::gateways::{
    Gateway, GatewayAllowedListenersNamespacesFrom, GatewayListeners, GatewayListenersTlsMode,
};
use crate::gw_types::v::listenersets::{ListenerSetListeners, ListenerSetListenersTlsMode};
use crate::tls::ListenerSource;
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
    /// per-listener health [`crate::tls::ListenerHealthKey`]).
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
    /// Whether routes from any namespace may attach (`allowedRoutes.namespaces.from`
    /// is anything other than `Same`); mirrors the existing simplified model.
    pub allows_all_namespaces: bool,
    /// `allowedRoutes.kinds` as `(group, kind)` pairs (empty = use the protocol
    /// default). Carried so route-health can compute per-listener `allows_kind`
    /// for routes attached via this listener (GEP-1713).
    pub allowed_route_kinds: Vec<(Option<String>, String)>,
    /// `true` when this listener lost a port-compatibility conflict to a
    /// higher-precedence listener and must NOT be programmed.
    pub conflicted: bool,
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
    namespaces: &reflector::Store<Namespace>,
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
            .map(|l| from_gateway_listener(l, &ns))
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
                eff.listeners
                    .push(from_listenerset_listener(l, &ls_ns, &ls_obj_key));
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
/// `protocol`); the heavier [`EffectiveGateway`]/[`EffectiveListener`] stay
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
/// Reuses [`merge_effective_gateways`] so the provisioning operator and the data
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
    namespaces: &reflector::Store<Namespace>,
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
                if l.conflicted {
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
    namespaces: &reflector::Store<Namespace>,
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
    namespaces: &reflector::Store<Namespace>,
    ns: &str,
) -> std::collections::BTreeMap<String, String> {
    namespaces
        .state()
        .into_iter()
        .find(|n| n.metadata.name.as_deref() == Some(ns))
        .and_then(|n| n.metadata.labels.clone())
        .unwrap_or_default()
}

/// Evaluate a Kubernetes label selector (`matchLabels` ANDed with
/// `matchExpressions`) against a label set. An empty selector matches everything.
fn selector_matches(
    match_labels: Option<&std::collections::BTreeMap<String, String>>,
    match_expressions: Option<
        &[crate::gw_types::v::gateways::GatewayAllowedListenersNamespacesSelectorMatchExpressions],
    >,
    labels: &std::collections::BTreeMap<String, String>,
) -> bool {
    if let Some(ml) = match_labels {
        for (k, v) in ml {
            if labels.get(k) != Some(v) {
                return false;
            }
        }
    }
    for expr in match_expressions.unwrap_or(&[]) {
        let present = labels.get(&expr.key);
        let values = expr.values.as_deref().unwrap_or(&[]);
        let ok = match expr.operator.as_str() {
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

/// Normalise a Gateway's own listener.
fn from_gateway_listener(l: &GatewayListeners, gw_ns: &str) -> EffectiveListener {
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
        allows_all_namespaces: gw_allows_all_namespaces(l),
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
        conflicted: false,
    }
}

/// Normalise a ListenerSet listener, tagging it with its source ListenerSet and
/// the namespace its `certificateRefs` resolve in (the ListenerSet's own).
fn from_listenerset_listener(
    l: &ListenerSetListeners,
    ls_ns: &str,
    ls_key: &ObjectKey,
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
        allows_all_namespaces: ls_allows_all_namespaces(l),
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
        conflicted: false,
    }
}

/// `allowedRoutes.namespaces.from` is anything other than `Same` (Gateway side).
fn gw_allows_all_namespaces(l: &GatewayListeners) -> bool {
    use crate::gw_types::v::gateways::GatewayListenersAllowedRoutesNamespacesFrom as F;
    l.allowed_routes
        .as_ref()
        .and_then(|ar| ar.namespaces.as_ref())
        .and_then(|ns| ns.from.as_ref())
        .is_some_and(|f| !matches!(f, F::Same))
}

/// `allowedRoutes.namespaces.from` is anything other than `Same` (ListenerSet side).
fn ls_allows_all_namespaces(l: &ListenerSetListeners) -> bool {
    use crate::gw_types::v::listenersets::ListenerSetListenersAllowedRoutesNamespacesFrom as F;
    l.allowed_routes
        .as_ref()
        .and_then(|ar| ar.namespaces.as_ref())
        .and_then(|ns| ns.from.as_ref())
        .is_some_and(|f| !matches!(f, F::Same))
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
        let compatible = entry.iter().all(|(proto, h)| {
            // Compatible only when the protocol matches and both hostnames are
            // non-empty and distinct (an empty hostname matches all SNI/Host and
            // therefore overlaps every sibling on the port).
            proto == &l.protocol && !host.is_empty() && !h.is_empty() && h != &host
        });
        if compatible {
            entry.push((l.protocol.clone(), host));
        } else {
            l.conflicted = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gw_types::v::gateways::{
        GatewayAllowedListeners, GatewayAllowedListenersNamespaces, GatewaySpec,
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

    fn empty_ns_store() -> reflector::Store<Namespace> {
        reflector::store::<Namespace>().0
    }

    fn names(eff: &EffectiveGateway) -> Vec<(ListenerSource, String, bool)> {
        eff.listeners
            .iter()
            .map(|l| (l.source.clone(), l.name.clone(), l.conflicted))
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
        assert!(!g.listeners[0].conflicted, "Gateway listener wins");
        assert!(
            g.listeners[1].conflicted,
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
            g.listeners.iter().all(|l| !l.conflicted),
            "distinct hostnames share a port"
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
