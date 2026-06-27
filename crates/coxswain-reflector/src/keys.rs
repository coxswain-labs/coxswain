//! Internal key types used as `HashMap` keys across the reflector pipeline.

use coxswain_core::listener_health::ListenerSource;
use coxswain_core::ownership::ObjectKey;

/// Key for a specific listener in the routing tables, scoped to the resource that
/// declares it (GEP-1713): `(source, ns, name, listener_name)`.
///
/// For a Gateway listener, `source` is [`ListenerSource::Gateway`] and `(ns, name)`
/// is the Gateway. For a ListenerSet listener, `source` is
/// [`ListenerSource::ListenerSet`] and `(ns, name)` is the **ListenerSet** — so a
/// route's `parentRef` (which targets either a Gateway or a ListenerSet) resolves
/// to a listener key directly from `(kind, namespace, name, sectionName)`, and a
/// Gateway listener never collides with a same-named ListenerSet listener.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListenerKey {
    /// The resource kind that declares this listener (Gateway or ListenerSet).
    pub source: ListenerSource,
    /// Namespace of the declaring resource (the Gateway, or the ListenerSet).
    pub gw_ns: String,
    /// Name of the declaring resource (the Gateway, or the ListenerSet).
    pub gw_name: String,
    /// `listenerName` from the resource spec.
    pub listener: String,
}

impl ListenerKey {
    /// Construct a Gateway-scoped `ListenerKey` (`source = Gateway`). Used for both
    /// a Gateway's own listeners and `parentRef.kind: Gateway` lookups.
    pub fn new(
        gw_ns: impl Into<String>,
        gw_name: impl Into<String>,
        listener: impl Into<String>,
    ) -> Self {
        Self {
            source: ListenerSource::Gateway,
            gw_ns: gw_ns.into(),
            gw_name: gw_name.into(),
            listener: listener.into(),
        }
    }

    /// Construct a ListenerSet-scoped `ListenerKey`: `(ns, name)` identify the
    /// ListenerSet `key`, `source = ListenerSet(key)` (GEP-1713).
    pub fn for_listener_set(key: &ObjectKey, listener: impl Into<String>) -> Self {
        Self {
            source: ListenerSource::ListenerSet(key.clone()),
            gw_ns: key.ns.clone(),
            gw_name: key.name.clone(),
            listener: listener.into(),
        }
    }
}

/// Key for one (HTTPRoute, parent Gateway) health entry.
///
/// `section` is the `sectionName` from `parentRef`, or an empty string when
/// no `sectionName` was specified.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteParentKey {
    /// Namespace of the HTTPRoute.
    pub route_ns: String,
    /// Name of the HTTPRoute.
    pub route_name: String,
    /// Namespace of the parent Gateway.
    pub gw_ns: String,
    /// Name of the parent Gateway.
    pub gw_name: String,
    /// `sectionName` from the `parentRef`, or empty when unspecified.
    pub section: String,
}

impl RouteParentKey {
    /// Construct a `RouteParentKey` from any string-convertible parts.
    pub fn new(
        route_ns: impl Into<String>,
        route_name: impl Into<String>,
        gw_ns: impl Into<String>,
        gw_name: impl Into<String>,
        section: impl Into<String>,
    ) -> Self {
        Self {
            route_ns: route_ns.into(),
            route_name: route_name.into(),
            gw_ns: gw_ns.into(),
            gw_name: gw_name.into(),
            section: section.into(),
        }
    }
}
