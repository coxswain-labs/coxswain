//! Internal key types used as `HashMap` keys across the reflector pipeline.

/// Key for a specific listener on a Gateway: `(gw_ns, gw_name, listener_name)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListenerKey {
    /// Namespace of the parent Gateway.
    pub gw_ns: String,
    /// Name of the parent Gateway.
    pub gw_name: String,
    /// `listenerName` from the Gateway spec.
    pub listener: String,
}

impl ListenerKey {
    /// Construct a `ListenerKey` from any string-convertible parts.
    pub fn new(
        gw_ns: impl Into<String>,
        gw_name: impl Into<String>,
        listener: impl Into<String>,
    ) -> Self {
        Self {
            gw_ns: gw_ns.into(),
            gw_name: gw_name.into(),
            listener: listener.into(),
        }
    }
}

/// Key for one (HTTPRoute, parent Gateway) health entry.
///
/// `section` is the `sectionName` from `parentRef`, or an empty string when
/// no `sectionName` was specified.
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
