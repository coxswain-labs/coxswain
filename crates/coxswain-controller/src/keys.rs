/// Key for a specific listener on a Gateway: `(gw_ns, gw_name, listener_name)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ListenerKey {
    pub gw_ns: String,
    pub gw_name: String,
    pub listener: String,
}

impl ListenerKey {
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
    pub route_ns: String,
    pub route_name: String,
    pub gw_ns: String,
    pub gw_name: String,
    pub section: String,
}

impl RouteParentKey {
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
