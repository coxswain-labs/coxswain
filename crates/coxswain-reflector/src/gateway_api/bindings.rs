//! Listener binding: matches `HTTPRoute.parentRefs` to Gateway listeners.

use super::hostnames;
use crate::gw_types::v::httproutes::HttpRouteParentRefs;
use crate::keys::ListenerKey;
use std::collections::{HashMap, HashSet};

/// Resolved hostname and port for a single Gateway listener, indexed by [`ListenerKey`].
///
/// Used to scope `HTTPRoute` entries to the correct per-port routing table slot and to
/// apply listener hostname filtering when the route has no `spec.hostnames` of its own.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ListenerBinding {
    /// Listener `hostname` (empty string = match all).
    pub hostname: String,
    /// Listener port number.
    pub port: u16,
}

/// Returns one entry per (listener hostname, listener port) binding derived from the
/// route's `parentRefs`. `None` hostname means insert under the port's catchall.
/// When no listener info is available (tests/misconfigured), port 80 is used as a fallback.
pub(super) fn compute_listener_bindings(
    route_hostnames: &[&str],
    parent_refs: &[HttpRouteParentRefs],
    route_ns: &str,
    listener_info: &HashMap<ListenerKey, ListenerBinding>,
) -> Vec<(Option<String>, u16)> {
    // Maps hostname_opt → set of ports.  None key = catchall.
    let mut bindings: HashMap<Option<String>, HashSet<u16>> = HashMap::new();

    macro_rules! add {
        ($hostname:expr, $port:expr) => {
            bindings.entry($hostname).or_default().insert($port);
        };
    }

    if listener_info.is_empty() {
        // No listener info: tests or misconfigured — use port 80 as fallback.
        if route_hostnames.is_empty() {
            add!(None, 80u16);
        } else {
            for h in route_hostnames {
                add!(Some(h.to_string()), 80u16);
            }
        }
    } else {
        for pr in parent_refs {
            let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
            let gw_name = pr.name.as_str();
            let pr_port_filter = pr.port.map(|p| p as u16);

            // Collect (port, listener_hostname) pairs for this parentRef.
            let l_bindings: Vec<(u16, &str)> = if let Some(sn) = pr.section_name.as_deref() {
                let key = ListenerKey::new(gw_ns, gw_name, sn);
                match listener_info.get(&key) {
                    Some(info) if pr_port_filter.is_none_or(|pp| pp == info.port) => {
                        vec![(info.port, info.hostname.as_str())]
                    }
                    _ => vec![],
                }
            } else {
                listener_info
                    .iter()
                    .filter_map(|(k, info)| {
                        if k.gw_ns != gw_ns || k.gw_name != gw_name {
                            return None;
                        }
                        if pr_port_filter.is_none_or(|pp| pp == info.port) {
                            Some((info.port, info.hostname.as_str()))
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            for (port, lh) in l_bindings {
                if lh.is_empty() {
                    if route_hostnames.is_empty() {
                        add!(None, port);
                    } else {
                        for h in route_hostnames {
                            add!(Some(h.to_string()), port);
                        }
                    }
                } else if route_hostnames.is_empty() {
                    add!(Some(lh.to_string()), port);
                } else {
                    // Intersection: the effective hostname is the more specific of the two.
                    for rh in route_hostnames {
                        if hostnames::hostname_matches(rh, lh) {
                            let effective = if rh.starts_with("*.") && !lh.starts_with("*.") {
                                lh.to_string()
                            } else {
                                rh.to_string()
                            };
                            add!(Some(effective), port);
                        }
                    }
                }
            }
        }
    }

    // Listener isolation: drop any hostname that a more-specific listener in the same
    // gateway would claim exclusively. Catchall bindings (None) are never dominated.
    if !listener_info.is_empty() {
        bindings.retain(|hostname_opt, _| {
            let e = match hostname_opt {
                Some(h) => h.as_str(),
                None => return true,
            };
            // Isolation only applies when the parentRef names a specific listener.
            !parent_refs.iter().any(|pr| {
                let our_sn = match pr.section_name.as_deref() {
                    Some(sn) if !sn.is_empty() => sn,
                    _ => return false,
                };
                let gw_ns = pr.namespace.as_deref().unwrap_or(route_ns);
                let gw_name = pr.name.as_str();
                let our_spec = listener_info
                    .get(&ListenerKey::new(gw_ns, gw_name, our_sn))
                    .map(|info| hostnames::listener_specificity(&info.hostname))
                    .unwrap_or(0);
                let e_is_wildcard = e.starts_with("*.");
                listener_info.iter().any(|(k, info)| {
                    let h_other = &info.hostname;
                    k.gw_ns == gw_ns
                        && k.gw_name == gw_name
                        && k.listener.as_str() != our_sn
                        && hostnames::listener_specificity(h_other) > our_spec
                        && if e_is_wildcard {
                            h_other == e
                        } else {
                            hostnames::hostname_matches(e, h_other)
                        }
                })
            })
        });
    }

    let mut result = Vec::new();
    for (hostname_opt, ports) in bindings {
        for port in ports {
            result.push((hostname_opt.clone(), port));
        }
    }
    result
}
