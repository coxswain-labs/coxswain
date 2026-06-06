mod entry;
mod host_router;
mod predicate;
mod routing;

use super::*;
use http::{HeaderMap, HeaderName};
use std::net::SocketAddr;

const PORT: u16 = 80;

pub(super) fn group(name: &str, addr: &str) -> Arc<BackendGroup> {
    Arc::new(BackendGroup::new(
        name.to_string(),
        vec![addr.parse::<SocketAddr>().unwrap()],
    ))
}

pub(super) fn entry(g: Arc<BackendGroup>) -> Arc<RouteEntry> {
    Arc::new(RouteEntry::path_only(g, "default/svc".to_string(), None))
}

pub(super) fn ctx_get() -> RequestContext<'static> {
    RequestContext::default()
}

pub(super) fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for (k, v) in pairs {
        m.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    m
}

pub(super) fn make_predicates(
    method: Option<&str>,
    headers: &[(&str, &str)], // (name, exact_value)
    query: &[(&str, &str)],   // (name, exact_value)
) -> MatchPredicates {
    MatchPredicates {
        method: method.map(|m| m.parse().unwrap()),
        headers: headers
            .iter()
            .map(|(n, v)| HeaderPredicate {
                name: HeaderName::from_bytes(n.as_bytes()).unwrap(),
                matcher: ValueMatch::Exact(v.to_string()),
            })
            .collect(),
        query: query
            .iter()
            .map(|(n, v)| QueryPredicate {
                name: n.to_string(),
                matcher: ValueMatch::Exact(v.to_string()),
            })
            .collect(),
    }
}
