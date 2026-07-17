//! SNI-keyed TLS passthrough routing table for `TLSRoute` / GEP-2643.
//!
//! In passthrough mode the proxy **never** terminates TLS: it extracts the SNI
//! from the raw ClientHello, picks a backend by hostname, and forwards the
//! encrypted stream byte-for-byte. This table is intentionally simpler than the
//! L7 [`RoutingTable`](crate::routing::RoutingTable) — there are no path predicates, filters, or headers; just
//! `port → SNI → BackendGroup`.
//!
//! Hostname matching follows Gateway-API semantics: exact match first, then
//! `*.`-prefixed multi-label wildcard (a single `*.example.com` matches any
//! depth of subdomain), then a catch-all (`""` or `"*"`). This differs from the
//! RFC 6125 single-label rule used for *certificate* matching — which is
//! irrelevant here because the proxy has no TLS certificate on this path.

use crate::routing::BackendGroup;
use crate::routing::common::host_router::{WildcardKind, wildcard_matches};
use crate::shared::Shared;
use std::collections::HashMap;
use std::sync::Arc;

/// Atomically-swappable handle to the active [`TlsPassthroughTable`].
pub type SharedTlsPassthroughTable = Shared<TlsPassthroughTable>;

/// Immutable routing table mapping `(port, SNI) → BackendGroup` for TLS passthrough.
///
/// Built once per reconcile cycle and published via [`SharedTlsPassthroughTable`].
/// The proxy loads it with a single atomic pointer read on each accepted TCP connection.
#[non_exhaustive]
#[derive(Default, Debug)]
pub struct TlsPassthroughTable {
    by_port: HashMap<u16, SniRouter>,
}

impl TlsPassthroughTable {
    /// Return the [`SniRouter`] for `port`, if any.
    #[must_use]
    pub fn port(&self, port: u16) -> Option<&SniRouter> {
        self.by_port.get(&port)
    }

    /// Number of ports with registered routes.
    #[must_use]
    pub fn port_count(&self) -> usize {
        self.by_port.len()
    }

    /// Iterate over `(port, SniRouter)` pairs in arbitrary order.
    pub fn ports_iter(&self) -> impl Iterator<Item = (u16, &SniRouter)> {
        self.by_port.iter().map(|(p, r)| (*p, r))
    }
}

/// Per-port SNI matcher for TLS passthrough.
///
/// Lookup order: exact → wildcard (multi-label, sorted longest-suffix-first) → catch-all.
#[non_exhaustive]
#[derive(Debug)]
pub struct SniRouter {
    exact: HashMap<Arc<str>, Arc<BackendGroup>>,
    /// Sorted longest-suffix-first so more-specific wildcards win.
    /// Each entry is `(suffix, backend)` where the pattern is `*.{suffix}`.
    wildcard: Vec<(Arc<str>, Arc<BackendGroup>)>,
    catchall: Option<Arc<BackendGroup>>,
}

impl SniRouter {
    /// Iterate over exact-match `(sni, backend)` pairs.
    pub fn exact_iter(&self) -> impl Iterator<Item = (&str, &Arc<BackendGroup>)> {
        self.exact.iter().map(|(k, v)| (k.as_ref(), v))
    }

    /// Iterate over wildcard `(suffix, backend)` pairs (no `*.` prefix on the suffix).
    pub fn wildcard_iter(&self) -> impl Iterator<Item = (&str, &Arc<BackendGroup>)> {
        self.wildcard.iter().map(|(k, v)| (k.as_ref(), v))
    }

    /// Return the catch-all backend, if any.
    #[must_use]
    pub fn catchall(&self) -> Option<&Arc<BackendGroup>> {
        self.catchall.as_ref()
    }

    /// Select a backend for `sni`.
    ///
    /// `sni` must be ASCII-lowercase: matching is case-sensitive by design,
    /// because the patterns this router is keyed by are already lowercase (the
    /// `Hostname` CRD schema enforces RFC 1123), so normalizing per connection
    /// would be redundant. Callers normalize once at ingestion — see
    /// `coxswain_proxy::edge::passthrough::peek_sni`, which lowercases while
    /// parsing the ClientHello. RFC 6066 defers to case-insensitive DNS, so a
    /// peer may legitimately send any casing and expect a match.
    ///
    /// Returns `None` when no pattern matches — the caller should close the connection.
    #[must_use]
    pub fn match_sni(&self, sni: Option<&str>) -> Option<&Arc<BackendGroup>> {
        debug_assert!(
            !sni.is_some_and(|s| s.bytes().any(|b| b.is_ascii_uppercase())),
            "sni must be normalized to ASCII-lowercase before matching; \
             an un-normalized ingestion point silently drops mixed-case connections"
        );
        if let Some(sni) = sni {
            if let Some(bg) = self.exact.get(sni) {
                return Some(bg);
            }
            if let Some((_, bg)) = self
                .wildcard
                .iter()
                .find(|(suffix, _)| wildcard_matches(sni, suffix, WildcardKind::MultiLabel))
            {
                return Some(bg);
            }
        }
        self.catchall.as_ref()
    }
}

/// Builder that compiles a [`TlsPassthroughTable`].
///
/// Typical usage: create one builder per reconcile cycle, call [`Self::add_route`]
/// for every `TLSRoute` rule, then call [`Self::build`].
#[non_exhaustive]
#[derive(Default, Debug)]
pub struct TlsPassthroughTableBuilder {
    by_port: HashMap<u16, SniRouterBuilder>,
}

impl TlsPassthroughTableBuilder {
    /// Construct an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `backend` as the target for `(port, hostname_pattern)`.
    ///
    /// Patterns: `""` or `"*"` → catch-all; `*.suffix` → multi-label wildcard;
    /// anything else → exact. The last `add_route` call for an exact duplicate
    /// pattern wins (last-writer-wins; reconcile sorts routes by precedence before
    /// calling this, so the winner is deterministic).
    #[must_use]
    pub fn add_route(
        mut self,
        port: u16,
        hostname_pattern: &str,
        backend: Arc<BackendGroup>,
    ) -> Self {
        self.by_port
            .entry(port)
            .or_default()
            .add(hostname_pattern, backend);
        self
    }

    /// Compile into an immutable [`TlsPassthroughTable`].
    #[must_use]
    pub fn build(self) -> TlsPassthroughTable {
        let by_port = self
            .by_port
            .into_iter()
            .map(|(port, b)| (port, b.build()))
            .collect();
        TlsPassthroughTable { by_port }
    }
}

#[derive(Default, Debug)]
struct SniRouterBuilder {
    exact: HashMap<Arc<str>, Arc<BackendGroup>>,
    wildcard: HashMap<Arc<str>, Arc<BackendGroup>>,
    catchall: Option<Arc<BackendGroup>>,
}

impl SniRouterBuilder {
    fn add(&mut self, pattern: &str, backend: Arc<BackendGroup>) {
        if pattern.is_empty() || pattern == "*" {
            self.catchall = Some(backend);
        } else if let Some(suffix) = pattern.strip_prefix("*.") {
            self.wildcard.insert(Arc::from(suffix), backend);
        } else {
            self.exact.insert(Arc::from(pattern), backend);
        }
    }

    fn build(self) -> SniRouter {
        let mut wildcard: Vec<(Arc<str>, Arc<BackendGroup>)> = self.wildcard.into_iter().collect();
        // Sort longest-suffix-first so more-specific patterns are tried first.
        wildcard.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        SniRouter {
            exact: self.exact,
            wildcard,
            catchall: self.catchall,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> Arc<BackendGroup> {
        Arc::new(BackendGroup::new("test".into(), vec![]))
    }

    fn table_one_port(port: u16, pattern: &str) -> TlsPassthroughTable {
        TlsPassthroughTableBuilder::new()
            .add_route(port, pattern, backend())
            .build()
    }

    #[test]
    fn exact_match() {
        let t = table_one_port(443, "app.example.com");
        let r = t.port(443).unwrap();
        assert!(r.match_sni(Some("app.example.com")).is_some());
        assert!(r.match_sni(Some("other.example.com")).is_none());
    }

    #[test]
    fn wildcard_multi_label_match() {
        let t = table_one_port(443, "*.example.com");
        let r = t.port(443).unwrap();
        assert!(r.match_sni(Some("a.example.com")).is_some());
        assert!(r.match_sni(Some("deep.a.example.com")).is_some());
        assert!(r.match_sni(Some("example.com")).is_none());
        assert!(r.match_sni(Some("notexample.com")).is_none());
    }

    #[test]
    fn catchall_empty_string() {
        let t = table_one_port(8444, "");
        let r = t.port(8444).unwrap();
        assert!(r.match_sni(Some("anything.example.com")).is_some());
        assert!(r.match_sni(None).is_some());
    }

    #[test]
    fn catchall_star() {
        let t = table_one_port(8444, "*");
        let r = t.port(8444).unwrap();
        assert!(r.match_sni(Some("whatever")).is_some());
    }

    #[test]
    fn exact_beats_wildcard() {
        let bg_exact = backend();
        let bg_wild = backend();
        let t = TlsPassthroughTableBuilder::new()
            .add_route(443, "app.example.com", Arc::clone(&bg_exact))
            .add_route(443, "*.example.com", Arc::clone(&bg_wild))
            .build();
        let r = t.port(443).unwrap();
        assert!(Arc::ptr_eq(
            r.match_sni(Some("app.example.com")).unwrap(),
            &bg_exact
        ));
        assert!(Arc::ptr_eq(
            r.match_sni(Some("other.example.com")).unwrap(),
            &bg_wild
        ));
    }

    #[test]
    fn longer_wildcard_suffix_wins() {
        let bg_long = backend();
        let bg_short = backend();
        let t = TlsPassthroughTableBuilder::new()
            .add_route(443, "*.a.example.com", Arc::clone(&bg_long))
            .add_route(443, "*.example.com", Arc::clone(&bg_short))
            .build();
        let r = t.port(443).unwrap();
        // foo.a.example.com: both match but *.a.example.com has longer suffix.
        assert!(Arc::ptr_eq(
            r.match_sni(Some("foo.a.example.com")).unwrap(),
            &bg_long
        ));
        assert!(Arc::ptr_eq(
            r.match_sni(Some("bar.example.com")).unwrap(),
            &bg_short
        ));
    }

    #[test]
    fn no_sni_falls_back_to_catchall() {
        let t = table_one_port(443, "*");
        let r = t.port(443).unwrap();
        assert!(r.match_sni(None).is_some());
    }

    #[test]
    fn no_sni_no_catchall_returns_none() {
        let t = table_one_port(443, "app.example.com");
        let r = t.port(443).unwrap();
        assert!(r.match_sni(None).is_none());
    }

    #[test]
    fn unknown_port_returns_none() {
        let t = table_one_port(443, "app.example.com");
        assert!(t.port(8444).is_none());
    }

    /// The router matches case-sensitively on purpose (patterns are already
    /// lowercase, so per-connection normalization would be wasted work); callers
    /// normalize at ingestion instead. This pins the *contract* — that a
    /// normalized mixed-case SNI matches — so that a future change making the
    /// patterns case-sensitive in a different way, or dropping the ingestion-side
    /// lowercasing, is caught here rather than in production.
    #[test]
    fn normalized_mixed_case_sni_matches_exact_and_wildcard() {
        let t = TlsPassthroughTableBuilder::new()
            .add_route(443, "app.example.com", backend())
            .add_route(443, "*.wild.example.com", backend())
            .build();
        let r = t.port(443).expect("port 443 was registered");

        assert!(
            r.match_sni(Some(&"App.Example.COM".to_ascii_lowercase()))
                .is_some(),
            "a mixed-case SNI normalized at ingestion must hit the exact route"
        );
        assert!(
            r.match_sni(Some(&"Deep.Sub.Wild.Example.Com".to_ascii_lowercase()))
                .is_some(),
            "a mixed-case SNI normalized at ingestion must hit the wildcard route"
        );
    }
}
