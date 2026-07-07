//! Shared filter + pagination envelope for the admin list endpoints.
//!
//! The routing list endpoints (`routing/{gateways,httproutes,ingresses}`) and the
//! per-proxy compiled route table (`fleet/proxies/{name}/routes`) accept the same
//! optional query parameters parsed here; absent parameters reproduce the full
//! dump (backward-compatible). The response envelope adds `total`/`returned`/
//! `offset` so the operator UI can render "showing X of Y" and a pager without
//! ever receiving rows it filtered out (#286, #292).
//!
//! Filtering is *applied by the caller* (the typed shapes differ per endpoint);
//! this module supplies the parsed params, the substring/severity predicates, and
//! the windowing + envelope serialisation.

use crate::aggregator::json_response;
use http::Response;

/// Default page size when `limit` is omitted. Documented in the `AdminServer`
/// capability table and the OpenAPI spec.
pub(crate) const DEFAULT_LIMIT: usize = 200;

/// Hard ceiling on `limit`; a larger request is clamped. Per the
/// no-silent-truncation rule the clamp is always visible as `returned < total`.
pub(crate) const MAX_LIMIT: usize = 1000;

/// Parsed list-endpoint query parameters. All optional; an all-default value
/// (see [`ListParams::is_empty`]) reproduces the legacy full dump.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub(crate) struct ListParams {
    /// Case-insensitive substring filter against each resource's object name —
    /// the routing list endpoints' free-text search (name-only by design; the
    /// operator UI's search box maps here). Lowercased at parse time.
    pub name: Option<String>,
    /// Exact (case-insensitive) namespace filter for the routing list endpoints —
    /// the operator UI's namespace dropdown maps here. Exact, not substring, so a
    /// page stays scoped to one namespace; lowercased at parse time.
    pub namespace: Option<String>,
    /// Exact (case-insensitive) host filter for the per-proxy route table — the
    /// operator UI's host dropdown (a pick from the proxy's known hosts) maps here.
    /// Exact, not substring, so a selection scopes to that one host; a no-op on
    /// the routing resource lists. Lowercased at parse time.
    pub host: Option<String>,
    /// Case-insensitive substring filter against the per-proxy route table's path —
    /// the operator UI's path search box maps here (the within-host refinement). A
    /// no-op on the routing resource lists. Lowercased at parse time.
    pub path: Option<String>,
    /// Page size; `None` selects [`DEFAULT_LIMIT`]. Clamped to [`MAX_LIMIT`].
    pub limit: Option<usize>,
    /// Page offset over the post-filter result set.
    pub offset: usize,
    /// `?status=problem` — keep only rows whose health is not `ok`.
    pub problems_only: bool,
}

impl ListParams {
    /// Parse from a raw query string (`uri.query()`), tolerating junk: an
    /// unparseable `limit`/`offset` falls back to its default rather than
    /// erroring (the operator UI is the only caller; a 400 here is a worse UX
    /// than a sane default). Empty `host`/`path` are treated as absent.
    pub(crate) fn parse(query: Option<&str>) -> Self {
        let mut p = ListParams::default();
        let Some(q) = query else { return p };
        for (k, v) in form_urlencoded::parse(q.as_bytes()) {
            match k.as_ref() {
                "name" if !v.is_empty() => p.name = Some(v.into_owned().to_ascii_lowercase()),
                "namespace" if !v.is_empty() => {
                    p.namespace = Some(v.into_owned().to_ascii_lowercase());
                }
                "host" if !v.is_empty() => p.host = Some(v.into_owned().to_ascii_lowercase()),
                "path" if !v.is_empty() => p.path = Some(v.into_owned().to_ascii_lowercase()),
                "limit" => p.limit = v.parse::<usize>().ok(),
                "offset" => p.offset = v.parse::<usize>().unwrap_or(0),
                "status" => p.problems_only = matches!(v.as_ref(), "problem" | "problems"),
                _ => {}
            }
        }
        p
    }

    /// Effective page size after applying the default and the [`MAX_LIMIT`] clamp.
    pub(crate) fn effective_limit(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
    }

    /// `true` when no filter/pagination params were supplied — the caller may
    /// emit its legacy full-dump shape (still wrapped in the envelope).
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.namespace.is_none()
            && self.host.is_none()
            && self.path.is_none()
            && self.limit.is_none()
            && self.offset == 0
            && !self.problems_only
    }

    /// `true` when the `name` filter is absent or a case-insensitive substring of
    /// `haystack`. Substring (not exact) so the operator UI's search box narrows
    /// progressively as the operator types.
    pub(crate) fn name_matches(&self, haystack: &str) -> bool {
        match &self.name {
            None => true,
            Some(needle) => haystack.to_ascii_lowercase().contains(needle),
        }
    }

    /// `true` when the `namespace` filter is absent or an exact (case-insensitive)
    /// match of `haystack` — a dropdown selection scopes the page to one namespace.
    pub(crate) fn namespace_matches(&self, haystack: &str) -> bool {
        match &self.namespace {
            None => true,
            Some(needle) => haystack.eq_ignore_ascii_case(needle),
        }
    }

    /// `true` when the `host` filter is absent or an exact (case-insensitive) match
    /// of `haystack` — a host-dropdown selection scopes the table to that host.
    pub(crate) fn host_matches(&self, haystack: &str) -> bool {
        match &self.host {
            None => true,
            Some(needle) => haystack.eq_ignore_ascii_case(needle),
        }
    }

    /// `true` when the `path` filter is absent or a case-insensitive substring of
    /// `haystack` — the path search narrows progressively as the operator types.
    pub(crate) fn path_matches(&self, haystack: &str) -> bool {
        match &self.path {
            None => true,
            Some(needle) => haystack.to_ascii_lowercase().contains(needle),
        }
    }
}

/// A windowed page of already-filtered rows plus the counts the UI needs to show
/// "showing `offset`–`offset+returned` of `total`".
#[non_exhaustive]
pub(crate) struct Page {
    /// The rows in this window.
    pub items: Vec<serde_json::Value>,
    /// Total rows after filtering, before the limit/offset window.
    pub total: usize,
    /// Number of rows actually returned in this window.
    pub returned: usize,
    /// The offset applied (clamped to `total`).
    pub offset: usize,
}

impl Page {
    /// Window an already-filtered list by the params' `offset` + effective limit.
    #[must_use]
    pub(crate) fn paginate(filtered: Vec<serde_json::Value>, params: &ListParams) -> Self {
        let total = filtered.len();
        let offset = params.offset.min(total);
        let limit = params.effective_limit();
        let items: Vec<serde_json::Value> = filtered.into_iter().skip(offset).take(limit).collect();
        let returned = items.len();
        Page {
            items,
            total,
            returned,
            offset,
        }
    }
}

/// Serialise a [`Page`] under `key` into the standard envelope:
/// `{ "<key>": [...], "total": N, "returned": N, "offset": N }`.
pub(crate) fn page_response(key: &str, page: Page) -> Response<Vec<u8>> {
    let mut map = serde_json::Map::with_capacity(4);
    map.insert(key.to_string(), serde_json::Value::Array(page.items));
    map.insert("total".to_string(), page.total.into());
    map.insert("returned".to_string(), page.returned.into());
    map.insert("offset".to_string(), page.offset.into());
    json_response(serde_json::Value::Object(map).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_query_is_empty() {
        assert!(ListParams::parse(None).is_empty());
        assert!(ListParams::parse(Some("")).is_empty());
    }

    #[test]
    fn parse_reads_and_lowercases_filters() {
        let p = ListParams::parse(Some("host=API.example.com&path=%2Fv1&limit=10&offset=5"));
        assert_eq!(p.host.as_deref(), Some("api.example.com"));
        assert_eq!(p.path.as_deref(), Some("/v1"));
        assert_eq!(p.limit, Some(10));
        assert_eq!(p.offset, 5);
        assert!(!p.is_empty());
    }

    #[test]
    fn status_problem_sets_problems_only() {
        assert!(ListParams::parse(Some("status=problem")).problems_only);
        assert!(ListParams::parse(Some("status=problems")).problems_only);
        assert!(!ListParams::parse(Some("status=ok")).problems_only);
    }

    #[test]
    fn effective_limit_defaults_and_clamps() {
        assert_eq!(ListParams::default().effective_limit(), DEFAULT_LIMIT);
        let p = ListParams {
            limit: Some(99_999),
            ..Default::default()
        };
        assert_eq!(p.effective_limit(), MAX_LIMIT);
    }

    #[test]
    fn host_is_exact_path_is_substring_case_insensitive() {
        let p = ListParams::parse(Some("host=App.Demo.local&path=%2Fv1"));
        // host: exact (case-insensitive), not substring.
        assert!(p.host_matches("app.demo.local"));
        assert!(!p.host_matches("app.demo.local.extra"));
        assert!(!p.host_matches("other.host"));
        // path: substring (case-insensitive).
        assert!(p.path_matches("/v1/users"));
        assert!(!p.path_matches("/v2"));
        // Absent → always matches.
        assert!(ListParams::default().host_matches("anything"));
        assert!(ListParams::default().path_matches("/anywhere"));
    }

    #[test]
    fn namespace_filter_is_case_insensitive_exact() {
        let p = ListParams::parse(Some("namespace=Demo"));
        assert_eq!(p.namespace.as_deref(), Some("demo"));
        assert!(p.namespace_matches("demo"));
        assert!(p.namespace_matches("DEMO"));
        assert!(!p.namespace_matches("demo-2")); // exact, not substring
        assert!(!p.namespace_matches("other"));
        assert!(!p.is_empty());
        // absent → always matches
        assert!(ListParams::default().namespace_matches("anything"));
    }

    #[test]
    fn name_filter_is_case_insensitive_substring() {
        let p = ListParams::parse(Some("name=API"));
        assert!(p.name_matches("api-route"));
        assert!(p.name_matches("public-API")); // substring, not a prefix
        assert!(!p.name_matches("web-route"));
        assert!(!p.is_empty());
        // absent → always matches
        assert!(ListParams::default().name_matches("anything"));
    }

    #[test]
    fn paginate_windows_and_reports_total() {
        let rows: Vec<serde_json::Value> = (0..10).map(serde_json::Value::from).collect();
        let params = ListParams {
            limit: Some(3),
            offset: 8,
            ..Default::default()
        };
        let page = Page::paginate(rows, &params);
        assert_eq!(page.total, 10);
        assert_eq!(page.offset, 8);
        assert_eq!(page.returned, 2); // only 2 rows left past offset 8
        assert_eq!(page.items, vec![serde_json::json!(8), serde_json::json!(9)]);
    }

    #[test]
    fn paginate_offset_past_end_is_empty_but_keeps_total() {
        let rows: Vec<serde_json::Value> = (0..3).map(serde_json::Value::from).collect();
        let params = ListParams {
            offset: 50,
            ..Default::default()
        };
        let page = Page::paginate(rows, &params);
        assert_eq!(page.total, 3);
        assert_eq!(page.returned, 0);
        assert_eq!(page.offset, 3); // clamped to total
    }
}
