//! Per-request filter actions: the [`FilterAction`] enum and the building blocks
//! it composes — path modifiers, header mutations, CORS policy, and mirror
//! sampling. Shared by both the Ingress and Gateway-API route builders and
//! evaluated on the proxy hot path.

use super::backend::BackendGroup;
use http::{HeaderName, HeaderValue};
use std::sync::Arc;

/// How a path is modified by `URLRewrite` or `RequestRedirect`.
#[derive(Clone, Debug)]
pub enum PathModifier {
    /// Discard the entire original path and use this fixed value instead.
    ReplaceFullPath(String),
    /// Replace `prefix` with `replacement` in the matched request path.
    ReplacePrefixMatch {
        /// The path prefix to strip (as registered at route build time).
        prefix: String,
        /// The string to prepend in place of the stripped prefix.
        replacement: String,
    },
    /// Expand regex capture groups into a replacement template.
    ///
    /// Backs the Ingress `use-regex` + `rewrite-target` pairing: the request path is
    /// matched against this route's own `ImplementationSpecific` pattern and `$1`…`$n`
    /// references in the template are substituted from the captures. Because the
    /// pattern is the route's own, capture substitution is intrinsically per-path even
    /// though the `rewrite-target` template is Ingress-scoped.
    RegexReplace {
        /// The route's compiled path regex, compiled once at reconcile and shared
        /// (`Arc`) — never recompiled per request.
        regex: Arc<regex::Regex>,
        /// The replacement template, e.g. `/$2`. Missing groups expand to empty.
        replacement: Box<str>,
    },
}

impl PathModifier {
    /// Apply this modifier to `path` and return the resulting path string.
    ///
    /// For `ReplacePrefixMatch`, returns `path` unchanged if it does not start
    /// with the prefix (should not happen in practice since routing only selects
    /// routes whose prefix matched, but avoids a panic on edge cases).
    pub fn apply(&self, path: &str) -> String {
        match self {
            PathModifier::ReplaceFullPath(p) => p.clone(),
            PathModifier::ReplacePrefixMatch {
                prefix,
                replacement,
            } => {
                let prefix_trimmed = prefix.trim_end_matches('/');
                if path == prefix_trimmed || path.starts_with(prefix_trimmed) {
                    let suffix = &path[prefix_trimmed.len()..];
                    let rep = replacement.trim_end_matches('/');
                    match suffix {
                        "" | "/" => {
                            if rep.is_empty() {
                                "/".to_string()
                            } else {
                                rep.to_string()
                            }
                        }
                        s => format!("{rep}{s}"),
                    }
                } else {
                    path.to_string()
                }
            }
            PathModifier::RegexReplace { regex, replacement } => {
                // The route was already selected by an `is_match` against the same
                // pattern, so `captures` normally succeeds; fall back to the
                // unchanged path defensively rather than panicking if it does not.
                match regex.captures(path) {
                    Some(caps) => {
                        let mut out = String::new();
                        caps.expand(replacement, &mut out);
                        out
                    }
                    None => path.to_string(),
                }
            }
        }
    }
}

/// Error produced when a header name or value is invalid at routing-table build time.
#[derive(Debug, thiserror::Error)]
pub enum HeaderModError {
    /// A header name string is not a valid HTTP token.
    #[error("invalid header name {name:?}: {source}")]
    InvalidName {
        /// The invalid header name string.
        name: String,
        /// The underlying parse error.
        #[source]
        source: http::header::InvalidHeaderName,
    },
    /// A header value string contains characters forbidden by RFC 7230.
    #[error("invalid header value for {name:?}: {source}")]
    InvalidValue {
        /// The header name the value was associated with.
        name: String,
        /// The underlying parse error.
        #[source]
        source: http::header::InvalidHeaderValue,
    },
}

/// Header add/set/remove operations applied as a unit.
///
/// Headers are pre-parsed at routing-table build time — no per-request
/// `HeaderName::from_bytes` / `HeaderValue::from_str` parsing on the hot path.
#[derive(Clone, Debug, Default)]
pub struct HeaderMod {
    /// Headers appended to any existing values.
    pub add: Vec<(HeaderName, HeaderValue)>,
    /// Headers overwritten (set).
    pub set: Vec<(HeaderName, HeaderValue)>,
    /// Header names removed entirely.
    pub remove: Vec<HeaderName>,
}

impl HeaderMod {
    /// Parse and validate raw string header pairs at build time.
    ///
    /// # Errors
    ///
    /// Returns `HeaderModError` if any name or value string is not a valid HTTP header.
    #[must_use = "the parsed HeaderMod is the result; dropping it discards the validated filter"]
    pub fn parse(
        add: &[(&str, &str)],
        set: &[(&str, &str)],
        remove: &[&str],
    ) -> Result<Self, HeaderModError> {
        let parse_pair = |name: &str,
                          value: &str|
         -> Result<(HeaderName, HeaderValue), HeaderModError> {
            let n = HeaderName::from_bytes(name.as_bytes()).map_err(|source| {
                HeaderModError::InvalidName {
                    name: name.to_string(),
                    source,
                }
            })?;
            let v =
                HeaderValue::from_str(value).map_err(|source| HeaderModError::InvalidValue {
                    name: name.to_string(),
                    source,
                })?;
            Ok((n, v))
        };
        let parse_name = |name: &str| -> Result<HeaderName, HeaderModError> {
            HeaderName::from_bytes(name.as_bytes()).map_err(|source| HeaderModError::InvalidName {
                name: name.to_string(),
                source,
            })
        };
        Ok(Self {
            add: add
                .iter()
                .map(|(n, v)| parse_pair(n, v))
                .collect::<Result<_, _>>()?,
            set: set
                .iter()
                .map(|(n, v)| parse_pair(n, v))
                .collect::<Result<_, _>>()?,
            remove: remove
                .iter()
                .map(|n| parse_name(n))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// A single origin entry from `HTTPRoute` CORS `allowOrigins` (GEP-1767).
///
/// Wildcard entries carry a `*` that may appear anywhere in the pattern;
/// matching checks that the request origin (lowercased) starts with `prefix`
/// and ends with `suffix`. Both halves are stored lowercased at parse time.
///
/// A bare `*` entry (match-all) is expressed via
/// [`CorsConfig::allow_all_origins`] rather than this enum.
#[derive(Clone, Debug)]
pub enum CorsOrigin {
    /// Exact origin string (lowercased at construction time).
    Exact(String),
    /// Wildcard pattern split at the `*` (e.g. `https://*.example.com` →
    /// `prefix = "https://"`, `suffix = ".example.com"`).
    ///
    /// Matches when the lowercased request origin starts with `prefix`
    /// and ends with `suffix`.
    Wildcard {
        /// Portion of the allowOrigins pattern before the `*`, lowercased.
        prefix: Box<str>,
        /// Portion of the allowOrigins pattern after the `*`, lowercased.
        suffix: Box<str>,
    },
}

impl CorsOrigin {
    /// Returns `true` if `request_origin` matches this entry (case-insensitive).
    ///
    /// The `Exact` arm compares in place via `eq_ignore_ascii_case` and allocates
    /// nothing — this is the per-request hot path (one call per allow-list entry).
    /// Only the rarer `Wildcard` arm lowercases into an owned `String`, because
    /// `starts_with`/`ends_with` have no case-insensitive stdlib equivalent.
    #[must_use]
    pub fn matches(&self, request_origin: &str) -> bool {
        match self {
            CorsOrigin::Exact(s) => request_origin.eq_ignore_ascii_case(s),
            CorsOrigin::Wildcard { prefix, suffix } => {
                let lower = request_origin.to_ascii_lowercase();
                lower.starts_with(prefix.as_ref()) && lower.ends_with(suffix.as_ref())
            }
        }
    }
}

/// Pre-rendered CORS policy for one `HTTPRoute` rule (GEP-1767).
///
/// The fixed `HeaderValue`s (methods, headers, expose-headers, max-age) are all
/// built once at reconcile time, so injecting them is a cheap `Bytes`-backed
/// clone. The one value constructed per matched request is the echoed
/// `Access-Control-Allow-Origin` — see [`CorsConfig::resolve_origin`], which
/// must mirror the caller's own `Origin` and so builds a fresh `HeaderValue`
/// from it (only on a match; non-matches allocate nothing).
///
/// Origin matching always echoes the concrete request `Origin` back rather than
/// `*`, which is spec-correct in all cases and is required when
/// [`allow_credentials`][Self::allow_credentials] is `true` (Fetch spec §3.2.5).
#[derive(Clone, Debug)]
pub struct CorsConfig {
    /// Parsed origin allow-list. Empty means "match none".
    pub allow_origins: Vec<CorsOrigin>,
    /// `true` when the allow-list contained a bare `*` entry — match any origin.
    pub allow_all_origins: bool,
    /// Whether to emit `Access-Control-Allow-Credentials: true`.
    pub allow_credentials: bool,
    /// Pre-joined `Access-Control-Allow-Methods` value, or `None` if unset.
    pub allow_methods: Option<HeaderValue>,
    /// Pre-joined `Access-Control-Allow-Headers` value, or `None` if unset.
    pub allow_headers: Option<HeaderValue>,
    /// Pre-joined `Access-Control-Expose-Headers` value, or `None` if unset.
    pub expose_headers: Option<HeaderValue>,
    /// `Access-Control-Max-Age` value (pre-formatted; default `"5"`).
    pub max_age: HeaderValue,
}

impl CorsConfig {
    /// Constructs a new [`CorsConfig`].
    ///
    /// Called at reconcile time (reflector / discovery deserialization), not on
    /// the hot path. Pass `None` for optional pre-rendered header values.
    pub fn new(
        allow_origins: Vec<CorsOrigin>,
        allow_all_origins: bool,
        allow_credentials: bool,
        allow_methods: Option<HeaderValue>,
        allow_headers: Option<HeaderValue>,
        expose_headers: Option<HeaderValue>,
        max_age: HeaderValue,
    ) -> Self {
        Self {
            allow_origins,
            allow_all_origins,
            allow_credentials,
            allow_methods,
            allow_headers,
            expose_headers,
            max_age,
        }
    }

    /// Returns the `Access-Control-Allow-Origin` value to emit for the given
    /// request origin, or `None` when no allow-list entry matches.
    ///
    /// The concrete request origin is echoed rather than `*` — this is always
    /// spec-correct and satisfies the credential-mode requirement without a
    /// special-case branch.
    ///
    /// Returns `None` (without error) when the origin contains bytes that cannot
    /// form a valid [`HeaderValue`]; callers treat this as a non-match.
    #[must_use]
    pub fn resolve_origin(&self, request_origin: &str) -> Option<HeaderValue> {
        let matched =
            self.allow_all_origins || self.allow_origins.iter().any(|o| o.matches(request_origin));
        if matched {
            HeaderValue::from_str(request_origin).ok()
        } else {
            None
        }
    }
}

/// GEP-3171 mirror sampling fraction.
///
/// Normalises both the `percent` (integer 0–100) and `fraction { numerator, denominator }`
/// forms from the Gateway API `HTTPRequestMirrorFilter` into a single representation.
/// `None` on a [`FilterAction::Mirror`] means 100% (mirror every request).
///
/// The proxy draws one random `u32` per mirror candidate and calls [`MirrorFraction::should_sample`]
/// to decide whether to dispatch; this keeps the RNG in the proxy and the arithmetic here
/// where it can be unit-tested cheaply.
///
/// # Invariants
///
/// `numerator ≤ denominator` and `denominator > 0`.  [`MirrorFraction::new`] returns `None`
/// when these do not hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MirrorFraction {
    /// Requests to mirror out of `denominator`.  0 means never mirror.
    numerator: u32,
    /// Denominator of the fraction.  Must be > 0.
    denominator: u32,
}

impl MirrorFraction {
    /// Constructs a [`MirrorFraction`] from `numerator / denominator`.
    ///
    /// Returns `None` when `denominator == 0` or `numerator > denominator`.
    #[must_use]
    pub fn new(numerator: u32, denominator: u32) -> Option<Self> {
        if denominator == 0 || numerator > denominator {
            return None;
        }
        Some(Self {
            numerator,
            denominator,
        })
    }

    /// Returns `true` when a request with the given `draw` (a uniform random `u32`)
    /// should be mirrored.
    ///
    /// The gate is `draw % denominator < numerator`, which is uniform and allocation-free.
    /// `numerator == 0` always returns `false`; `numerator == denominator` always returns
    /// `true` (100% mirror).
    #[must_use]
    pub fn should_sample(self, draw: u32) -> bool {
        draw % self.denominator < self.numerator
    }

    /// Returns `(numerator, denominator)` for wire encoding.
    #[must_use]
    pub fn as_parts(self) -> (u32, u32) {
        (self.numerator, self.denominator)
    }
}

/// A filter action evaluated per-request on the proxy hot path.
#[derive(Clone, Debug)]
pub enum FilterAction {
    /// Modify request headers before forwarding upstream.
    RequestHeaderModifier(HeaderMod),
    /// Modify response headers before returning to the client.
    ResponseHeaderModifier(HeaderMod),
    /// Return a 3xx redirect without connecting to the upstream.
    RequestRedirect {
        /// Override the `scheme` component of the redirect URL.
        scheme: Option<String>,
        /// Override the `host` component of the redirect URL.
        hostname: Option<String>,
        /// Override the port of the redirect URL.
        port: Option<u16>,
        /// HTTP status code (default 302).
        status_code: u16,
        /// Optional path rewrite applied to the redirect URL.
        path: Option<PathModifier>,
    },
    /// Rewrite the upstream request host and/or path (client-visible URL is unchanged).
    UrlRewrite {
        /// Replacement `Host` header for the upstream request.
        hostname: Option<String>,
        /// Path rewrite applied to the upstream request.
        path: Option<PathModifier>,
    },
    /// Mirror the matched request, fire-and-forget, to a secondary backend.
    ///
    /// The primary request is unaffected by the mirror outcome; the mirror response is
    /// discarded entirely. The backend is resolved to pod endpoints at reconcile time so
    /// the hot path performs no per-request resolution. Shared with the HTTPRoute
    /// `HTTPRequestMirrorFilter` surface (#261).
    ///
    /// Ingress surface: `ingress.coxswain-labs.dev/mirror-target` (#283).
    Mirror {
        /// Pre-resolved mirror backend (round-robins to a concrete endpoint at dispatch time).
        backend: Arc<BackendGroup>,
        /// GEP-3171 sampling fraction.  `None` means mirror every request (100%).
        /// When `Some`, the proxy draws a random value per request and skips dispatch
        /// when the draw falls outside the fraction's range.
        fraction: Option<MirrorFraction>,
    },
    /// Apply CORS policy (GEP-1767) to the matched request.
    ///
    /// On `OPTIONS` preflight requests (presence of `Access-Control-Request-Method`),
    /// the proxy short-circuits with a `204` carrying the allow-headers without
    /// forwarding to the upstream. On actual CORS requests, the proxy injects
    /// `Access-Control-Allow-Origin` (and optionally `Allow-Credentials` /
    /// `Expose-Headers`) into the upstream response.
    ///
    /// Wrapped in [`Arc`] so this variant stays one pointer wide in the hot
    /// `Arc<[FilterAction]>` slice.
    Cors(Arc<CorsConfig>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use std::sync::Arc;

    // ── PathModifier::RegexReplace ────────────────────────────────────────────────

    fn regex_replace(pattern: &str, template: &str) -> PathModifier {
        PathModifier::RegexReplace {
            regex: Arc::new(regex::Regex::new(pattern).expect("test pattern compiles")),
            replacement: template.into(),
        }
    }

    #[test]
    fn regex_replace_expands_capture_groups() {
        // The canonical nginx pattern: capture the tail and rewrite the upstream path.
        let pm = regex_replace(r"^/something(/|$)(.*)", "/$2");
        assert_eq!(pm.apply("/something/foo/bar"), "/foo/bar");
        assert_eq!(pm.apply("/something/"), "/");
    }

    #[test]
    fn regex_replace_missing_group_expands_empty() {
        // `$3` has no corresponding group → expands to empty, matching the regex crate.
        let pm = regex_replace(r"^/api/(.*)", "/v2/$1$3");
        assert_eq!(pm.apply("/api/users"), "/v2/users");
    }

    #[test]
    fn regex_replace_no_match_falls_back_to_path() {
        // Defensive: `apply` is only reached after `is_match` selected the route, but a
        // non-matching path must not panic — it returns unchanged.
        let pm = regex_replace(r"^/api/(\d+)$", "/n/$1");
        assert_eq!(pm.apply("/api/abc"), "/api/abc");
    }

    // ── CorsOrigin::matches ───────────────────────────────────────────────────────

    #[test]
    fn cors_origin_exact_matches_case_insensitively() {
        let o = CorsOrigin::Exact("https://example.com".to_string());
        assert!(o.matches("https://example.com"));
        assert!(o.matches("https://EXAMPLE.COM"));
        assert!(o.matches("HTTPS://Example.Com"));
    }

    #[test]
    fn cors_origin_exact_rejects_different_origin() {
        let o = CorsOrigin::Exact("https://example.com".to_string());
        assert!(!o.matches("https://other.com"));
        assert!(!o.matches("http://example.com")); // different scheme
        assert!(!o.matches("https://example.com:8080")); // port mismatch
    }

    #[test]
    fn cors_origin_wildcard_matches_subdomain() {
        let o = CorsOrigin::Wildcard {
            prefix: "https://".into(),
            suffix: ".example.com".into(),
        };
        assert!(o.matches("https://foo.example.com"));
        assert!(o.matches("https://BAR.example.com")); // case-insensitive
    }

    #[test]
    fn cors_origin_wildcard_rejects_wrong_scheme_or_suffix() {
        let o = CorsOrigin::Wildcard {
            prefix: "https://".into(),
            suffix: ".example.com".into(),
        };
        assert!(!o.matches("http://foo.example.com")); // wrong scheme
        assert!(!o.matches("https://foo.other.com")); // wrong suffix
        assert!(!o.matches("https://example.com")); // no subdomain — doesn't end with .example.com after the prefix
    }

    // ── CorsConfig::resolve_origin ────────────────────────────────────────────────

    fn cors_config_exact(origin: &str) -> CorsConfig {
        CorsConfig {
            allow_origins: vec![CorsOrigin::Exact(origin.to_ascii_lowercase())],
            allow_all_origins: false,
            allow_credentials: false,
            allow_methods: None,
            allow_headers: None,
            expose_headers: None,
            max_age: HeaderValue::from_static("5"),
        }
    }

    #[test]
    fn resolve_origin_returns_echoed_origin_on_match() {
        let cfg = cors_config_exact("https://allowed.example");
        let hv = cfg
            .resolve_origin("https://allowed.example")
            .expect("should match");
        assert_eq!(hv, "https://allowed.example");
    }

    #[test]
    fn resolve_origin_returns_none_when_no_match() {
        let cfg = cors_config_exact("https://allowed.example");
        assert!(cfg.resolve_origin("https://evil.example").is_none());
    }

    #[test]
    fn resolve_origin_allow_all_origins_matches_any() {
        let cfg = CorsConfig {
            allow_origins: vec![],
            allow_all_origins: true,
            allow_credentials: false,
            allow_methods: None,
            allow_headers: None,
            expose_headers: None,
            max_age: HeaderValue::from_static("5"),
        };
        let hv = cfg
            .resolve_origin("https://any.random.example")
            .expect("should match");
        assert_eq!(hv, "https://any.random.example");
    }

    #[test]
    fn resolve_origin_echoes_concrete_origin_not_wildcard() {
        // Even when allow_all_origins is set the concrete origin is echoed,
        // satisfying the credentials-mode requirement without a special-case branch.
        let cfg = CorsConfig {
            allow_origins: vec![],
            allow_all_origins: true,
            allow_credentials: true,
            allow_methods: None,
            allow_headers: None,
            expose_headers: None,
            max_age: HeaderValue::from_static("5"),
        };
        let hv = cfg
            .resolve_origin("https://specific.example.com")
            .expect("should match");
        assert_eq!(hv, "https://specific.example.com");
        assert_ne!(hv, "*");
    }
}
