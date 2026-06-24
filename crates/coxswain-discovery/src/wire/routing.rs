//! Wire-DTO conversions between compiled routing types and proto3 messages.
//!
//! # Overview
//!
//! The controller calls `to_wire` to serialise a compiled [`RoutingTable`] into
//! a proto message and then embeds it in a [`Snapshot`].  The proxy
//! calls `from_wire` on arrival and replays the builder API — exactly the same
//! public constructors the reflector uses — to produce a freshly-compiled table
//! without ever touching the Kubernetes API.
//!
//! # Determinism
//!
//! All `to_wire` functions emit data in deterministic canonical order:
//! - Ports: ascending by port number.
//! - Hosts per port: exact entries first (sorted by hostname), then wildcard
//!   (sorted by suffix), then catchall.
//! - Routes per host: in `wire_entries()` insertion order — the order the
//!   reflector registered them, which is stable across reconcile cycles for the
//!   same set of Ingress/HTTPRoute objects.
//! - Addresses inside a backend: sorted for hash stability.
//! - CIDRs: sorted string representation.
//! - TLS/mTLS entries: sorted by host pattern.
//! - Listener health entries: sorted by `ObjectKey` string.
//!
//! No `map<>` fields appear anywhere in the proto; all maps are `repeated Entry`
//! emitted in sorted order.  This makes the serialised bytes byte-identical
//! across reconcile cycles for the same routing world, which keeps the
//! `ContentHash` oracle stable.
//!
//! # Recursion guard
//!
//! `FilterAction::Mirror` embeds an `Arc<BackendGroup>`, which itself may carry
//! `per_backend_filters` containing further `Mirror` actions.  In practice the
//! graph is a tree (no cycles), but the proto is untrusted: `from_wire` limits
//! recursion through Mirror backends to [`MAX_MIRROR_DEPTH`].
//!
//! [`RoutingTable`]: coxswain_core::routing::RoutingTable
//! [`Snapshot`]: crate::proto::v1::Snapshot

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use coxswain_core::routing::{
    BackendGroup, BackendProtocol, BasicCredential, CircuitBreakerConfig, CompressionConfig,
    ExtAuthConfig, ExtAuthTransport, FilterAction, ForwardedForConfig, GatewayRoutingTable,
    HashSource, HeaderMod, HeaderPredicate, HostPattern, HostRouter, HostRouterBuilder,
    HttpExtAuthConfig, IngressAuthConfig, IngressRoutingTable, LoadBalance, MatchPredicates,
    NormalizeLevel, PasswordHash, PathModifier, PortRoutingTable, QueryPredicate, RateLimitConfig,
    RateLimitKey, RouteEntry, RouteKind, RouteTimeouts, RouterError, SessionAffinity, UpstreamCa,
    UpstreamTls, ValueMatch, WildcardKind,
};

use crate::error::WireError;
use crate::proto::v1 as p;

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

/// Maximum nesting depth for `Mirror` backends in `from_wire`.
///
/// Prevents unbounded recursion through untrusted proto bytes where a Mirror
/// backend itself carries a per-backend filter that embeds another Mirror, etc.
/// Trees only in practice; this guard is a safety net for malformed input.
pub const MAX_MIRROR_DEPTH: usize = 4;

// ────────────────────────────────────────────────────────────────────────────
// Routing table: to_wire
// ────────────────────────────────────────────────────────────────────────────

/// Serialise an [`IngressRoutingTable`] to its wire DTO.
#[must_use = "wire DTO must be embedded in a Snapshot to reach the proxy"]
pub fn ingress_to_wire(t: &IngressRoutingTable) -> p::RoutingTable {
    routing_table_to_wire(t)
}

/// Serialise a [`GatewayRoutingTable`] to its wire DTO.
#[must_use = "wire DTO must be embedded in a Snapshot to reach the proxy"]
pub fn gateway_to_wire(t: &GatewayRoutingTable) -> p::RoutingTable {
    routing_table_to_wire(t)
}

fn routing_table_to_wire<Kind>(t: &coxswain_core::routing::RoutingTable<Kind>) -> p::RoutingTable {
    let mut ports: Vec<(u16, &PortRoutingTable)> = t.ports().collect();
    ports.sort_by_key(|(p, _)| *p);

    p::RoutingTable {
        ports: ports
            .into_iter()
            .map(|(port, pt)| port_entry_to_wire(port, pt))
            .collect(),
    }
}

fn port_entry_to_wire(port: u16, pt: &PortRoutingTable) -> p::PortEntry {
    // Collect host views in canonical order: exact (sorted), wildcard (sorted by suffix), catchall.
    let mut exact_entries: Vec<(&str, &HostRouter)> = Vec::new();
    let mut wildcard_entries: Vec<(&str, WildcardKind, &HostRouter)> = Vec::new();
    let mut catchall_entry: Option<&HostRouter> = None;

    for (pattern, router) in pt.host_views() {
        match pattern {
            HostPattern::Exact(h) => exact_entries.push((h, router)),
            HostPattern::Wildcard(suffix, kind) => wildcard_entries.push((suffix, kind, router)),
            HostPattern::Catchall => catchall_entry = Some(router),
            _ => {} // future HostPattern variants: skip (won't be wired until wire.rs is updated)
        }
    }
    exact_entries.sort_by_key(|(h, _)| *h);
    wildcard_entries.sort_by_key(|(s, _, _)| *s);

    let mut hosts = Vec::new();
    for (hostname, router) in exact_entries {
        hosts.push(host_entry_to_wire(
            p::host_entry::Pattern::Exact(hostname.to_string()),
            router,
        ));
    }
    for (suffix, kind, router) in wildcard_entries {
        hosts.push(host_entry_to_wire(
            p::host_entry::Pattern::Wildcard(p::WildcardHost {
                suffix: suffix.to_string(),
                kind: wildcard_kind_to_wire(kind) as i32,
            }),
            router,
        ));
    }
    if let Some(router) = catchall_entry {
        hosts.push(host_entry_to_wire(
            p::host_entry::Pattern::Catchall(true),
            router,
        ));
    }

    p::PortEntry {
        port: u32::from(port),
        hosts,
    }
}

fn host_entry_to_wire(pattern: p::host_entry::Pattern, router: &HostRouter) -> p::HostEntry {
    let routes: Vec<p::RouteEntry> = router
        .wire_entries()
        .map(|(path, kind, entry)| route_entry_to_wire(path, kind, entry))
        .collect();

    p::HostEntry {
        pattern: Some(pattern),
        normalize_level: normalize_level_to_wire(router.normalize()) as i32,
        routes,
    }
}

fn route_entry_to_wire(path: &str, kind: RouteKind, e: &RouteEntry) -> p::RouteEntry {
    let mut allow_source_range: Vec<String> = e
        .allow_source_range
        .as_deref()
        .map(|nets| nets.iter().map(|n| n.to_string()).collect())
        .unwrap_or_default();
    allow_source_range.sort_unstable();

    let mut deny_source_range: Vec<String> = e
        .deny_source_range
        .as_deref()
        .map(|nets| nets.iter().map(|n| n.to_string()).collect())
        .unwrap_or_default();
    deny_source_range.sort_unstable();

    p::RouteEntry {
        kind: route_kind_to_wire(kind) as i32,
        path: path.to_string(),
        backend_group: Some(backend_group_to_wire(&e.backend_group, 0)),
        predicates: Some(predicates_to_wire(&e.predicates)),
        filters: e.filters.iter().map(|f| filter_to_wire(f, 0)).collect(),
        timeouts: Some(timeouts_to_wire(&e.timeouts)),
        route_id: e.route_id.clone(),
        metric_route_id: e.metric_route_id.to_string(),
        path_pattern: e.path_pattern.to_string(),
        created_at_unix_millis: e.created_at.and_then(|t| {
            t.duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as u64)
        }),
        error_status: e.error_status.map(u32::from),
        max_body_size: e.max_body_size,
        allow_source_range,
        deny_source_range,
        cache_enabled: e.cache_enabled,
        access_log_enabled: e.access_log_enabled,
        rate_limit: e.rate_limit.as_deref().map(rate_limit_to_wire),
        auth: e.auth.as_deref().map(auth_to_wire),
        compression: e.compression.as_deref().map(compression_to_wire),
        forwarded_for: e.forwarded_for.as_deref().map(forwarded_for_to_wire),
        circuit_breaker: e.circuit_breaker.as_deref().map(circuit_breaker_to_wire),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// BackendGroup
// ────────────────────────────────────────────────────────────────────────────

fn backend_group_to_wire(bg: &BackendGroup, depth: usize) -> p::BackendGroup {
    let spec = bg.spec();
    let weighted: Vec<p::WeightedBackend> = spec
        .weighted
        .iter()
        .map(|(addrs, weight)| {
            let mut addr_strs: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
            addr_strs.sort_unstable();
            p::WeightedBackend {
                addrs: addr_strs,
                weight: u32::from(*weight),
            }
        })
        .collect();

    // Per-backend filters: emit only slots with non-empty filters, indexed by position.
    let per_backend_filters: Vec<p::PerBackendFiltersEntry> = bg
        .per_backend_filters()
        .unwrap_or(&[])
        .iter()
        .enumerate()
        .filter_map(|(i, slot)| {
            slot.as_ref().map(|filters| p::PerBackendFiltersEntry {
                backend_index: i as u32,
                filters: filters.iter().map(|f| filter_to_wire(f, depth)).collect(),
            })
        })
        .collect();

    let keepalive_millis = bg.keepalive_timeout().map(|d| d.as_millis() as u64);

    p::BackendGroup {
        name: bg.name().to_string(),
        weighted,
        protocol: protocol_to_wire(bg.protocol()) as i32,
        tls: bg.upstream_tls().map(|t| upstream_tls_to_wire(t)),
        retry: Some(retry_to_wire(&bg.retry_policy())),
        keepalive_millis,
        per_backend_filters,
        load_balance: Some(load_balance_to_wire(bg.load_balance())),
        session_affinity: bg.session_affinity().map(session_affinity_to_wire),
    }
}

fn upstream_tls_to_wire(tls: &UpstreamTls) -> p::UpstreamTls {
    let ca = match &tls.ca {
        UpstreamCa::System => p::upstream_tls::Ca::System(true),
        UpstreamCa::Bundle(pem) => p::upstream_tls::Ca::Bundle(pem.to_vec()),
        _ => unreachable!(
            "invariant: all UpstreamCa variants handled; update wire.rs when adding new variants"
        ),
    };
    p::UpstreamTls {
        sni: tls.sni.to_string(),
        ca: Some(ca),
        group_key: tls.group_key,
    }
}

fn retry_to_wire(retry: &coxswain_core::routing::RetryPolicy) -> p::RetryPolicy {
    use coxswain_core::routing::RetryOn;
    p::RetryPolicy {
        max_retries: retry.max_retries,
        on_connect_failure: retry.on.contains(RetryOn::CONNECT_FAILURE),
        on_timeout: retry.on.contains(RetryOn::TIMEOUT),
        on_http_5xx: retry.on.contains(RetryOn::HTTP_5XX),
    }
}

fn load_balance_to_wire(lb: &LoadBalance) -> p::LoadBalance {
    let algorithm = match lb {
        LoadBalance::RoundRobin => p::load_balance::Algorithm::RoundRobin(true),
        LoadBalance::LeastConn => p::load_balance::Algorithm::LeastConn(true),
        LoadBalance::Ewma => p::load_balance::Algorithm::Ewma(true),
        LoadBalance::Hash(src) => p::load_balance::Algorithm::Hash(hash_source_to_wire(src)),
        _ => unreachable!(
            "invariant: all LoadBalance variants handled; update wire.rs when adding new variants"
        ),
    };
    p::LoadBalance {
        algorithm: Some(algorithm),
    }
}

fn hash_source_to_wire(src: &HashSource) -> p::HashSource {
    let source = match src {
        HashSource::Uri => p::hash_source::Source::Uri(true),
        HashSource::SourceIp => p::hash_source::Source::SourceIp(true),
        HashSource::Header(name) => p::hash_source::Source::Header(name.as_str().to_string()),
        HashSource::Cookie(name) => p::hash_source::Source::Cookie(name.to_string()),
        _ => unreachable!(
            "invariant: all HashSource variants handled; update wire.rs when adding new variants"
        ),
    };
    p::HashSource {
        source: Some(source),
    }
}

fn session_affinity_to_wire(sa: &SessionAffinity) -> p::SessionAffinity {
    let mode = match sa {
        SessionAffinity::Cookie { cookie_name } => {
            p::session_affinity::Mode::CookieName(cookie_name.to_string())
        }
        SessionAffinity::Header { header } => {
            p::session_affinity::Mode::Header(header.as_str().to_string())
        }
        _ => unreachable!(
            "invariant: all SessionAffinity variants handled; update wire.rs when adding new variants"
        ),
    };
    p::SessionAffinity { mode: Some(mode) }
}

// ────────────────────────────────────────────────────────────────────────────
// Filters
// ────────────────────────────────────────────────────────────────────────────

fn filter_to_wire(f: &FilterAction, depth: usize) -> p::FilterAction {
    let action = match f {
        FilterAction::RequestHeaderModifier(hm) => {
            p::filter_action::Action::RequestHeaderModifier(header_mod_to_wire(hm))
        }
        FilterAction::ResponseHeaderModifier(hm) => {
            p::filter_action::Action::ResponseHeaderModifier(header_mod_to_wire(hm))
        }
        FilterAction::RequestRedirect {
            scheme,
            hostname,
            port,
            status_code,
            path,
        } => p::filter_action::Action::RequestRedirect(p::RequestRedirect {
            scheme: scheme.clone(),
            hostname: hostname.clone(),
            port: port.map(u32::from),
            status_code: u32::from(*status_code),
            path: path.as_ref().map(path_modifier_to_wire),
        }),
        FilterAction::UrlRewrite { hostname, path } => {
            p::filter_action::Action::UrlRewrite(p::UrlRewrite {
                hostname: hostname.clone(),
                path: path.as_ref().map(path_modifier_to_wire),
            })
        }
        FilterAction::Mirror { backend } => {
            // Saturate depth rather than panic — depth > MAX_MIRROR_DEPTH is
            // only reachable if the runtime type was built with malformed data
            // (defensive guard; from_wire is the primary enforcement site).
            p::filter_action::Action::Mirror(backend_group_to_wire(
                backend,
                depth.saturating_add(1),
            ))
        }
        _ => unreachable!(
            "invariant: all FilterAction variants handled; update wire.rs when adding new variants"
        ),
    };
    p::FilterAction {
        action: Some(action),
    }
}

fn header_mod_to_wire(hm: &HeaderMod) -> p::HeaderMod {
    p::HeaderMod {
        add: hm
            .add
            .iter()
            .map(|(n, v)| p::HeaderPair {
                name: n.as_str().to_string(),
                value: v.to_str().unwrap_or("").to_string(),
            })
            .collect(),
        set: hm
            .set
            .iter()
            .map(|(n, v)| p::HeaderPair {
                name: n.as_str().to_string(),
                value: v.to_str().unwrap_or("").to_string(),
            })
            .collect(),
        remove: hm.remove.iter().map(|n| n.as_str().to_string()).collect(),
    }
}

fn path_modifier_to_wire(pm: &PathModifier) -> p::PathModifier {
    let modifier = match pm {
        PathModifier::ReplaceFullPath(p) => p::path_modifier::Modifier::ReplaceFullPath(p.clone()),
        PathModifier::ReplacePrefixMatch {
            prefix,
            replacement,
        } => p::path_modifier::Modifier::ReplacePrefix(p::ReplacePrefix {
            prefix: prefix.clone(),
            replacement: replacement.clone(),
        }),
        PathModifier::RegexReplace { regex, replacement } => {
            p::path_modifier::Modifier::RegexReplace(p::RegexReplace {
                pattern: regex.as_str().to_string(),
                replacement: replacement.to_string(),
            })
        }
        _ => unreachable!(
            "invariant: all PathModifier variants handled; update wire.rs when adding new variants"
        ),
    };
    p::PathModifier {
        modifier: Some(modifier),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Predicates
// ────────────────────────────────────────────────────────────────────────────

fn predicates_to_wire(mp: &MatchPredicates) -> p::MatchPredicates {
    p::MatchPredicates {
        method: mp.method.as_ref().map(|m| m.as_str().to_string()),
        headers: mp
            .headers
            .iter()
            .map(|hp| p::HeaderPredicate {
                name: hp.name.as_str().to_string(),
                matcher: Some(value_match_to_wire(&hp.matcher)),
            })
            .collect(),
        query: mp
            .query
            .iter()
            .map(|qp| p::QueryPredicate {
                name: qp.name.clone(),
                matcher: Some(value_match_to_wire(&qp.matcher)),
            })
            .collect(),
    }
}

fn value_match_to_wire(vm: &ValueMatch) -> p::ValueMatch {
    let m = match vm {
        ValueMatch::Exact(s) => p::value_match::Value::Exact(s.clone()),
        ValueMatch::Regex(re) => p::value_match::Value::Regex(re.as_str().to_string()),
        _ => unreachable!(
            "invariant: all ValueMatch variants handled; update wire.rs when adding new variants"
        ),
    };
    p::ValueMatch { value: Some(m) }
}

// ────────────────────────────────────────────────────────────────────────────
// Timeouts and Duration
// ────────────────────────────────────────────────────────────────────────────

fn timeouts_to_wire(rt: &RouteTimeouts) -> p::RouteTimeouts {
    p::RouteTimeouts {
        request: rt.request.map(duration_to_wire),
        backend_request: rt.backend_request.map(duration_to_wire),
        connect: rt.connect.map(duration_to_wire),
        read: rt.read.map(duration_to_wire),
        send: rt.send.map(duration_to_wire),
    }
}

fn duration_to_wire(d: Duration) -> p::Duration {
    p::Duration {
        secs: d.as_secs(),
        nanos: d.subsec_nanos(),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Per-route config
// ────────────────────────────────────────────────────────────────────────────

fn rate_limit_to_wire(rl: &RateLimitConfig) -> p::RateLimitConfig {
    let key = match &rl.key {
        RateLimitKey::ClientIp => p::RateLimitKey {
            dimension: Some(p::rate_limit_key::Dimension::ClientIp(true)),
        },
        RateLimitKey::Header(name) => p::RateLimitKey {
            dimension: Some(p::rate_limit_key::Dimension::Header(name.to_string())),
        },
        _ => unreachable!(
            "invariant: all RateLimitKey variants handled; update wire.rs when adding new variants"
        ),
    };
    p::RateLimitConfig {
        requests_per_second: rl.requests_per_second.get(),
        burst: rl.burst,
        key: Some(key),
    }
}

fn auth_to_wire(auth: &IngressAuthConfig) -> p::IngressAuthConfig {
    let a = match auth {
        IngressAuthConfig::External(ext) => {
            p::ingress_auth_config::Auth::External(p::ExtAuthConfig {
                timeout: Some(duration_to_wire(ext.timeout)),
                http: Some(match &ext.transport {
                    ExtAuthTransport::Http(h) => p::HttpExtAuthConfig {
                        url: h.url.to_string(),
                        response_headers: h
                            .response_headers
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        always_set_cookie: h.always_set_cookie,
                    },
                    _ => unreachable!("invariant: all ExtAuthTransport variants handled; update wire.rs when adding new variants"),
                }),
            })
        }
        IngressAuthConfig::Basic(creds) => {
            p::ingress_auth_config::Auth::Basic(p::BasicCredList {
                credentials: creds
                    .iter()
                    .map(|c| {
                        let (hash_kind, hash) = match &c.hash {
                            PasswordHash::Bcrypt(h) => {
                                (p::PasswordHash::Bcrypt as i32, h.to_string())
                            }
                            PasswordHash::Sha1(h) => {
                                (p::PasswordHash::Sha1 as i32, h.to_string())
                            }
                            _ => unreachable!("invariant: all PasswordHash variants handled; update wire.rs when adding new variants"),
                        };
                        p::BasicCred {
                            username: c.username.to_string(),
                            hash_kind,
                            hash,
                        }
                    })
                    .collect(),
            })
        }
        IngressAuthConfig::Unavailable => {
            p::ingress_auth_config::Auth::Unavailable(true)
        }
        _ => unreachable!("invariant: all IngressAuthConfig variants handled; update wire.rs when adding new variants"),
    };
    p::IngressAuthConfig { auth: Some(a) }
}

fn compression_to_wire(c: &CompressionConfig) -> p::CompressionConfig {
    let mut types: Vec<String> = c.types.iter().map(|t| t.to_string()).collect();
    types.sort_unstable();
    p::CompressionConfig {
        gzip: c.gzip,
        brotli: c.brotli,
        level: c.level,
        min_size: c.min_size,
        types,
    }
}

fn forwarded_for_to_wire(ff: &ForwardedForConfig) -> p::ForwardedForConfig {
    let mut trusted_cidrs: Vec<String> = ff.trusted_cidrs.iter().map(|n| n.to_string()).collect();
    trusted_cidrs.sort_unstable();
    p::ForwardedForConfig {
        header: ff.header.to_string(),
        trusted_cidrs,
    }
}

fn circuit_breaker_to_wire(cb: &CircuitBreakerConfig) -> p::CircuitBreakerConfig {
    p::CircuitBreakerConfig {
        threshold_pct: u32::from(cb.threshold_pct),
        min_requests: cb.min_requests,
        window: Some(duration_to_wire(cb.window)),
        open_duration: Some(duration_to_wire(cb.open_duration)),
        max_open_duration: cb.max_open_duration.map(duration_to_wire),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Enum mappings
// ────────────────────────────────────────────────────────────────────────────

fn route_kind_to_wire(k: RouteKind) -> p::RouteKind {
    match k {
        RouteKind::Exact => p::RouteKind::Exact,
        RouteKind::Prefix => p::RouteKind::Prefix,
        RouteKind::Regex => p::RouteKind::Regex,
        _ => unreachable!(
            "invariant: all RouteKind variants handled; update wire.rs when adding new variants"
        ),
    }
}

fn wildcard_kind_to_wire(k: WildcardKind) -> p::WildcardKind {
    match k {
        WildcardKind::SingleLabel => p::WildcardKind::SingleLabel,
        WildcardKind::MultiLabel => p::WildcardKind::MultiLabel,
        _ => unreachable!(
            "invariant: all WildcardKind variants handled; update wire.rs when adding new variants"
        ),
    }
}

fn normalize_level_to_wire(n: NormalizeLevel) -> p::NormalizeLevel {
    match n {
        NormalizeLevel::None => p::NormalizeLevel::None,
        NormalizeLevel::Base => p::NormalizeLevel::Base,
        NormalizeLevel::MergeSlashes => p::NormalizeLevel::MergeSlashes,
        NormalizeLevel::DecodeAndMergeSlashes => p::NormalizeLevel::DecodeAndMergeSlashes,
        _ => unreachable!(
            "invariant: all NormalizeLevel variants handled; update wire.rs when adding new variants"
        ),
    }
}

fn protocol_to_wire(proto: BackendProtocol) -> p::BackendProtocol {
    match proto {
        BackendProtocol::Http1 => p::BackendProtocol::Http1,
        BackendProtocol::H2c => p::BackendProtocol::H2c,
        BackendProtocol::WebSocket => p::BackendProtocol::WebSocket,
        BackendProtocol::Https => p::BackendProtocol::Https,
        BackendProtocol::WebSocketTls => p::BackendProtocol::WebSocketTls,
        _ => unreachable!(
            "invariant: all BackendProtocol variants handled; update wire.rs when adding new variants"
        ),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Routing table: from_wire
// ────────────────────────────────────────────────────────────────────────────

/// Reconstruct an [`IngressRoutingTable`] from its wire DTO.
///
/// # Errors
///
/// Returns [`WireError`] if any field is invalid (bad regex, bad header name,
/// unknown enum value, depth-exceeded mirror, etc.).
#[must_use = "the rebuilt routing table must be stored for the proxy to use it"]
pub fn ingress_from_wire(dto: &p::RoutingTable) -> Result<IngressRoutingTable, WireError> {
    routing_table_from_wire::<coxswain_core::routing::Ingress>(dto)
}

/// Reconstruct a [`GatewayRoutingTable`] from its wire DTO.
///
/// # Errors
///
/// Returns [`WireError`] if any field is invalid.
#[must_use = "the rebuilt routing table must be stored for the proxy to use it"]
pub fn gateway_from_wire(dto: &p::RoutingTable) -> Result<GatewayRoutingTable, WireError> {
    routing_table_from_wire::<coxswain_core::routing::Gateway>(dto)
}

fn routing_table_from_wire<Kind>(
    dto: &p::RoutingTable,
) -> Result<coxswain_core::routing::RoutingTable<Kind>, WireError>
where
    coxswain_core::routing::RoutingTableBuilder<Kind>: Default,
{
    let mut builder = coxswain_core::routing::RoutingTableBuilder::<Kind>::new();
    for port_entry in &dto.ports {
        let port = port_entry.port as u16;
        let port_builder = builder.for_port(port);
        for host_entry in &port_entry.hosts {
            host_entry_from_wire(host_entry, port_builder)?;
        }
    }
    builder.build().map_err(|e| match e {
        RouterError::Regex(re) => WireError::InvalidRegex(re),
        other => WireError::InvalidMatchitPath(other.to_string()),
    })
}

fn host_entry_from_wire(
    he: &p::HostEntry,
    port_builder: &mut coxswain_core::routing::PortTableBuilder,
) -> Result<(), WireError> {
    let normalize = normalize_level_from_wire(he.normalize_level)?;

    let pattern = he.pattern.as_ref().ok_or(WireError::MissingRequiredField {
        field: "host_entry.pattern",
    })?;

    let host_builder = match pattern {
        p::host_entry::Pattern::Exact(hostname) => port_builder.exact_host(hostname),
        p::host_entry::Pattern::Wildcard(w) => {
            let kind = wildcard_kind_from_wire(w.kind)?;
            let pattern = format!("*.{}", w.suffix);
            port_builder.wildcard_host(&pattern, kind)
        }
        p::host_entry::Pattern::Catchall(_) => port_builder.catchall(),
    };

    host_builder.set_path_normalize(normalize);

    for route_dto in &he.routes {
        route_entry_from_wire(route_dto, host_builder)?;
    }
    Ok(())
}

fn route_entry_from_wire(
    dto: &p::RouteEntry,
    host_builder: &mut HostRouterBuilder,
) -> Result<(), WireError> {
    let kind = route_kind_from_wire(dto.kind)?;
    let entry = Arc::new(build_route_entry(dto)?);

    match kind {
        RouteKind::Exact => {
            host_builder.add_exact_route(&dto.path, entry);
        }
        RouteKind::Prefix => {
            host_builder.add_prefix_route(&dto.path, entry);
        }
        RouteKind::Regex => {
            host_builder.add_regex_route(&dto.path, entry);
        }
        _ => unreachable!(
            "invariant: all RouteKind variants handled; \
             add a new arm when the core type gains a variant"
        ),
    }
    Ok(())
}

fn build_route_entry(dto: &p::RouteEntry) -> Result<RouteEntry, WireError> {
    let bg_dto = dto
        .backend_group
        .as_ref()
        .ok_or(WireError::MissingRequiredField {
            field: "route_entry.backend_group",
        })?;
    let backend_group = Arc::new(bg_from_wire(bg_dto, 0)?);

    let predicates = dto
        .predicates
        .as_ref()
        .map(predicates_from_wire)
        .transpose()?
        .unwrap_or_default();

    let mut filters = Vec::with_capacity(dto.filters.len());
    for f in &dto.filters {
        filters.push(filter_from_wire(f, 0)?);
    }

    let timeouts = dto
        .timeouts
        .as_ref()
        .map(timeouts_from_wire)
        .unwrap_or_default();

    let created_at = dto
        .created_at_unix_millis
        .map(|ms| UNIX_EPOCH + Duration::from_millis(ms));

    let mut entry = RouteEntry::with_filters(
        backend_group,
        predicates,
        filters,
        timeouts,
        dto.route_id.clone(),
        created_at,
    );
    entry = entry.with_metric_route_id(dto.metric_route_id.clone().into());
    entry = entry.with_path_pattern(dto.path_pattern.clone().into());
    entry = entry.with_error_status(dto.error_status.map(|s| s as u16));

    if let Some(max) = dto.max_body_size {
        entry = entry.with_max_body_size(Some(max));
    }

    if !dto.allow_source_range.is_empty() {
        let nets: Vec<ipnet::IpNet> = dto
            .allow_source_range
            .iter()
            .map(|s| s.parse::<ipnet::IpNet>().map_err(WireError::InvalidCidr))
            .collect::<Result<_, _>>()?;
        entry = entry.with_allow_source_range(Some(Arc::new(nets)));
    }

    if !dto.deny_source_range.is_empty() {
        let nets: Vec<ipnet::IpNet> = dto
            .deny_source_range
            .iter()
            .map(|s| s.parse::<ipnet::IpNet>().map_err(WireError::InvalidCidr))
            .collect::<Result<_, _>>()?;
        entry = entry.with_deny_source_range(Some(Arc::new(nets)));
    }

    if dto.cache_enabled {
        entry = entry.with_cache_enabled(true);
    }
    if let Some(enabled) = dto.access_log_enabled {
        entry = entry.with_access_log_enabled(Some(enabled));
    }

    if let Some(rl_dto) = &dto.rate_limit {
        entry = entry.with_rate_limit(Some(Arc::new(rate_limit_from_wire(rl_dto)?)));
    }
    if let Some(auth_dto) = &dto.auth {
        entry = entry.with_auth(Some(Arc::new(auth_from_wire(auth_dto)?)));
    }
    if let Some(c_dto) = &dto.compression {
        entry = entry.with_compression(Some(Arc::new(compression_from_wire(c_dto))));
    }
    if let Some(ff_dto) = &dto.forwarded_for {
        entry = entry.with_forwarded_for(Some(Arc::new(forwarded_for_from_wire(ff_dto)?)));
    }
    if let Some(cb_dto) = &dto.circuit_breaker {
        entry = entry.with_circuit_breaker(Some(Arc::new(circuit_breaker_from_wire(cb_dto))));
    }

    Ok(entry)
}

// ────────────────────────────────────────────────────────────────────────────
// BackendGroup: from_wire
// ────────────────────────────────────────────────────────────────────────────

pub(crate) fn bg_from_wire(dto: &p::BackendGroup, depth: usize) -> Result<BackendGroup, WireError> {
    if depth > MAX_MIRROR_DEPTH {
        return Err(WireError::MirrorTooDeep {
            limit: MAX_MIRROR_DEPTH,
        });
    }

    // Reconstruct (addrs, weight) pairs from BackendGroupSpec.
    let mut pools: Vec<(Vec<SocketAddr>, u16)> = Vec::with_capacity(dto.weighted.len());
    for wb in &dto.weighted {
        let addrs: Vec<SocketAddr> = wb
            .addrs
            .iter()
            .map(|s| s.parse::<SocketAddr>().map_err(WireError::InvalidAddr))
            .collect::<Result<_, _>>()?;
        let weight = wb.weight as u16;
        pools.push((addrs, weight));
    }

    // Build per-backend filters (sparse; indexed by backend_index).
    let per_backend_filters: Option<Vec<Vec<FilterAction>>> = if dto.per_backend_filters.is_empty()
    {
        None
    } else {
        let mut slots: Vec<Vec<FilterAction>> = vec![vec![]; pools.len()];
        for entry in &dto.per_backend_filters {
            let idx = entry.backend_index as usize;
            if idx < slots.len() {
                let filters: Vec<FilterAction> = entry
                    .filters
                    .iter()
                    .map(|f| filter_from_wire(f, depth + 1))
                    .collect::<Result<_, _>>()?;
                slots[idx] = filters;
            }
        }
        Some(slots)
    };

    let protocol = protocol_from_wire(dto.protocol)?;

    let tls = dto.tls.as_ref().map(upstream_tls_from_wire).transpose()?;

    let retry = dto.retry.as_ref().map(retry_from_wire).unwrap_or_default();

    // weighted() accepts (addrs_ref, weight); we need to feed the pairs from the spec.
    let pairs: Vec<(Vec<SocketAddr>, u16)> = pools;
    let mut bg = BackendGroup::weighted(dto.name.clone(), pairs);

    bg = bg.with_protocol(protocol);
    if let Some(tls) = tls {
        bg = bg.with_tls(Arc::new(tls));
    }
    bg = bg.with_retries(retry);
    if let Some(ms) = dto.keepalive_millis {
        bg = bg.with_keepalive_timeout(Some(Duration::from_millis(ms)));
    }
    if let Some(pbf) = per_backend_filters {
        bg = bg.with_per_backend_filters(pbf);
    }

    let lb = dto
        .load_balance
        .as_ref()
        .ok_or(WireError::InvalidLoadBalance)
        .and_then(load_balance_from_wire)?;
    bg = bg.with_load_balance(lb);

    if let Some(sa_dto) = &dto.session_affinity {
        let sa = session_affinity_from_wire(sa_dto)?;
        bg = bg.with_session_affinity(Some(sa));
    }

    Ok(bg)
}

fn upstream_tls_from_wire(dto: &p::UpstreamTls) -> Result<UpstreamTls, WireError> {
    let ca = match dto.ca.as_ref().ok_or(WireError::MissingRequiredField {
        field: "upstream_tls.ca",
    })? {
        p::upstream_tls::Ca::System(_) => UpstreamCa::System,
        p::upstream_tls::Ca::Bundle(pem) => UpstreamCa::Bundle(Arc::from(pem.clone())),
    };
    Ok(UpstreamTls::new(
        Arc::from(dto.sni.as_str()),
        ca,
        dto.group_key,
    ))
}

fn retry_from_wire(dto: &p::RetryPolicy) -> coxswain_core::routing::RetryPolicy {
    use coxswain_core::routing::{RetryOn, RetryPolicy};
    let mut on = RetryOn::empty();
    if dto.on_connect_failure {
        on.insert(RetryOn::CONNECT_FAILURE);
    }
    if dto.on_timeout {
        on.insert(RetryOn::TIMEOUT);
    }
    if dto.on_http_5xx {
        on.insert(RetryOn::HTTP_5XX);
    }
    RetryPolicy::new(dto.max_retries, on)
}

fn load_balance_from_wire(dto: &p::LoadBalance) -> Result<LoadBalance, WireError> {
    match dto
        .algorithm
        .as_ref()
        .ok_or(WireError::InvalidLoadBalance)?
    {
        p::load_balance::Algorithm::RoundRobin(_) => Ok(LoadBalance::RoundRobin),
        p::load_balance::Algorithm::LeastConn(_) => Ok(LoadBalance::LeastConn),
        p::load_balance::Algorithm::Ewma(_) => Ok(LoadBalance::Ewma),
        p::load_balance::Algorithm::Hash(src) => Ok(LoadBalance::Hash(hash_source_from_wire(src)?)),
    }
}

fn hash_source_from_wire(dto: &p::HashSource) -> Result<HashSource, WireError> {
    match dto.source.as_ref().ok_or(WireError::InvalidLoadBalance)? {
        p::hash_source::Source::Uri(_) => Ok(HashSource::Uri),
        p::hash_source::Source::SourceIp(_) => Ok(HashSource::SourceIp),
        p::hash_source::Source::Header(name) => Ok(HashSource::Header(
            http::HeaderName::from_bytes(name.as_bytes())?,
        )),
        p::hash_source::Source::Cookie(name) => Ok(HashSource::Cookie(Arc::from(name.as_str()))),
    }
}

fn session_affinity_from_wire(dto: &p::SessionAffinity) -> Result<SessionAffinity, WireError> {
    match dto.mode.as_ref().ok_or(WireError::MissingRequiredField {
        field: "session_affinity.mode",
    })? {
        p::session_affinity::Mode::CookieName(name) => Ok(SessionAffinity::Cookie {
            cookie_name: Arc::from(name.as_str()),
        }),
        p::session_affinity::Mode::Header(name) => Ok(SessionAffinity::Header {
            header: http::HeaderName::from_bytes(name.as_bytes())?,
        }),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Filters: from_wire
// ────────────────────────────────────────────────────────────────────────────

fn filter_from_wire(dto: &p::FilterAction, depth: usize) -> Result<FilterAction, WireError> {
    if depth > MAX_MIRROR_DEPTH {
        return Err(WireError::MirrorTooDeep {
            limit: MAX_MIRROR_DEPTH,
        });
    }
    let action = dto.action.as_ref().ok_or(WireError::MissingRequiredField {
        field: "filter_action.action",
    })?;
    match action {
        p::filter_action::Action::RequestHeaderModifier(hm) => Ok(
            FilterAction::RequestHeaderModifier(header_mod_from_wire(hm)?),
        ),
        p::filter_action::Action::ResponseHeaderModifier(hm) => Ok(
            FilterAction::ResponseHeaderModifier(header_mod_from_wire(hm)?),
        ),
        p::filter_action::Action::RequestRedirect(rd) => Ok(FilterAction::RequestRedirect {
            scheme: rd.scheme.clone(),
            hostname: rd.hostname.clone(),
            port: rd.port.map(|p| p as u16),
            status_code: rd.status_code as u16,
            path: rd.path.as_ref().map(path_modifier_from_wire).transpose()?,
        }),
        p::filter_action::Action::UrlRewrite(uw) => Ok(FilterAction::UrlRewrite {
            hostname: uw.hostname.clone(),
            path: uw.path.as_ref().map(path_modifier_from_wire).transpose()?,
        }),
        p::filter_action::Action::Mirror(bg_dto) => {
            let backend = Arc::new(bg_from_wire(bg_dto, depth + 1)?);
            Ok(FilterAction::Mirror { backend })
        }
    }
}

fn header_mod_from_wire(dto: &p::HeaderMod) -> Result<HeaderMod, WireError> {
    let add: Vec<(&str, &str)> = dto
        .add
        .iter()
        .map(|p| (p.name.as_str(), p.value.as_str()))
        .collect();
    let set: Vec<(&str, &str)> = dto
        .set
        .iter()
        .map(|p| (p.name.as_str(), p.value.as_str()))
        .collect();
    let remove: Vec<&str> = dto.remove.iter().map(|s| s.as_str()).collect();
    HeaderMod::parse(&add, &set, &remove).map_err(|e| match e {
        coxswain_core::routing::HeaderModError::InvalidName { source, .. } => {
            WireError::InvalidHeaderName(source)
        }
        coxswain_core::routing::HeaderModError::InvalidValue { source, .. } => {
            WireError::InvalidHeaderValue(source)
        }
        _ => unreachable!(
            "invariant: all HeaderModError variants handled; \
                 add a new arm when the core type gains a variant"
        ),
    })
}

fn path_modifier_from_wire(dto: &p::PathModifier) -> Result<PathModifier, WireError> {
    match dto
        .modifier
        .as_ref()
        .ok_or(WireError::MissingRequiredField {
            field: "path_modifier.modifier",
        })? {
        p::path_modifier::Modifier::ReplaceFullPath(p) => {
            Ok(PathModifier::ReplaceFullPath(p.clone()))
        }
        p::path_modifier::Modifier::ReplacePrefix(rp) => Ok(PathModifier::ReplacePrefixMatch {
            prefix: rp.prefix.clone(),
            replacement: rp.replacement.clone(),
        }),
        p::path_modifier::Modifier::RegexReplace(rr) => {
            let regex = Arc::new(regex::Regex::new(&rr.pattern)?);
            Ok(PathModifier::RegexReplace {
                regex,
                replacement: rr.replacement.clone().into_boxed_str(),
            })
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Predicates: from_wire
// ────────────────────────────────────────────────────────────────────────────

fn predicates_from_wire(dto: &p::MatchPredicates) -> Result<MatchPredicates, WireError> {
    let method = dto
        .method
        .as_deref()
        .map(|m| http::Method::from_bytes(m.as_bytes()))
        .transpose()?;

    let mut headers = Vec::with_capacity(dto.headers.len());
    for hp in &dto.headers {
        let name = http::HeaderName::from_bytes(hp.name.as_bytes())?;
        let matcher = hp
            .matcher
            .as_ref()
            .ok_or(WireError::MissingRequiredField {
                field: "header_predicate.matcher",
            })
            .and_then(value_match_from_wire)?;
        headers.push(HeaderPredicate { name, matcher });
    }

    let mut query = Vec::with_capacity(dto.query.len());
    for qp in &dto.query {
        let matcher = qp
            .matcher
            .as_ref()
            .ok_or(WireError::MissingRequiredField {
                field: "query_predicate.matcher",
            })
            .and_then(value_match_from_wire)?;
        query.push(QueryPredicate {
            name: qp.name.clone(),
            matcher,
        });
    }

    Ok(MatchPredicates {
        method,
        headers,
        query,
    })
}

fn value_match_from_wire(dto: &p::ValueMatch) -> Result<ValueMatch, WireError> {
    match dto.value.as_ref().ok_or(WireError::MissingRequiredField {
        field: "value_match.value",
    })? {
        p::value_match::Value::Exact(s) => Ok(ValueMatch::Exact(s.clone())),
        p::value_match::Value::Regex(pat) => Ok(ValueMatch::Regex(regex::Regex::new(pat)?)),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Timeouts: from_wire
// ────────────────────────────────────────────────────────────────────────────

fn timeouts_from_wire(dto: &p::RouteTimeouts) -> RouteTimeouts {
    RouteTimeouts {
        request: dto.request.as_ref().map(duration_from_wire),
        backend_request: dto.backend_request.as_ref().map(duration_from_wire),
        connect: dto.connect.as_ref().map(duration_from_wire),
        read: dto.read.as_ref().map(duration_from_wire),
        send: dto.send.as_ref().map(duration_from_wire),
    }
}

fn duration_from_wire(dto: &p::Duration) -> Duration {
    Duration::new(dto.secs, dto.nanos)
}

// ────────────────────────────────────────────────────────────────────────────
// Per-route config: from_wire
// ────────────────────────────────────────────────────────────────────────────

pub(crate) fn rate_limit_from_wire(dto: &p::RateLimitConfig) -> Result<RateLimitConfig, WireError> {
    let rps = NonZeroU32::new(dto.requests_per_second).ok_or(WireError::ZeroRps)?;
    let key = dto
        .key
        .as_ref()
        .ok_or(WireError::MissingRequiredField {
            field: "rate_limit.key",
        })
        .and_then(|k| {
            match k
                .dimension
                .as_ref()
                .ok_or(WireError::MissingRequiredField {
                    field: "rate_limit_key.dimension",
                })? {
                p::rate_limit_key::Dimension::ClientIp(_) => Ok(RateLimitKey::ClientIp),
                p::rate_limit_key::Dimension::Header(name) => {
                    Ok(RateLimitKey::Header(Arc::from(name.as_str())))
                }
            }
        })?;
    Ok(RateLimitConfig::new(rps, dto.burst, key))
}

fn auth_from_wire(dto: &p::IngressAuthConfig) -> Result<IngressAuthConfig, WireError> {
    match dto.auth.as_ref().ok_or(WireError::MissingRequiredField {
        field: "ingress_auth_config.auth",
    })? {
        p::ingress_auth_config::Auth::External(ext) => {
            let http = ext.http.as_ref().ok_or(WireError::MissingRequiredField {
                field: "ext_auth.http",
            })?;
            Ok(IngressAuthConfig::External(ExtAuthConfig::new(
                ext.timeout
                    .as_ref()
                    .map(duration_from_wire)
                    .unwrap_or_default(),
                ExtAuthTransport::Http(HttpExtAuthConfig::new(
                    Arc::from(http.url.as_str()),
                    http.response_headers
                        .iter()
                        .map(|s| Box::from(s.as_str()))
                        .collect::<Arc<[_]>>(),
                    http.always_set_cookie,
                )),
            )))
        }
        p::ingress_auth_config::Auth::Basic(list) => {
            let creds: Arc<[BasicCredential]> = list
                .credentials
                .iter()
                .map(|c| {
                    let hash = match p::PasswordHash::try_from(c.hash_kind).ok() {
                        Some(p::PasswordHash::Bcrypt) => {
                            PasswordHash::Bcrypt(Box::from(c.hash.as_str()))
                        }
                        Some(p::PasswordHash::Sha1) => {
                            PasswordHash::Sha1(Box::from(c.hash.as_str()))
                        }
                        _ => {
                            return Err(WireError::InvalidEnumValue {
                                value: c.hash_kind,
                                field: "basic_cred.hash_kind",
                            });
                        }
                    };
                    Ok(BasicCredential::new(c.username.as_str(), hash))
                })
                .collect::<Result<_, _>>()?;
            Ok(IngressAuthConfig::Basic(creds))
        }
        p::ingress_auth_config::Auth::Unavailable(_) => Ok(IngressAuthConfig::Unavailable),
    }
}

fn compression_from_wire(dto: &p::CompressionConfig) -> CompressionConfig {
    CompressionConfig::new(
        dto.gzip,
        dto.brotli,
        dto.level,
        dto.min_size,
        dto.types.iter().map(|t| Box::from(t.as_str())).collect(),
    )
}

fn forwarded_for_from_wire(dto: &p::ForwardedForConfig) -> Result<ForwardedForConfig, WireError> {
    let trusted_cidrs: Box<[ipnet::IpNet]> = dto
        .trusted_cidrs
        .iter()
        .map(|s| s.parse::<ipnet::IpNet>().map_err(WireError::InvalidCidr))
        .collect::<Result<_, _>>()?;
    Ok(ForwardedForConfig::new(
        Box::from(dto.header.as_str()),
        trusted_cidrs,
    ))
}

fn circuit_breaker_from_wire(dto: &p::CircuitBreakerConfig) -> CircuitBreakerConfig {
    CircuitBreakerConfig::new(
        dto.threshold_pct as u8,
        dto.min_requests,
        dto.window
            .as_ref()
            .map(duration_from_wire)
            .unwrap_or_default(),
        dto.open_duration
            .as_ref()
            .map(duration_from_wire)
            .unwrap_or_default(),
        dto.max_open_duration.as_ref().map(duration_from_wire),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// Enum mappings: from_wire
//
// Two deliberate patterns here, by whether the field has a safe default:
//   - `route_kind` / `wildcard_kind` have NO sensible default — a route with no
//     kind is meaningless — so proto3 `Unspecified` (the zero value, also where
//     `try_from` lands an out-of-range int) returns `WireError::InvalidEnumValue`.
//   - `normalize_level` / `protocol` DO have a safe default (`Base` / `Http1`),
//     so `Unspecified` *and* any unknown/out-of-range value degrade to that
//     default rather than rejecting the whole snapshot. This is intentional
//     forward-compat: a newer controller advertising a level/protocol this build
//     doesn't know falls back to safe behaviour instead of failing closed.
// ────────────────────────────────────────────────────────────────────────────

fn route_kind_from_wire(v: i32) -> Result<RouteKind, WireError> {
    match p::RouteKind::try_from(v).unwrap_or(p::RouteKind::Unspecified) {
        p::RouteKind::Exact => Ok(RouteKind::Exact),
        p::RouteKind::Prefix => Ok(RouteKind::Prefix),
        p::RouteKind::Regex => Ok(RouteKind::Regex),
        p::RouteKind::Unspecified => Err(WireError::InvalidEnumValue {
            value: v,
            field: "route_entry.kind",
        }),
    }
}

fn wildcard_kind_from_wire(v: i32) -> Result<WildcardKind, WireError> {
    match p::WildcardKind::try_from(v).unwrap_or(p::WildcardKind::Unspecified) {
        p::WildcardKind::SingleLabel => Ok(WildcardKind::SingleLabel),
        p::WildcardKind::MultiLabel => Ok(WildcardKind::MultiLabel),
        p::WildcardKind::Unspecified => Err(WireError::InvalidEnumValue {
            value: v,
            field: "wildcard_host.kind",
        }),
    }
}

fn normalize_level_from_wire(v: i32) -> Result<NormalizeLevel, WireError> {
    match p::NormalizeLevel::try_from(v).unwrap_or(p::NormalizeLevel::Unspecified) {
        p::NormalizeLevel::Unspecified | p::NormalizeLevel::Base => Ok(NormalizeLevel::Base),
        p::NormalizeLevel::None => Ok(NormalizeLevel::None),
        p::NormalizeLevel::MergeSlashes => Ok(NormalizeLevel::MergeSlashes),
        p::NormalizeLevel::DecodeAndMergeSlashes => Ok(NormalizeLevel::DecodeAndMergeSlashes),
    }
}

fn protocol_from_wire(v: i32) -> Result<BackendProtocol, WireError> {
    match p::BackendProtocol::try_from(v).unwrap_or(p::BackendProtocol::Unspecified) {
        p::BackendProtocol::Unspecified | p::BackendProtocol::Http1 => Ok(BackendProtocol::Http1),
        p::BackendProtocol::H2c => Ok(BackendProtocol::H2c),
        p::BackendProtocol::WebSocket => Ok(BackendProtocol::WebSocket),
        p::BackendProtocol::Https => Ok(BackendProtocol::Https),
        p::BackendProtocol::WebSocketTls => Ok(BackendProtocol::WebSocketTls),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::tests::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    pub(super) fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap_or_else(|e| panic!("bad addr {s}: {e}"))
    }

    pub(super) fn simple_bg(name: &str, addrs: &[SocketAddr]) -> Arc<BackendGroup> {
        Arc::new(BackendGroup::new(name.to_string(), addrs.to_vec()))
    }

    pub(super) fn simple_entry(bg: Arc<BackendGroup>) -> RouteEntry {
        RouteEntry::with_filters(
            bg,
            MatchPredicates::default(),
            vec![],
            RouteTimeouts::default(),
            "test-route".to_string(),
            None,
        )
    }

    pub(super) fn ctx() -> RequestContext<'static> {
        RequestContext::default()
    }

    pub(super) fn rt_ingress(
        builder: IngressRoutingTableBuilder,
    ) -> coxswain_core::routing::IngressRoutingTable {
        let t = builder.build().expect("build");
        let dto = ingress_to_wire(&t);
        ingress_from_wire(&dto).expect("from_wire")
    }

    pub(super) fn rt_gateway(
        builder: GatewayRoutingTableBuilder,
    ) -> coxswain_core::routing::GatewayRoutingTable {
        let t = builder.build().expect("build");
        let dto = gateway_to_wire(&t);
        gateway_from_wire(&dto).expect("from_wire")
    }

    // ── 1. Ingress exact route ────────────────────────────────────────────────

    #[test]
    fn ingress_exact_route_round_trips() {
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:8080")]);
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/foo", entry);

        let rt = rt_ingress(b);
        assert!(
            rt.route(80, "example.com", "/foo", &ctx()).is_some(),
            "exact /foo must hit"
        );
        assert!(
            rt.route(80, "example.com", "/bar", &ctx()).is_none(),
            "/bar must miss"
        );
        assert!(
            rt.route(80, "other.com", "/foo", &ctx()).is_none(),
            "wrong host must miss"
        );
    }

    // ── 2. Ingress prefix routes ──────────────────────────────────────────────

    #[test]
    fn ingress_prefix_route_round_trips() {
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:8080")]);
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_prefix_route("/foo", entry);

        let rt = rt_ingress(b);
        assert!(
            rt.route(80, "example.com", "/foo", &ctx()).is_some(),
            "/foo hit"
        );
        assert!(
            rt.route(80, "example.com", "/foo/", &ctx()).is_some(),
            "/foo/ hit"
        );
        assert!(
            rt.route(80, "example.com", "/foo/bar", &ctx()).is_some(),
            "/foo/bar hit"
        );
        assert!(
            rt.route(80, "example.com", "/foobar", &ctx()).is_none(),
            "/foobar must miss"
        );
    }

    // ── 3. Ingress regex route ────────────────────────────────────────────────

    #[test]
    fn ingress_regex_route_round_trips() {
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:8080")]);
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_regex_route(r"^/api/v\d+$", entry);

        let rt = rt_ingress(b);
        assert!(
            rt.route(80, "example.com", "/api/v1", &ctx()).is_some(),
            "/api/v1 hit"
        );
        assert!(
            rt.route(80, "example.com", "/api/v42", &ctx()).is_some(),
            "/api/v42 hit"
        );
        assert!(
            rt.route(80, "example.com", "/api/vX", &ctx()).is_none(),
            "/api/vX miss"
        );
        assert!(
            rt.route(80, "example.com", "/api/v1/sub", &ctx()).is_none(),
            "sub-path miss"
        );
    }

    // ── 4. Gateway weighted multi-backend spec preserved ──────────────────────
    //
    // This test verifies that pre-GCD weighted groups survive the wire round-trip
    // (BackendGroupSpec). Predicates are omitted so the default RequestContext matches.

    #[test]
    fn gateway_weighted_multi_backend_spec_preserved() {
        let a1 = addr("10.0.0.1:80");
        let a2 = addr("10.0.0.2:80");
        let b1 = addr("10.1.0.1:80");
        let bg = Arc::new(BackendGroup::weighted(
            "ns/svc".to_string(),
            vec![(vec![a1, a2], 4), (vec![b1], 2)],
        ));

        let entry = Arc::new(simple_entry(bg));

        let mut b = GatewayRoutingTableBuilder::new();
        b.for_port(443)
            .exact_host("api.example.com")
            .add_exact_route("/submit", entry);

        let rt = rt_gateway(b);
        let bg2 = rt
            .route(443, "api.example.com", "/submit", &ctx())
            .expect("hit");
        let spec = bg2.spec();
        assert_eq!(spec.weighted.len(), 2, "two backend groups");
        assert_eq!(spec.weighted[0].1, 4, "first group weight = 4 (pre-GCD)");
        assert_eq!(spec.weighted[1].1, 2, "second group weight = 2 (pre-GCD)");
    }

    // ── 7. Compression config ─────────────────────────────────────────────────

    #[test]
    fn compression_config_round_trips() {
        let types: Box<[Box<str>]> =
            vec![Box::from("text/html"), Box::from("application/json")].into();
        let comp = CompressionConfig::new(true, true, 6, 1024, types);

        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(simple_entry(bg).with_compression(Some(Arc::new(comp))));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);

        let rt = rt_ingress(b);
        let RouteOutcome::Found(m) = rt.find(80, "example.com", "/", &ctx()) else {
            panic!("expected Found")
        };
        let comp2 = m.compression.as_deref().expect("compression present");
        assert!(comp2.gzip, "gzip preserved");
        assert!(comp2.brotli, "brotli preserved");
        assert_eq!(comp2.level, 6, "level preserved");
        assert_eq!(comp2.min_size, 1024, "min_size preserved");
        assert!(comp2.allows_type("text/html"), "text/html preserved");
        assert!(
            comp2.allows_type("application/json"),
            "application/json preserved"
        );
    }

    // ── 8. Rate-limit: ClientIp + Header; zero-rps → error ───────────────────

    #[test]
    fn rate_limit_client_ip_round_trips() {
        let rl = RateLimitConfig::new(NonZeroU32::new(100).unwrap(), 50, RateLimitKey::ClientIp);
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(simple_entry(bg).with_rate_limit(Some(Arc::new(rl))));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);
        rt_ingress(b);
    }

    #[test]
    fn rate_limit_header_round_trips() {
        let rl = RateLimitConfig::new(
            NonZeroU32::new(50).unwrap(),
            0,
            RateLimitKey::Header(Arc::from("x-api-key")),
        );
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(simple_entry(bg).with_rate_limit(Some(Arc::new(rl))));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);
        rt_ingress(b);
    }

    #[test]
    fn zero_rps_from_wire_returns_error() {
        let rl_dto = p::RateLimitConfig {
            requests_per_second: 0, // invalid
            burst: 0,
            key: Some(p::RateLimitKey {
                dimension: Some(p::rate_limit_key::Dimension::ClientIp(true)),
            }),
        };
        let err = rate_limit_from_wire(&rl_dto).unwrap_err();
        assert!(
            matches!(err, WireError::ZeroRps),
            "expected ZeroRps, got {err:?}"
        );
    }

    // ── 9. Source-range allow + deny ──────────────────────────────────────────

    #[test]
    fn source_range_round_trips() {
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(
            simple_entry(bg)
                .with_allow_source_range(Some(Arc::new(vec!["10.0.0.0/8".parse().unwrap()])))
                .with_deny_source_range(Some(Arc::new(vec!["10.1.0.0/16".parse().unwrap()]))),
        );

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);
        let rt = rt_ingress(b);

        let RouteOutcome::Found(m) = rt.find(80, "example.com", "/", &ctx()) else {
            panic!("expected Found")
        };
        assert_eq!(
            m.allow_source_range.as_deref().map(|v| v.len()),
            Some(1),
            "allow range"
        );
        assert_eq!(
            m.deny_source_range.as_deref().map(|v| v.len()),
            Some(1),
            "deny range"
        );
    }

    // ── 10. Per-backend filters: index alignment ──────────────────────────────

    #[test]
    fn per_backend_filters_index_alignment_round_trips() {
        let a = addr("10.0.0.1:80");
        let b_addr = addr("10.0.1.1:80");
        let hdr_filter = FilterAction::RequestHeaderModifier(
            coxswain_core::routing::HeaderMod::parse(&[("x-via", "proxy")], &[], &[])
                .expect("header mod"),
        );

        let bg = Arc::new(
            BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a], 1), (vec![b_addr], 1)])
                .with_per_backend_filters(vec![
                    vec![hdr_filter], // backend 0 gets a filter
                    vec![],           // backend 1 has none
                ]),
        );
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/api", entry);

        let rt = rt_ingress(b);
        let bg2 = rt.route(80, "example.com", "/api", &ctx()).expect("hit");
        let pbf = bg2
            .per_backend_filters()
            .expect("per-backend filters present");
        assert_eq!(pbf.len(), 2, "two slots");
        assert!(pbf[0].is_some(), "backend 0 has filters");
        assert!(pbf[1].is_none(), "backend 1 has no filters");
    }

    // ── 11. Mirror: nested depth ok; over-deep → MirrorTooDeep ───────────────

    #[test]
    fn mirror_depth_within_limit_round_trips() {
        let mirror_bg = Arc::new(BackendGroup::new(
            "mirror-svc".to_string(),
            vec![addr("10.9.0.1:80")],
        ));
        let inner_filter = FilterAction::Mirror {
            backend: mirror_bg.clone(),
        };
        let outer_bg = Arc::new(
            BackendGroup::new("outer".to_string(), vec![addr("10.0.0.1:80")])
                .with_per_backend_filters(vec![vec![inner_filter]]),
        );
        let entry = Arc::new(RouteEntry::with_filters(
            outer_bg,
            MatchPredicates::default(),
            vec![FilterAction::Mirror { backend: mirror_bg }],
            RouteTimeouts::default(),
            "mirror-route".to_string(),
            None,
        ));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);
        rt_ingress(b);
    }

    #[test]
    fn mirror_too_deep_returns_error() {
        fn nested_bg(depth: usize) -> p::BackendGroup {
            let addr_dto = p::WeightedBackend {
                addrs: vec!["10.0.0.1:80".to_string()],
                weight: 1,
            };
            let lb = p::LoadBalance {
                algorithm: Some(p::load_balance::Algorithm::RoundRobin(true)),
            };
            if depth == 0 {
                p::BackendGroup {
                    name: "leaf".to_string(),
                    weighted: vec![addr_dto],
                    load_balance: Some(lb),
                    protocol: p::BackendProtocol::Http1 as i32,
                    ..Default::default()
                }
            } else {
                let filter = p::FilterAction {
                    action: Some(p::filter_action::Action::Mirror(nested_bg(depth - 1))),
                };
                p::BackendGroup {
                    name: format!("depth-{depth}"),
                    weighted: vec![addr_dto],
                    load_balance: Some(lb),
                    protocol: p::BackendProtocol::Http1 as i32,
                    per_backend_filters: vec![p::PerBackendFiltersEntry {
                        backend_index: 0,
                        filters: vec![filter],
                    }],
                    ..Default::default()
                }
            }
        }

        let dto = nested_bg(MAX_MIRROR_DEPTH + 1);
        let err = bg_from_wire(&dto, 0).unwrap_err();
        assert!(
            matches!(err, WireError::MirrorTooDeep { .. }),
            "expected MirrorTooDeep, got {err:?}"
        );
    }

    // ── 12. PathModifier variants ─────────────────────────────────────────────

    #[test]
    fn path_modifier_replace_full_round_trips() {
        let filter = FilterAction::UrlRewrite {
            hostname: None,
            path: Some(PathModifier::ReplaceFullPath("/new-path".to_string())),
        };
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(RouteEntry::with_filters(
            bg,
            MatchPredicates::default(),
            vec![filter],
            RouteTimeouts::default(),
            "path-route".to_string(),
            None,
        ));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/old", entry);

        let rt = rt_ingress(b);
        let RouteOutcome::Found(m) = rt.find(80, "example.com", "/old", &ctx()) else {
            panic!("expected Found")
        };
        let FilterAction::UrlRewrite {
            path: Some(PathModifier::ReplaceFullPath(p)),
            ..
        } = &m.filters[0]
        else {
            panic!("expected UrlRewrite with ReplaceFullPath")
        };
        assert_eq!(p, "/new-path");
    }

    #[test]
    fn path_modifier_regex_replace_round_trips() {
        let re = Arc::new(regex::Regex::new(r"^/v(\d+)/").unwrap());
        let filter = FilterAction::UrlRewrite {
            hostname: None,
            path: Some(PathModifier::RegexReplace {
                regex: re,
                replacement: Box::from("/api/v$1/"),
            }),
        };
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(RouteEntry::with_filters(
            bg,
            MatchPredicates::default(),
            vec![filter],
            RouteTimeouts::default(),
            "regex-path-route".to_string(),
            None,
        ));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_regex_route(r"^/v\d+/", entry);

        let rt = rt_ingress(b);
        let RouteOutcome::Found(m) = rt.find(80, "example.com", "/v2/", &ctx()) else {
            panic!("expected Found")
        };
        let FilterAction::UrlRewrite {
            path: Some(PathModifier::RegexReplace { replacement, .. }),
            ..
        } = &m.filters[0]
        else {
            panic!("expected UrlRewrite with RegexReplace")
        };
        assert_eq!(replacement.as_ref(), "/api/v$1/");
    }

    // ── 13. RequestRedirect + error_status ────────────────────────────────────
    //
    // Two sub-cases:
    //   a) Redirect filter round-trips (no error_status → RouteOutcome::Found).
    //   b) error_status: Some(N) causes RouteOutcome::Error(N) — exercises with_error_status.

    #[test]
    fn request_redirect_round_trips() {
        let filter = FilterAction::RequestRedirect {
            scheme: Some("https".to_string()),
            hostname: None,
            port: None,
            status_code: 301,
            path: None,
        };
        let entry = Arc::new(RouteEntry::redirect_only(
            MatchPredicates::default(),
            vec![filter],
            RouteTimeouts::default(),
            "redirect-route".to_string(),
            None,
        ));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/old", entry);

        let rt = rt_ingress(b);
        let RouteOutcome::Found(m) = rt.find(80, "example.com", "/old", &ctx()) else {
            panic!("expected Found")
        };
        let FilterAction::RequestRedirect {
            scheme: Some(s),
            status_code: 301,
            ..
        } = &m.filters[0]
        else {
            panic!("expected RequestRedirect with scheme")
        };
        assert_eq!(s, "https");
    }

    #[test]
    fn error_status_produces_error_outcome() {
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(simple_entry(bg).with_error_status(Some(503)));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/dead", entry);

        let rt = rt_ingress(b);
        // error_status makes find() short-circuit to RouteOutcome::Error, not Found
        assert!(
            matches!(
                rt.find(80, "example.com", "/dead", &ctx()),
                RouteOutcome::Error(503)
            ),
            "error_status: Some(503) must yield RouteOutcome::Error(503)"
        );
    }

    // ── 14. URLRewrite round-trip ─────────────────────────────────────────────

    #[test]
    fn url_rewrite_round_trips() {
        let filter = FilterAction::UrlRewrite {
            hostname: Some("upstream-svc.internal".to_string()),
            path: Some(PathModifier::ReplacePrefixMatch {
                prefix: "/api".to_string(),
                replacement: "/v2/api".to_string(),
            }),
        };
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(RouteEntry::with_filters(
            bg,
            MatchPredicates::default(),
            vec![filter],
            RouteTimeouts::default(),
            "rewrite-route".to_string(),
            None,
        ));

        let mut b = GatewayRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("api.example.com")
            .add_prefix_route("/api", entry);

        let rt = rt_gateway(b);
        let RouteOutcome::Found(m) = rt.find(80, "api.example.com", "/api/users", &ctx()) else {
            panic!("expected Found")
        };
        let FilterAction::UrlRewrite {
            hostname: Some(h),
            path: Some(PathModifier::ReplacePrefixMatch { replacement, .. }),
            ..
        } = &m.filters[0]
        else {
            panic!("expected UrlRewrite with hostname and ReplacePrefixMatch")
        };
        assert_eq!(h, "upstream-svc.internal");
        assert_eq!(replacement, "/v2/api");
    }

    // ── NormalizeLevel per host ───────────────────────────────────────────────

    #[test]
    fn normalize_level_full_round_trips() {
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        let hb = b.for_port(80).exact_host("norm.example.com");
        hb.set_path_normalize(NormalizeLevel::DecodeAndMergeSlashes);
        hb.add_exact_route("/", entry);

        let t = b.build().expect("build");
        let dto = ingress_to_wire(&t);
        let port_entry = dto.ports.first().expect("port");
        let host_entry = port_entry.hosts.first().expect("host");
        assert_ne!(host_entry.normalize_level, 0, "normalize level serialised");

        ingress_from_wire(&dto).expect("from_wire round-trip");
    }

    // ── WildcardKind Single vs Multi ──────────────────────────────────────────

    #[test]
    fn wildcard_single_label_round_trips() {
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .wildcard_host("*.example.com", WildcardKind::SingleLabel)
            .add_exact_route("/", entry);

        let rt = rt_ingress(b);
        assert!(
            rt.route(80, "sub.example.com", "/", &ctx()).is_some(),
            "single-label hit"
        );
        assert!(
            rt.route(80, "a.b.example.com", "/", &ctx()).is_none(),
            "multi-label miss"
        );
    }

    #[test]
    fn wildcard_multi_label_round_trips() {
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .wildcard_host("*.example.com", WildcardKind::MultiLabel)
            .add_exact_route("/", entry);

        let rt = rt_ingress(b);
        assert!(
            rt.route(80, "sub.example.com", "/", &ctx()).is_some(),
            "single-label hit"
        );
        assert!(
            rt.route(80, "a.b.example.com", "/", &ctx()).is_some(),
            "multi-label hit"
        );
    }

    // ── Catchall-only table ───────────────────────────────────────────────────

    #[test]
    fn catchall_only_round_trips() {
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80).catchall().add_exact_route("/", entry);

        let rt = rt_ingress(b);
        assert!(
            rt.route(80, "anything.example.com", "/", &ctx()).is_some(),
            "catchall hit"
        );
        assert!(
            rt.route(80, "other.io", "/", &ctx()).is_some(),
            "other domain hits catchall"
        );
    }

    // ── Hash determinism ─────────────────────────────────────────────────────

    #[test]
    fn to_wire_is_byte_deterministic() {
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80"), addr("10.0.0.2:80")]);
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/api", entry.clone());
        b.for_port(443)
            .exact_host("example.com")
            .add_exact_route("/api", entry);

        let t = b.build().expect("build");
        let dto1 = ingress_to_wire(&t);
        let dto2 = ingress_to_wire(&t);
        assert_eq!(
            dto1.encode_to_vec(),
            dto2.encode_to_vec(),
            "repeated to_wire calls must produce identical bytes"
        );
    }
}
