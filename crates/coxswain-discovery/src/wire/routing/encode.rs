//! Domain routing tables → protobuf wire DTOs (encode half of the wire codec).
//!
//! Every `*_to_wire` function serialises a compiled routing type into its proto3
//! message in deterministic canonical order; see the [`super`] module header for
//! the full determinism and ordering contract.

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use coxswain_core::routing::{
    BackendGroup, BackendProtocol, CircuitBreakerConfig, CompressionConfig, CorsConfig, CorsOrigin,
    ExtAuthTransport, FilterAction, ForwardedForConfig, GatewayRoutingTable, HashSource, HeaderMod,
    HostPattern, HostRouter, IngressAuthConfig, IngressRoutingTable, LoadBalance, MatchPredicates,
    NormalizeLevel, PasswordHash, PathModifier, PortRoutingTable, RateLimitConfig, RateLimitKey,
    RouteEntry, RouteKind, RouteTimeouts, SessionAffinity, SubjectAltName, TcpRouteTable,
    TlsPassthroughTable, UdpRouteTable, UpstreamCa, UpstreamTls, ValueMatch, WildcardKind,
};

use crate::proto::v1 as p;

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
        access_log_enabled: e.access_log_enabled,
        rate_limit: e.rate_limit.as_deref().map(rate_limit_to_wire),
        auth: e.auth.iter().map(|a| auth_to_wire(a)).collect(),
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
    let connect_millis = bg.connect_timeout().map(|d| d.as_millis() as u64);

    p::BackendGroup {
        name: bg.name().to_string(),
        weighted,
        protocol: protocol_to_wire(bg.protocol()) as i32,
        tls: bg.upstream_tls().map(|t| upstream_tls_to_wire(t)),
        retry: Some(retry_to_wire(bg.retry_policy())),
        keepalive_millis,
        connect_millis,
        per_backend_filters,
        load_balance: Some(load_balance_to_wire(bg.load_balance())),
        session_affinity: bg.session_affinity().map(session_affinity_to_wire),
    }
}

pub(crate) fn upstream_tls_to_wire(tls: &UpstreamTls) -> p::UpstreamTls {
    let ca = match &tls.ca {
        UpstreamCa::System => p::upstream_tls::Ca::System(true),
        UpstreamCa::Bundle(pem) => p::upstream_tls::Ca::Bundle(pem.to_vec()),
        _ => unreachable!(
            "invariant: all UpstreamCa variants handled; update wire.rs when adding new variants"
        ),
    };
    let (client_cert_pem, client_cert_key, client_cert_source) = match tls.client_cert() {
        Some(cc) => (
            cc.cert_pem.to_vec(),
            cc.key_pem.to_vec(),
            cc.source.to_string(),
        ),
        None => (Vec::new(), Vec::new(), String::new()),
    };
    let subject_alt_names = tls
        .subject_alt_names()
        .iter()
        .filter_map(|san| match san {
            SubjectAltName::Hostname(h) => Some(p::SubjectAltName {
                kind: p::subject_alt_name::Kind::Hostname.into(),
                value: h.to_string(),
            }),
            SubjectAltName::Uri(u) => Some(p::SubjectAltName {
                kind: p::subject_alt_name::Kind::Uri.into(),
                value: u.to_string(),
            }),
            // Forward-compatible: unknown variants added in future releases are dropped
            // (they were added after this binary was compiled; a rolling upgrade is safe
            // because the SAN set must contain at least one recognisable entry to enforce
            // — an empty residual is caught by from_wire's fail-closed path).
            _ => None,
        })
        .collect();
    p::UpstreamTls {
        sni: tls.sni.to_string(),
        ca: Some(ca),
        group_key: tls.group_key,
        client_cert_pem,
        client_cert_key,
        client_cert_source,
        subject_alt_names,
    }
}

fn retry_to_wire(retry: &coxswain_core::routing::RetryPolicyConfig) -> p::RetryPolicy {
    p::RetryPolicy {
        attempts: retry.attempts,
        // Duration millis are bounded by realistic backoff config; the cast is lossless
        // for any sane value and saturates rather than wrapping on an absurd one.
        backoff_ms: retry
            .backoff
            .map_or(0, |d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)),
        http_codes: retry.http_codes.iter().map(|&c| u32::from(c)).collect(),
        grpc_codes: retry.grpc_codes.iter().map(|&c| u32::from(c)).collect(),
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
        FilterAction::Mirror { backend, fraction } => {
            // Saturate depth rather than panic — depth > MAX_MIRROR_DEPTH is
            // only reachable if the runtime type was built with malformed data
            // (defensive guard; from_wire is the primary enforcement site).
            p::filter_action::Action::Mirror(p::MirrorFilter {
                backend: Some(backend_group_to_wire(backend, depth.saturating_add(1))),
                fraction: fraction.map(|f| {
                    let (numerator, denominator) = f.as_parts();
                    p::MirrorFractionProto {
                        numerator,
                        denominator,
                    }
                }),
            })
        }
        FilterAction::Cors(cfg) => p::filter_action::Action::Cors(cors_config_to_wire(cfg)),
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
            // Exactly one of `http`/`grpc` is set per the resolved transport. A
            // future `#[non_exhaustive]` transport encodes as neither: the decoder
            // then fails that auth entry closed (Unavailable) rather than the
            // encoder panicking and taking down the whole routing stream.
            let (http, grpc) = match &ext.transport {
                ExtAuthTransport::Http(h) => (
                    Some(p::HttpExtAuthConfig {
                        response_headers: h
                            .response_headers
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        always_set_cookie: h.always_set_cookie,
                    }),
                    None,
                ),
                ExtAuthTransport::Grpc(g) => (
                    None,
                    Some(p::GrpcExtAuthConfig {
                        response_headers: g
                            .response_headers
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                    }),
                ),
                _ => (None, None),
            };
            p::ingress_auth_config::Auth::External(p::ExtAuthConfig {
                timeout: Some(duration_to_wire(ext.timeout)),
                endpoints: ext.endpoints.iter().map(|a| a.to_string()).collect(),
                fail_closed: ext.fail_closed,
                http,
                grpc,
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
        IngressAuthConfig::Jwt(jwt) => p::ingress_auth_config::Auth::Jwt(p::JwtAuthConfig {
            issuer: jwt.issuer.to_string(),
            audiences: jwt.audiences.iter().map(|s| s.to_string()).collect(),
            jwks: jwt.jwks.to_string(),
            from_headers: jwt
                .from_headers
                .iter()
                .map(|h| p::JwtHeaderLocation {
                    name: h.name.to_string(),
                    value_prefix: h.value_prefix.to_string(),
                })
                .collect(),
            forward_payload_header: jwt.forward_payload_header.as_ref().map(|s| s.to_string()),
            claim_to_headers: jwt
                .claim_to_headers
                .iter()
                .map(|(claim, header)| p::ClaimToHeader {
                    claim: claim.to_string(),
                    header: header.to_string(),
                })
                .collect(),
            forward_token: jwt.forward_token,
        }),
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
        _ => unreachable!(
            "invariant: all BackendProtocol variants handled; update wire.rs when adding new variants"
        ),
    }
}

fn cors_config_to_wire(cfg: &CorsConfig) -> p::CorsFilter {
    // Reconstruct origin strings from parsed CorsOrigin variants.
    let allow_origins: Vec<String> = cfg
        .allow_origins
        .iter()
        .map(|o| match o {
            CorsOrigin::Exact(s) => s.clone(),
            CorsOrigin::Wildcard { prefix, suffix } => format!("{}*{}", prefix, suffix),
            _ => unreachable!(
                "invariant: all CorsOrigin variants handled; update wire.rs when adding new variants"
            ),
        })
        .collect();
    // Pre-joined header values are sent as-is (the proxy re-parses into HeaderValue).
    let header_str = |hv: &Option<http::HeaderValue>| -> Option<String> {
        hv.as_ref()
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    p::CorsFilter {
        allow_origins,
        allow_all_origins: cfg.allow_all_origins,
        allow_credentials: cfg.allow_credentials,
        allow_methods: header_str(&cfg.allow_methods),
        allow_headers: header_str(&cfg.allow_headers),
        expose_headers: header_str(&cfg.expose_headers),
        max_age: cfg.max_age.to_str().unwrap_or("5").parse().unwrap_or(5),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TLS passthrough table
// ────────────────────────────────────────────────────────────────────────────

/// Encode a [`TlsPassthroughTable`] as a protobuf DTO.
///
/// Ports are emitted in ascending order for content-hash stability.
/// Within each port, exact entries come first (sorted), then wildcard entries
/// (sorted by suffix), then the catch-all if present.
#[must_use = "wire DTO must be embedded in a Snapshot to reach the proxy"]
pub fn passthrough_to_wire(t: &TlsPassthroughTable) -> p::TlsPassthroughTable {
    let mut ports: Vec<p::TlsPassthroughPort> = t
        .ports_iter()
        .map(|(port, router)| {
            let mut exact_entries: Vec<(&str, &Arc<BackendGroup>)> = router.exact_iter().collect();
            exact_entries.sort_by_key(|(sni, _)| *sni);

            let mut wildcard_entries: Vec<(&str, &Arc<BackendGroup>)> =
                router.wildcard_iter().collect();
            wildcard_entries.sort_by_key(|(suffix, _)| *suffix);

            let mut entries: Vec<p::TlsPassthroughEntry> = Vec::new();

            for (sni, bg) in exact_entries {
                entries.push(p::TlsPassthroughEntry {
                    pattern: Some(p::tls_passthrough_entry::Pattern::Exact(sni.to_string())),
                    backend_group: Some(backend_group_to_wire(bg, 0)),
                });
            }
            for (suffix, bg) in wildcard_entries {
                entries.push(p::TlsPassthroughEntry {
                    pattern: Some(p::tls_passthrough_entry::Pattern::WildcardSuffix(
                        suffix.to_string(),
                    )),
                    backend_group: Some(backend_group_to_wire(bg, 0)),
                });
            }
            if let Some(bg) = router.catchall() {
                entries.push(p::TlsPassthroughEntry {
                    pattern: Some(p::tls_passthrough_entry::Pattern::Catchall(true)),
                    backend_group: Some(backend_group_to_wire(bg, 0)),
                });
            }

            p::TlsPassthroughPort {
                port: u32::from(port),
                entries,
            }
        })
        .collect();
    ports.sort_by_key(|e| e.port);
    p::TlsPassthroughTable { ports }
}

// ────────────────────────────────────────────────────────────────────────────
// TCP route table (#505)
// ────────────────────────────────────────────────────────────────────────────

/// Encode a [`TcpRouteTable`] as a protobuf DTO.
///
/// Ports are emitted in ascending order for content-hash stability. No SNI
/// dimension — each port carries exactly one backend group.
#[must_use = "wire DTO must be embedded in a Snapshot to reach the proxy"]
pub fn tcp_table_to_wire(t: &TcpRouteTable) -> p::TcpRouteTable {
    let mut ports: Vec<p::TcpRoutePort> = t
        .ports_iter()
        .map(|(port, bg)| p::TcpRoutePort {
            port: u32::from(port),
            backend_group: Some(backend_group_to_wire(bg, 0)),
        })
        .collect();
    ports.sort_by_key(|e| e.port);
    p::TcpRouteTable { ports }
}

/// Serialise a [`UdpRouteTable`] to its wire DTO (UDPRoute, GEP-2645, #506).
///
/// Same shape as [`tcp_table_to_wire`] — port-keyed, no SNI dimension.
#[must_use = "wire DTO must be embedded in a Snapshot to reach the proxy"]
pub fn udp_table_to_wire(t: &UdpRouteTable) -> p::UdpRouteTable {
    let mut ports: Vec<p::UdpRoutePort> = t
        .ports_iter()
        .map(|(port, bg)| p::UdpRoutePort {
            port: u32::from(port),
            backend_group: Some(backend_group_to_wire(bg, 0)),
        })
        .collect();
    ports.sort_by_key(|e| e.port);
    p::UdpRouteTable { ports }
}
