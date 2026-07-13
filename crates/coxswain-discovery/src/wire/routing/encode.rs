//! Domain routing tables → protobuf wire DTOs (encode half of the wire codec).
//!
//! Every `*_to_wire` function serialises a compiled routing type into its proto3
//! message in deterministic canonical order; see the [`super`] module header for
//! the full determinism and ordering contract.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use coxswain_core::endpoints::{EndpointKey, ResolvedEndpoints};
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
// Endpoint collector (#383)
// ────────────────────────────────────────────────────────────────────────────

/// Accumulates the EDS-style endpoint resources referenced while encoding a
/// scope's routing tables (#383).
///
/// Every keyed [`BackendGroup`] backend emits an `endpoint_ref` on the wire and
/// records its `(EndpointKey → ResolvedEndpoints)` here. First occurrence wins:
/// if two routes reference the same `(namespace, service, port)` with transiently
/// disagreeing resolutions (a rebuild caught mid-flight), the first-encoded value
/// is authoritative for this snapshot — the next rebuild re-materialises both
/// consistently. The collector emits exactly one [`p::EndpointResource`] per key.
pub(crate) struct EndpointCollector {
    map: HashMap<EndpointKey, Arc<ResolvedEndpoints>>,
}

impl EndpointCollector {
    /// Create an empty collector.
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Record a referenced endpoint resource, first-occurrence-wins.
    fn record(&mut self, key: &EndpointKey, resolved: &Arc<ResolvedEndpoints>) {
        self.map
            .entry(key.clone())
            .or_insert_with(|| Arc::clone(resolved));
    }

    /// Emit one [`p::Resource`] per referenced endpoint key.
    ///
    /// Addresses are stringified and sorted for hash determinism. The caller
    /// folds these into the materialized view alongside the route/TLS/L4
    /// resources; ordering here is irrelevant (the view re-keys by canonical key).
    pub(crate) fn into_resources(self) -> Vec<p::Resource> {
        self.map
            .into_iter()
            .map(|(key, resolved)| {
                let mut addrs: Vec<String> = resolved.addrs.iter().map(|a| a.to_string()).collect();
                addrs.sort_unstable();
                p::Resource {
                    payload: Some(p::resource::Payload::Endpoints(p::EndpointResource {
                        namespace: key.namespace.to_string(),
                        service: key.service.to_string(),
                        port: u32::from(key.port),
                        app_protocol: protocol_to_wire(resolved.app_protocol) as i32,
                        service_exists: resolved.service_exists,
                        addrs,
                    })),
                    ..Default::default()
                }
            })
            .collect()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Routing table: per-resource emitters (#383)
// ────────────────────────────────────────────────────────────────────────────

/// Emit one [`p::Resource::RouteHost`] per `(table, port, host)` bucket of an
/// [`IngressRoutingTable`], recording referenced endpoints into `endpoints`.
#[must_use = "route-host resources must be folded into the materialized view"]
pub(crate) fn ingress_route_resources(
    t: &IngressRoutingTable,
    endpoints: &mut EndpointCollector,
) -> Vec<p::Resource> {
    route_resources(t, p::RouteTableKind::Ingress, endpoints)
}

/// Emit one [`p::Resource::RouteHost`] per `(table, port, host)` bucket of a
/// [`GatewayRoutingTable`], recording referenced endpoints into `endpoints`.
#[must_use = "route-host resources must be folded into the materialized view"]
pub(crate) fn gateway_route_resources(
    t: &GatewayRoutingTable,
    endpoints: &mut EndpointCollector,
) -> Vec<p::Resource> {
    route_resources(t, p::RouteTableKind::Gateway, endpoints)
}

fn route_resources<Kind>(
    t: &coxswain_core::routing::RoutingTable<Kind>,
    table: p::RouteTableKind,
    endpoints: &mut EndpointCollector,
) -> Vec<p::Resource> {
    let mut ports: Vec<(u16, &PortRoutingTable)> = t.ports().collect();
    ports.sort_by_key(|(p, _)| *p);

    let mut out = Vec::new();
    for (port, pt) in ports {
        for host in port_host_entries(pt, endpoints) {
            out.push(p::Resource {
                payload: Some(p::resource::Payload::RouteHost(p::RouteHostResource {
                    table: table as i32,
                    port: u32::from(port),
                    host: Some(host),
                })),
                ..Default::default()
            });
        }
    }
    out
}

/// Serialise every host bucket of one port in canonical order (exact sorted,
/// wildcard sorted by suffix, catchall last), reusing [`host_entry_to_wire`].
fn port_host_entries(
    pt: &PortRoutingTable,
    endpoints: &mut EndpointCollector,
) -> Vec<p::HostEntry> {
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
            endpoints,
        ));
    }
    for (suffix, kind, router) in wildcard_entries {
        hosts.push(host_entry_to_wire(
            p::host_entry::Pattern::Wildcard(p::WildcardHost {
                suffix: suffix.to_string(),
                kind: wildcard_kind_to_wire(kind) as i32,
            }),
            router,
            endpoints,
        ));
    }
    if let Some(router) = catchall_entry {
        hosts.push(host_entry_to_wire(
            p::host_entry::Pattern::Catchall(true),
            router,
            endpoints,
        ));
    }
    hosts
}

fn host_entry_to_wire(
    pattern: p::host_entry::Pattern,
    router: &HostRouter,
    endpoints: &mut EndpointCollector,
) -> p::HostEntry {
    let routes: Vec<p::RouteEntry> = router
        .wire_entries()
        .map(|(path, kind, entry)| route_entry_to_wire(path, kind, entry, endpoints))
        .collect();

    p::HostEntry {
        pattern: Some(pattern),
        normalize_level: normalize_level_to_wire(router.normalize()) as i32,
        routes,
    }
}

fn route_entry_to_wire(
    path: &str,
    kind: RouteKind,
    e: &RouteEntry,
    endpoints: &mut EndpointCollector,
) -> p::RouteEntry {
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

    // #383 provenance split: endpoint-derived statuses (503 valid-but-empty /
    // 500 missing-Service) are omitted from the wire — the client re-derives them
    // from its endpoint pool, so endpoint drain never rewrites this route's hash.
    // Endpoint-independent statuses (e.g. a 502 fail-closed) stay baked.
    let error_status = if e.error_status_endpoint_derived {
        None
    } else {
        e.error_status.map(u32::from)
    };

    p::RouteEntry {
        kind: route_kind_to_wire(kind) as i32,
        path: path.to_string(),
        backend_group: Some(backend_group_to_wire(&e.backend_group, 0, endpoints)),
        predicates: Some(predicates_to_wire(&e.predicates)),
        filters: e
            .filters
            .iter()
            .map(|f| filter_to_wire(f, 0, endpoints))
            .collect(),
        timeouts: Some(timeouts_to_wire(&e.timeouts)),
        route_id: e.route_id.clone(),
        metric_route_id: e.metric_route_id.to_string(),
        path_pattern: e.path_pattern.to_string(),
        created_at_unix_millis: e.created_at.and_then(|t| {
            t.duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as u64)
        }),
        error_status,
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

fn backend_group_to_wire(
    bg: &BackendGroup,
    depth: usize,
    endpoints: &mut EndpointCollector,
) -> p::BackendGroup {
    let spec = bg.spec();
    let weighted: Vec<p::WeightedBackend> = spec
        .weighted
        .iter()
        .map(|wb| match &wb.key {
            // #383 keyed ref: emit an `endpoint_ref` (no addrs) and record the
            // referenced resource so the server ships it in the same message.
            // Endpoint drain therefore rewrites only the endpoint resource, never
            // this route's bytes. Retained even when addrs is empty — a
            // scaled-to-zero Service still needs its ref on the wire.
            Some(key) => {
                endpoints.record(key, &wb.resolved);
                p::WeightedBackend {
                    addrs: Vec::new(),
                    weight: u32::from(wb.weight),
                    endpoint_ref: Some(p::EndpointRef {
                        namespace: key.namespace.to_string(),
                        service: key.service.to_string(),
                        port: u32::from(key.port),
                    }),
                }
            }
            // Literal ref (pre-#383 constructors): inline the sorted addresses.
            None => {
                let mut addr_strs: Vec<String> =
                    wb.resolved.addrs.iter().map(|a| a.to_string()).collect();
                addr_strs.sort_unstable();
                p::WeightedBackend {
                    addrs: addr_strs,
                    weight: u32::from(wb.weight),
                    endpoint_ref: None,
                }
            }
        })
        .collect();

    // Map pool position → spec position. `per_backend_filters()` is pool-aligned
    // (one slot per address-bearing backend that entered the hot-path pools), but
    // the wire contract keys each entry by its index in `weighted` — the
    // SPEC-aligned list, which retains keyed-empty (drained) refs the pools drop.
    // The i-th pool backend is the i-th spec entry that resolved at least one
    // address (spec entries already carry `weight > 0`), mirroring `from_pools`'s
    // pool construction and the decoder's `surviving` filter. Emitting the pool
    // index verbatim would misalign every filter past a keyed-empty ref.
    let pool_to_spec: Vec<u32> = spec
        .weighted
        .iter()
        .enumerate()
        .filter(|(_, wb)| !wb.resolved.addrs.is_empty())
        .map(|(spec_idx, _)| spec_idx as u32)
        .collect();

    // Per-backend filters: emit only slots with non-empty filters, keyed by the
    // backend's SPEC index (index-aligned with `weighted`).
    let per_backend_filters: Vec<p::PerBackendFiltersEntry> = bg
        .per_backend_filters()
        .unwrap_or(&[])
        .iter()
        .enumerate()
        .filter_map(|(i, slot)| {
            slot.as_ref().map(|filters| p::PerBackendFiltersEntry {
                backend_index: pool_to_spec.get(i).copied().unwrap_or(i as u32),
                filters: filters
                    .iter()
                    .map(|f| filter_to_wire(f, depth, endpoints))
                    .collect(),
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

fn filter_to_wire(
    f: &FilterAction,
    depth: usize,
    endpoints: &mut EndpointCollector,
) -> p::FilterAction {
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
                backend: Some(backend_group_to_wire(
                    backend,
                    depth.saturating_add(1),
                    endpoints,
                )),
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

/// Serialise one port of a [`TlsPassthroughTable`] into a [`p::TlsPassthroughPort`].
///
/// Within the port, exact entries come first (sorted), then wildcard entries
/// (sorted by suffix), then the catch-all if present.
fn passthrough_port_to_wire(
    port: u16,
    router: &coxswain_core::routing::SniRouter,
    endpoints: &mut EndpointCollector,
) -> p::TlsPassthroughPort {
    let mut exact_entries: Vec<(&str, &Arc<BackendGroup>)> = router.exact_iter().collect();
    exact_entries.sort_by_key(|(sni, _)| *sni);

    let mut wildcard_entries: Vec<(&str, &Arc<BackendGroup>)> = router.wildcard_iter().collect();
    wildcard_entries.sort_by_key(|(suffix, _)| *suffix);

    let mut entries: Vec<p::TlsPassthroughEntry> = Vec::new();
    for (sni, bg) in exact_entries {
        entries.push(p::TlsPassthroughEntry {
            pattern: Some(p::tls_passthrough_entry::Pattern::Exact(sni.to_string())),
            backend_group: Some(backend_group_to_wire(bg, 0, endpoints)),
        });
    }
    for (suffix, bg) in wildcard_entries {
        entries.push(p::TlsPassthroughEntry {
            pattern: Some(p::tls_passthrough_entry::Pattern::WildcardSuffix(
                suffix.to_string(),
            )),
            backend_group: Some(backend_group_to_wire(bg, 0, endpoints)),
        });
    }
    if let Some(bg) = router.catchall() {
        entries.push(p::TlsPassthroughEntry {
            pattern: Some(p::tls_passthrough_entry::Pattern::Catchall(true)),
            backend_group: Some(backend_group_to_wire(bg, 0, endpoints)),
        });
    }

    p::TlsPassthroughPort {
        port: u32::from(port),
        entries,
    }
}

/// Emit one [`p::Resource`] per port of a [`TlsPassthroughTable`].
///
/// `terminate` selects the [`p::resource::Payload::TlsTerminatePort`] arm (#481)
/// vs the [`p::resource::Payload::TlsPassthroughPort`] arm (#70); the two tables
/// share this message shape but stay distinct resources on the wire.
#[must_use = "passthrough resources must be folded into the materialized view"]
pub(crate) fn passthrough_resources(
    t: &TlsPassthroughTable,
    terminate: bool,
    endpoints: &mut EndpointCollector,
) -> Vec<p::Resource> {
    t.ports_iter()
        .map(|(port, router)| {
            let dto = passthrough_port_to_wire(port, router, endpoints);
            let payload = if terminate {
                p::resource::Payload::TlsTerminatePort(dto)
            } else {
                p::resource::Payload::TlsPassthroughPort(dto)
            };
            p::Resource {
                payload: Some(payload),
                ..Default::default()
            }
        })
        .collect()
}

/// Emit one [`p::Resource::TcpPort`] per port of a [`TcpRouteTable`] (#505).
#[must_use = "tcp resources must be folded into the materialized view"]
pub(crate) fn tcp_resources(
    t: &TcpRouteTable,
    endpoints: &mut EndpointCollector,
) -> Vec<p::Resource> {
    t.ports_iter()
        .map(|(port, bg)| p::Resource {
            payload: Some(p::resource::Payload::TcpPort(p::TcpRoutePort {
                port: u32::from(port),
                backend_group: Some(backend_group_to_wire(bg, 0, endpoints)),
            })),
            ..Default::default()
        })
        .collect()
}

/// Emit one [`p::Resource::UdpPort`] per port of a [`UdpRouteTable`] (#506).
#[must_use = "udp resources must be folded into the materialized view"]
pub(crate) fn udp_resources(
    t: &UdpRouteTable,
    endpoints: &mut EndpointCollector,
) -> Vec<p::Resource> {
    t.ports_iter()
        .map(|(port, bg)| p::Resource {
            payload: Some(p::resource::Payload::UdpPort(p::UdpRoutePort {
                port: u32::from(port),
                backend_group: Some(backend_group_to_wire(bg, 0, endpoints)),
            })),
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::endpoints::{EndpointKey, ResolvedEndpoints};
    use std::net::SocketAddr;

    fn resolved(addrs: &[&str]) -> Arc<ResolvedEndpoints> {
        let parsed: Vec<SocketAddr> = addrs
            .iter()
            .map(|a| a.parse().expect("valid addr"))
            .collect();
        let exists = !parsed.is_empty();
        Arc::new(ResolvedEndpoints::new(
            parsed,
            BackendProtocol::default(),
            exists,
        ))
    }

    /// #383 resource-oriented wire: a keyed backend emits an `endpoint_ref` (no
    /// inline addrs) and records the endpoint resource in the collector, so
    /// endpoint churn re-sends only the endpoint resource. A keyed-empty ref (a
    /// Service scaled to zero, `service_exists = true`) still emits its ref and
    /// records a zero-addr EndpointResource — the meaningful-503 signal.
    #[test]
    fn keyed_backend_emits_ref_and_records_endpoint() {
        let addr_bearing = resolved(&["10.0.0.1:80"]);
        let addr_key = EndpointKey::new("default", "svc-a", 80);
        // Present-but-empty Service: service_exists=true, zero addrs.
        let drained = Arc::new(ResolvedEndpoints::new(
            Vec::new(),
            BackendProtocol::default(),
            true,
        ));
        let drained_key = EndpointKey::new("default", "svc-b", 80);

        let bg = BackendGroup::weighted_with_endpoints(
            "default/svc".to_string(),
            vec![
                (addr_bearing, Some(addr_key), 1),
                (drained, Some(drained_key), 1),
            ],
        );

        let mut coll = EndpointCollector::new();
        let dto = backend_group_to_wire(&bg, 0, &mut coll);

        // Both backends emit an endpoint_ref and NO inline addrs.
        assert_eq!(dto.weighted.len(), 2, "both keyed refs ride the wire");
        for wb in &dto.weighted {
            assert!(wb.endpoint_ref.is_some(), "keyed backend emits a ref");
            assert!(wb.addrs.is_empty(), "keyed backend inlines no addrs");
        }

        // Two endpoint resources recorded, one of them zero-addr + service_exists.
        let resources = coll.into_resources();
        assert_eq!(resources.len(), 2, "one EndpointResource per keyed ref");
        let drained_res = resources
            .iter()
            .find_map(|r| match r.payload.as_ref() {
                Some(p::resource::Payload::Endpoints(e)) if e.service == "svc-b" => Some(e),
                _ => None,
            })
            .expect("drained endpoint resource emitted");
        assert!(drained_res.addrs.is_empty(), "scaled-to-zero has no addrs");
        assert!(
            drained_res.service_exists,
            "a present-but-empty Service keeps service_exists (drives client 503)"
        );
    }

    /// A literal-address backend (pre-#383 constructor, `key: None`) inlines its
    /// sorted addresses and emits no ref, recording no endpoint resource.
    #[test]
    fn literal_backend_emits_addrs_no_ref() {
        let bg = BackendGroup::new("ns/svc".to_string(), vec!["10.0.0.2:80".parse().unwrap()]);
        let mut coll = EndpointCollector::new();
        let dto = backend_group_to_wire(&bg, 0, &mut coll);
        assert_eq!(dto.weighted.len(), 1);
        assert!(dto.weighted[0].endpoint_ref.is_none(), "literal → no ref");
        assert_eq!(dto.weighted[0].addrs, vec!["10.0.0.2:80".to_string()]);
        assert!(
            coll.into_resources().is_empty(),
            "literal backends reference no endpoint resource"
        );
    }
}
