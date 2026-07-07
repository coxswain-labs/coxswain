//! Protobuf wire DTOs → domain routing tables (decode half of the wire codec).
//!
//! Every `*_from_wire` function replays the builder API to reconstruct a compiled
//! routing type from untrusted proto bytes, enforcing the recursion guard
//! [`super::MAX_MIRROR_DEPTH`]; see the [`super`] module header for the
//! fail-closed contract.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use coxswain_core::routing::{
    BackendClientCert, BackendGroup, BackendProtocol, BasicCredential, CircuitBreakerConfig,
    CompressionConfig, CorsConfig, CorsOrigin, ExtAuthConfig, ExtAuthTransport, FilterAction,
    ForwardedForConfig, GatewayRoutingTable, HashSource, HeaderMod, HeaderPredicate,
    HostRouterBuilder, HttpExtAuthConfig, IngressAuthConfig, IngressRoutingTable, LoadBalance,
    MatchPredicates, MirrorFraction, NormalizeLevel, PasswordHash, PathModifier, QueryPredicate,
    RateLimitConfig, RateLimitKey, RouteEntry, RouteKind, RouteTimeouts, RouterError,
    SessionAffinity, SubjectAltName, TlsPassthroughTable, TlsPassthroughTableBuilder, UpstreamCa,
    UpstreamTls, ValueMatch, WildcardKind,
};

use super::MAX_MIRROR_DEPTH;
use crate::error::WireError;
use crate::proto::v1 as p;

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

    if let Some(enabled) = dto.access_log_enabled {
        entry = entry.with_access_log_enabled(Some(enabled));
    }

    if let Some(rl_dto) = &dto.rate_limit {
        entry = entry.with_rate_limit(Some(Arc::new(rate_limit_from_wire(rl_dto)?)));
    }
    if !dto.auth.is_empty() {
        let chain = dto
            .auth
            .iter()
            .map(|a| auth_from_wire(a).map(Arc::new))
            .collect::<Result<Vec<_>, _>>()?;
        entry = entry.with_auth_chain(Arc::from(chain));
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
    if let Some(ms) = dto.connect_millis {
        bg = bg.with_connect_timeout(Some(Duration::from_millis(ms)));
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

pub(crate) fn upstream_tls_from_wire(dto: &p::UpstreamTls) -> Result<UpstreamTls, WireError> {
    let ca = match dto.ca.as_ref().ok_or(WireError::MissingRequiredField {
        field: "upstream_tls.ca",
    })? {
        p::upstream_tls::Ca::System(_) => UpstreamCa::System,
        p::upstream_tls::Ca::Bundle(pem) => UpstreamCa::Bundle(Arc::from(pem.clone())),
    };
    let mut tls = UpstreamTls::new(Arc::from(dto.sni.as_str()), ca, dto.group_key);
    // An empty source means no client cert; cert/key bytes are only meaningful when
    // a source is present. Set the field directly to preserve the wire `group_key`
    // (`with_client_cert` would re-mix the identity and diverge from the sender).
    if !dto.client_cert_source.is_empty() {
        tls.client_cert = Some(Arc::new(BackendClientCert::new(
            Arc::from(dto.client_cert_pem.as_slice()),
            Arc::from(dto.client_cert_key.as_slice()),
            Arc::from(dto.client_cert_source.as_str()),
        )));
    }
    // Deserialise SANs with direct field assignment — not with_subject_alt_names() —
    // so the wire group_key is preserved verbatim (the builder re-folds the hash and
    // diverges from the sender's pool key, breaking connection-pool isolation).
    if !dto.subject_alt_names.is_empty() {
        // Drop unknown SAN kinds gracefully — consistent with to_wire's _ => None.
        // This prevents a future proto Kind from being coerced to the default (Hostname=0)
        // and producing a spurious SAN mismatch / silent auth downgrade on rolling upgrades.
        // Drop unknown SAN kinds gracefully — consistent with to_wire's _ => None.
        // This prevents a future proto Kind from being coerced to the default (Hostname=0)
        // and producing a spurious SAN mismatch on rolling upgrades.
        let sans: Arc<[SubjectAltName]> = dto
            .subject_alt_names
            .iter()
            .filter_map(|san| {
                let kind = p::subject_alt_name::Kind::try_from(san.kind).ok()?;
                Some(match kind {
                    p::subject_alt_name::Kind::Hostname => {
                        SubjectAltName::Hostname(Arc::from(san.value.as_str()))
                    }
                    p::subject_alt_name::Kind::Uri => {
                        SubjectAltName::Uri(Arc::from(san.value.as_str()))
                    }
                })
            })
            .collect();
        if sans.is_empty() {
            // All SAN entries had unrecognised kinds (e.g. a future proto variant
            // sent by a newer controller). Fail closed: silently skipping the SAN
            // check would downgrade auth to hostname-only, which is incorrect.
            let bad_kind = dto.subject_alt_names.first().map_or(-1, |s| s.kind);
            return Err(WireError::InvalidEnumValue {
                value: bad_kind,
                field: "UpstreamTls.subject_alt_names[*].kind",
            });
        }
        tls.subject_alt_names = sans;
    }
    Ok(tls)
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
        p::filter_action::Action::Mirror(mirror_dto) => {
            let bg_dto = mirror_dto
                .backend
                .as_ref()
                .ok_or(WireError::MissingRequiredField {
                    field: "MirrorFilter.backend",
                })?;
            let backend = Arc::new(bg_from_wire(bg_dto, depth + 1)?);
            let fraction = mirror_dto
                .fraction
                .as_ref()
                .and_then(|f| MirrorFraction::new(f.numerator, f.denominator));
            Ok(FilterAction::Mirror { backend, fraction })
        }
        p::filter_action::Action::Cors(cors_dto) => Ok(FilterAction::Cors(Arc::new(
            cors_config_from_wire(cors_dto)?,
        ))),
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

fn cors_config_from_wire(dto: &p::CorsFilter) -> Result<CorsConfig, WireError> {
    use http::HeaderValue;

    let mut allow_origins: Vec<CorsOrigin> = Vec::with_capacity(dto.allow_origins.len());
    for origin in &dto.allow_origins {
        if let Some(star_pos) = origin.find('*') {
            let prefix = origin[..star_pos].to_ascii_lowercase().into_boxed_str();
            let suffix = origin[star_pos + 1..].to_ascii_lowercase().into_boxed_str();
            allow_origins.push(CorsOrigin::Wildcard { prefix, suffix });
        } else {
            allow_origins.push(CorsOrigin::Exact(origin.to_ascii_lowercase()));
        }
    }

    let parse_header_opt = |s: &Option<String>| -> Result<Option<HeaderValue>, WireError> {
        let Some(val) = s.as_deref() else {
            return Ok(None);
        };
        if val.is_empty() {
            return Ok(None);
        }
        HeaderValue::from_str(val)
            .map(Some)
            .map_err(WireError::InvalidHeaderValue)
    };

    let max_age = HeaderValue::from(dto.max_age);

    Ok(CorsConfig::new(
        allow_origins,
        dto.allow_all_origins,
        dto.allow_credentials,
        parse_header_opt(&dto.allow_methods)?,
        parse_header_opt(&dto.allow_headers)?,
        parse_header_opt(&dto.expose_headers)?,
        max_age,
    ))
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
            let endpoints: Arc<[SocketAddr]> = ext
                .endpoints
                .iter()
                .map(|s| s.parse::<SocketAddr>().map_err(WireError::InvalidAddr))
                .collect::<Result<Vec<_>, _>>()?
                .into();
            Ok(IngressAuthConfig::External(ExtAuthConfig::new(
                ext.timeout
                    .as_ref()
                    .map(duration_from_wire)
                    .unwrap_or_default(),
                endpoints,
                ext.fail_closed,
                ExtAuthTransport::Http(HttpExtAuthConfig::new(
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
        p::NormalizeLevel::MergeSlashes => Ok(NormalizeLevel::MergeSlashes),
        p::NormalizeLevel::DecodeAndMergeSlashes => Ok(NormalizeLevel::DecodeAndMergeSlashes),
    }
}

fn protocol_from_wire(v: i32) -> Result<BackendProtocol, WireError> {
    match p::BackendProtocol::try_from(v).unwrap_or(p::BackendProtocol::Unspecified) {
        p::BackendProtocol::Unspecified | p::BackendProtocol::Http1 => Ok(BackendProtocol::Http1),
        p::BackendProtocol::H2c => Ok(BackendProtocol::H2c),
        p::BackendProtocol::WebSocket => Ok(BackendProtocol::WebSocket),
    }
}

/// Decode a [`TlsPassthroughTable`] from a protobuf DTO.
///
/// # Errors
///
/// Returns [`WireError`] if any backend group fails to decode (bad address,
/// missing required field, etc.).
#[must_use = "the rebuilt passthrough table must be stored for the proxy to use it"]
pub fn passthrough_from_wire(
    dto: &p::TlsPassthroughTable,
) -> Result<TlsPassthroughTable, WireError> {
    let mut builder = TlsPassthroughTableBuilder::new();
    for port_entry in &dto.ports {
        let port = port_entry.port as u16;
        for entry in &port_entry.entries {
            let bg = match &entry.backend_group {
                Some(bg) => Arc::new(bg_from_wire(bg, 0)?),
                None => continue,
            };
            let pattern = match &entry.pattern {
                Some(p::tls_passthrough_entry::Pattern::Exact(s)) => s.clone(),
                Some(p::tls_passthrough_entry::Pattern::WildcardSuffix(s)) => {
                    format!("*.{s}")
                }
                Some(p::tls_passthrough_entry::Pattern::Catchall(_)) => String::new(),
                None => continue,
            };
            builder = builder.add_route(port, &pattern, bg);
        }
    }
    Ok(builder.build())
}
