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

use coxswain_core::endpoints::{EndpointPool, empty_group_status};
use coxswain_core::routing::{
    BackendClientCert, BackendGroup, BackendProtocol, BasicCredential, CircuitBreakerConfig,
    CompressionConfig, CorsConfig, CorsOrigin, ExtAuthConfig, ExtAuthTransport, FilterAction,
    ForwardedForConfig, GrpcExtAuthConfig, HashSource, HeaderMod, HeaderPredicate,
    HostRouterBuilder, HttpExtAuthConfig, IngressAuthConfig, JwtConfig, JwtHeaderLoc, LoadBalance,
    MatchPredicates, MirrorFraction, NormalizeLevel, PasswordHash, PathModifier, QueryPredicate,
    RateLimitConfig, RateLimitKey, RouteEntry, RouteKind, RouteTimeouts, RouterError,
    SessionAffinity, SubjectAltName, TcpRouteTable, TcpRouteTableBuilder, TlsPassthroughTable,
    TlsPassthroughTableBuilder, UdpRouteTable, UdpRouteTableBuilder, UpstreamCa, UpstreamTls,
    ValueMatch, WildcardKind,
};
// Whole-table route types + the pool-from-resources helper are used only by the
// test-only `decode_world` route oracle (production decode is partition-wise via
// `build_route_table`, cell-wise via the L4 decoders — see `crate::apply`).
#[cfg(test)]
use coxswain_core::routing::{GatewayRoutingTable, IngressRoutingTable};

use super::MAX_MIRROR_DEPTH;
use crate::error::WireError;
use crate::proto::v1 as p;
use crate::wire::endpoints::endpoint_key_from_wire;
#[cfg(test)]
use crate::wire::endpoints::endpoint_pool_from_resources;

// ────────────────────────────────────────────────────────────────────────────
// MaterializedGroup (#383)
// ────────────────────────────────────────────────────────────────────────────

/// A [`BackendGroup`] decoded against the message's endpoint pool, plus the
/// endpoint-derived error status the client must re-install (#383).
///
/// `empty_status` is `Some` only when the group referenced ≥1 endpoint resource
/// (a keyed backendRef) yet resolved to zero routable addresses — the exact
/// condition under which the reflector's encoder *omitted* the status (it marks
/// keyed empties `error_status_endpoint_derived`). The value reproduces the
/// shared rule ([`empty_group_status`]): a valid Service with zero ready
/// endpoints → 503, an invalid/missing Service → 500. Literal-address groups and
/// backend-less (redirect) groups leave it `None`; any endpoint-independent
/// status the server baked rides `dto.error_status` and wins at the call site.
#[derive(Debug)]
pub(crate) struct MaterializedGroup {
    /// The reconstructed backend group (hot-path routing structures).
    pub(crate) group: BackendGroup,
    /// Endpoint-derived error status to install when the server omitted it.
    pub(crate) empty_status: Option<u16>,
}

// ────────────────────────────────────────────────────────────────────────────
// Routing table: from_wire
// ────────────────────────────────────────────────────────────────────────────

/// Reconstruct an [`IngressRoutingTable`] from its whole-table wire DTO,
/// resolving endpoint references against `pool`.
///
/// Test-only oracle (#383): production decode now goes partition-by-partition
/// through [`build_route_table`] (the client's `crate::apply` splice path), so
/// this whole-table variant survives only as the wire round-trip tests'
/// convenience.
///
/// # Errors
///
/// Returns [`WireError`] if any field is invalid (bad regex, bad header name,
/// unknown enum value, depth-exceeded mirror, dangling endpoint ref, etc.).
#[cfg(test)]
#[must_use = "the rebuilt routing table must be stored for the proxy to use it"]
pub(crate) fn ingress_from_wire(
    dto: &p::RoutingTable,
    pool: &EndpointPool,
) -> Result<IngressRoutingTable, WireError> {
    routing_table_from_wire::<coxswain_core::routing::Ingress>(dto, pool)
}

/// Reconstruct a [`GatewayRoutingTable`] from its whole-table wire DTO, resolving
/// endpoint references against `pool`. Test-only oracle — see
/// [`ingress_from_wire`].
///
/// # Errors
///
/// Returns [`WireError`] if any field is invalid.
#[cfg(test)]
#[must_use = "the rebuilt routing table must be stored for the proxy to use it"]
pub(crate) fn gateway_from_wire(
    dto: &p::RoutingTable,
    pool: &EndpointPool,
) -> Result<GatewayRoutingTable, WireError> {
    routing_table_from_wire::<coxswain_core::routing::Gateway>(dto, pool)
}

#[cfg(test)]
fn routing_table_from_wire<Kind>(
    dto: &p::RoutingTable,
    pool: &EndpointPool,
) -> Result<coxswain_core::routing::RoutingTable<Kind>, WireError>
where
    coxswain_core::routing::RoutingTableBuilder<Kind>: Default,
{
    // Reshape the port-nested DTO into the borrowed per-port host map that
    // [`build_route_table`] consumes, so this and the client's staged-cache
    // apply path (#383) compile through one function.
    let mut hosts_by_port: std::collections::BTreeMap<u16, Vec<&p::HostEntry>> =
        std::collections::BTreeMap::new();
    for port_entry in &dto.ports {
        let entry = hosts_by_port.entry(port_entry.port as u16).or_default();
        entry.extend(port_entry.hosts.iter());
    }
    build_route_table::<Kind>(&hosts_by_port, pool)
}

/// Compile a routing table of table-kind `Kind` from a per-port map of host
/// buckets and the message's endpoint pool.
///
/// This is the **per-table compile seam** shared by the whole-DTO decode
/// ([`routing_table_from_wire`], hence `decode_world`) and the client's
/// staged-cache apply pipeline (`crate::apply`, #383). The client keys its
/// resource cache by `(table, port, host)` partition; when the partitioned
/// recompile lands (commit 5) it groups the staged route partitions back into
/// this per-port shape and calls this function per table kind. Keeping one
/// compile function means the streamed full decode and the client rebuild can
/// never diverge in how a host bucket becomes a compiled router.
///
/// `hosts_by_port` is a `BTreeMap` so ports compile in a deterministic order
/// (listener-isolation tie-breaks are order-sensitive in the builder).
///
/// # Errors
///
/// Returns [`WireError`] if any host bucket fails to decode (bad regex, bad
/// header name, unknown enum value, depth-exceeded mirror, dangling endpoint
/// ref, or a path pattern the `matchit` router rejects).
#[must_use = "the compiled routing table must be stored for the proxy to use it"]
pub(crate) fn build_route_table<Kind>(
    hosts_by_port: &std::collections::BTreeMap<u16, Vec<&p::HostEntry>>,
    pool: &EndpointPool,
) -> Result<coxswain_core::routing::RoutingTable<Kind>, WireError>
where
    coxswain_core::routing::RoutingTableBuilder<Kind>: Default,
{
    let mut builder = coxswain_core::routing::RoutingTableBuilder::<Kind>::new();
    for (&port, hosts) in hosts_by_port {
        let port_builder = builder.for_port(port);
        for host_entry in hosts {
            host_entry_from_wire(host_entry, port_builder, pool)?;
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
    pool: &EndpointPool,
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
        route_entry_from_wire(route_dto, host_builder, pool)?;
    }
    Ok(())
}

fn route_entry_from_wire(
    dto: &p::RouteEntry,
    host_builder: &mut HostRouterBuilder,
    pool: &EndpointPool,
) -> Result<(), WireError> {
    let kind = route_kind_from_wire(dto.kind)?;
    let entry = Arc::new(build_route_entry(dto, pool)?);

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
    }
    Ok(())
}

fn build_route_entry(dto: &p::RouteEntry, pool: &EndpointPool) -> Result<RouteEntry, WireError> {
    let bg_dto = dto
        .backend_group
        .as_ref()
        .ok_or(WireError::MissingRequiredField {
            field: "route_entry.backend_group",
        })?;
    let materialized = bg_from_wire(bg_dto, pool, 0)?;
    let backend_group = Arc::new(materialized.group);

    let predicates = dto
        .predicates
        .as_ref()
        .map(predicates_from_wire)
        .transpose()?
        .unwrap_or_default();

    let mut filters = Vec::with_capacity(dto.filters.len());
    for f in &dto.filters {
        filters.push(filter_from_wire(f, 0, pool)?);
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
    // #383 provenance split: a baked (endpoint-independent) status wins; else
    // install the endpoint-derived status the server omitted, re-derived from the
    // resolved pool. Reproduces the reflector's precedence exactly.
    entry = entry.with_error_status(
        dto.error_status
            .map(|s| s as u16)
            .or(materialized.empty_status),
    );

    if let Some(max) = dto.max_body_size {
        entry = entry.with_max_body_size(Some(max));
    }

    if !dto.allow_source_range.is_empty() {
        let nets: Vec<ipnet::IpNet> = dto
            .allow_source_range
            .iter()
            .map(|s| s.parse::<ipnet::IpNet>().map_err(WireError::InvalidCidr))
            .collect::<Result<_, _>>()?;
        entry = entry.with_allow_source_range(Some(Arc::from(nets)));
    }

    if !dto.deny_source_range.is_empty() {
        let nets: Vec<ipnet::IpNet> = dto
            .deny_source_range
            .iter()
            .map(|s| s.parse::<ipnet::IpNet>().map_err(WireError::InvalidCidr))
            .collect::<Result<_, _>>()?;
        entry = entry.with_deny_source_range(Some(Arc::from(nets)));
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

pub(crate) fn bg_from_wire(
    dto: &p::BackendGroup,
    pool: &EndpointPool,
    depth: usize,
) -> Result<MaterializedGroup, WireError> {
    if depth > MAX_MIRROR_DEPTH {
        return Err(WireError::MirrorTooDeep {
            limit: MAX_MIRROR_DEPTH,
        });
    }

    // Resolve each weighted backend to its (addrs, weight), tracking whether any
    // keyed ref resolved and whether the group is a valid-but-empty Service — the
    // inputs to the endpoint-derived status the reflector omitted (#383).
    let mut resolved: Vec<(Vec<SocketAddr>, u16)> = Vec::with_capacity(dto.weighted.len());
    let mut has_keyed_ref = false;
    let mut has_valid_empty = false;
    for wb in &dto.weighted {
        let weight = wb.weight as u16;
        let addrs = if let Some(reference) = &wb.endpoint_ref {
            has_keyed_ref = true;
            // The pool is keyed by u16-narrowed `EndpointKey`s (out-of-range
            // endpoint resources are rejected at stage), so a ref port outside the
            // u16 range can never legitimately resolve — narrowing it would truncate
            // (65616 → 80) and silently bind to an unrelated port's endpoints. Treat
            // an out-of-range ref as a dangling reference (#383 review).
            let port =
                u16::try_from(reference.port).map_err(|_| WireError::UnknownEndpointRef {
                    namespace: reference.namespace.clone(),
                    service: reference.service.clone(),
                    port: reference.port,
                })?;
            let key = endpoint_key_from_wire(&reference.namespace, &reference.service, port.into());
            let ep = pool
                .get(&key)
                .ok_or_else(|| WireError::UnknownEndpointRef {
                    namespace: reference.namespace.clone(),
                    service: reference.service.clone(),
                    port: u32::from(port),
                })?;
            if weight > 0 && ep.service_exists && ep.addrs.is_empty() {
                has_valid_empty = true;
            }
            ep.addrs.clone()
        } else {
            // Literal addresses (pre-#383 form) or a structurally-invalid empty
            // entry (no ref, no addrs) — parse whatever is present.
            wb.addrs
                .iter()
                .map(|s| s.parse::<SocketAddr>().map_err(WireError::InvalidAddr))
                .collect::<Result<_, _>>()?
        };
        resolved.push((addrs, weight));
    }

    // A backend survives into the hot-path pools iff it has ≥1 address and a
    // non-zero weight (mirrors BackendGroup::weighted's own retention). Filter
    // here first so per-backend filters can be built in lockstep with the
    // surviving pools — with_per_backend_filters requires index alignment with
    // the final backend set.
    let surviving: Vec<usize> = resolved
        .iter()
        .enumerate()
        .filter(|(_, (addrs, w))| *w > 0 && !addrs.is_empty())
        .map(|(i, _)| i)
        .collect();

    let has_addrs = !surviving.is_empty();
    // The endpoint-derived status the server omitted (keyed group, no routable
    // address). A literal/backend-less group leaves this None; any baked
    // endpoint-independent status wins at build_route_entry.
    let empty_status = (has_keyed_ref && !has_addrs).then(|| empty_group_status(has_valid_empty));

    // Build per-backend filters aligned to the SURVIVING backends (sparse input
    // is keyed by original weighted index).
    let per_backend_filters: Option<Vec<Vec<FilterAction>>> = if dto.per_backend_filters.is_empty()
    {
        None
    } else {
        let mut by_orig: std::collections::HashMap<usize, Vec<FilterAction>> =
            std::collections::HashMap::new();
        for entry in &dto.per_backend_filters {
            let filters: Vec<FilterAction> = entry
                .filters
                .iter()
                .map(|f| filter_from_wire(f, depth + 1, pool))
                .collect::<Result<_, _>>()?;
            by_orig.insert(entry.backend_index as usize, filters);
        }
        let slots: Vec<Vec<FilterAction>> = surviving
            .iter()
            .map(|&orig| by_orig.remove(&orig).unwrap_or_default())
            .collect();
        Some(slots)
    };

    let pools: Vec<(Vec<SocketAddr>, u16)> =
        surviving.iter().map(|&i| resolved[i].clone()).collect();

    let protocol = protocol_from_wire(dto.protocol)?;

    let tls = dto.tls.as_ref().map(upstream_tls_from_wire).transpose()?;

    let retry = dto.retry.as_ref().map(retry_from_wire).unwrap_or_default();

    let mut bg = BackendGroup::weighted(dto.name.clone(), pools);

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

    Ok(MaterializedGroup {
        group: bg,
        empty_status,
    })
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
        // Drop unknown SAN kinds gracefully: `san.kind` is the wire (proto) enum,
        // which stays forward-compatible across versions. This prevents a future
        // proto Kind from being coerced to the default (Hostname=0) and producing a
        // spurious SAN mismatch / silent auth downgrade on rolling upgrades.
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

fn retry_from_wire(dto: &p::RetryPolicy) -> coxswain_core::routing::RetryPolicyConfig {
    use coxswain_core::routing::RetryPolicyConfig;
    let backoff = (dto.backoff_ms > 0).then(|| Duration::from_millis(u64::from(dto.backoff_ms)));
    // Wire carries codes as u32 (proto3 has no u16); drop any that don't fit a status
    // code — they can only arise from a corrupt/incompatible peer.
    let http_codes = dto
        .http_codes
        .iter()
        .filter_map(|&c| u16::try_from(c).ok())
        .collect();
    let grpc_codes = dto
        .grpc_codes
        .iter()
        .filter_map(|&c| u16::try_from(c).ok())
        .collect();
    RetryPolicyConfig::new(dto.attempts, backoff, http_codes, grpc_codes)
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

fn filter_from_wire(
    dto: &p::FilterAction,
    depth: usize,
    pool: &EndpointPool,
) -> Result<FilterAction, WireError> {
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
            let backend = Arc::new(bg_from_wire(bg_dto, pool, depth + 1)?.group);
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
        other => WireError::InvalidHeaderMod(other.to_string()),
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
            let endpoints: Arc<[SocketAddr]> = ext
                .endpoints
                .iter()
                .map(|s| s.parse::<SocketAddr>().map_err(WireError::InvalidAddr))
                .collect::<Result<Vec<_>, _>>()?
                .into();
            // Transport is whichever of grpc/http is present (grpc wins if both,
            // which the encoder never emits). Neither present → a forward-
            // incompatible or malformed entry: fail that route's auth **closed**
            // (Unavailable → 503) rather than erroring the whole snapshot decode.
            let transport = if let Some(g) = ext.grpc.as_ref() {
                ExtAuthTransport::Grpc(GrpcExtAuthConfig::new(
                    g.response_headers
                        .iter()
                        .map(|s| Box::from(s.as_str()))
                        .collect::<Arc<[_]>>(),
                ))
            } else if let Some(http) = ext.http.as_ref() {
                ExtAuthTransport::Http(HttpExtAuthConfig::new(
                    http.response_headers
                        .iter()
                        .map(|s| Box::from(s.as_str()))
                        .collect::<Arc<[_]>>(),
                    http.always_set_cookie,
                ))
            } else {
                return Ok(IngressAuthConfig::Unavailable);
            };
            Ok(IngressAuthConfig::External(ExtAuthConfig::new(
                ext.timeout
                    .as_ref()
                    .map(duration_from_wire)
                    .unwrap_or_default(),
                endpoints,
                ext.fail_closed,
                transport,
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
        p::ingress_auth_config::Auth::Jwt(jwt) => {
            // An unresolved JWKS (controller hasn't fetched the remote `jwksUri`
            // yet, or the wire payload is malformed) encodes as an empty string —
            // fail that route's auth closed rather than handing the proxy an
            // empty key set to "verify" against.
            if jwt.jwks.is_empty() {
                return Ok(IngressAuthConfig::Unavailable);
            }
            let from_headers: Arc<[JwtHeaderLoc]> = jwt
                .from_headers
                .iter()
                .map(|h| JwtHeaderLoc::new(h.name.as_str(), h.value_prefix.as_str()))
                .collect();
            let claim_to_headers: Arc<[(Box<str>, Box<str>)]> = jwt
                .claim_to_headers
                .iter()
                .map(|c| (Box::from(c.claim.as_str()), Box::from(c.header.as_str())))
                .collect();
            Ok(IngressAuthConfig::Jwt(JwtConfig::new(
                Arc::from(jwt.issuer.as_str()),
                jwt.audiences
                    .iter()
                    .map(|s| Box::from(s.as_str()))
                    .collect(),
                Arc::from(jwt.jwks.as_str()),
                from_headers,
                jwt.forward_payload_header.as_deref().map(Box::from),
                claim_to_headers,
                jwt.forward_token,
            )))
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

pub(crate) fn protocol_from_wire(v: i32) -> Result<BackendProtocol, WireError> {
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
pub(crate) fn passthrough_from_wire(
    dto: &p::TlsPassthroughTable,
    pool: &EndpointPool,
) -> Result<TlsPassthroughTable, WireError> {
    let mut builder = TlsPassthroughTableBuilder::new();
    for port_entry in &dto.ports {
        let port = port_entry.port as u16;
        for entry in &port_entry.entries {
            let bg = match &entry.backend_group {
                Some(bg) => Arc::new(bg_from_wire(bg, pool, 0)?.group),
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

/// Decode a [`TcpRouteTable`] from a protobuf DTO (#505).
///
/// # Errors
///
/// Returns [`WireError`] if any backend group fails to decode (bad address,
/// missing required field, etc.).
#[must_use = "the rebuilt TCP route table must be stored for the proxy to use it"]
pub(crate) fn tcp_table_from_wire(
    dto: &p::TcpRouteTable,
    pool: &EndpointPool,
) -> Result<TcpRouteTable, WireError> {
    let mut builder = TcpRouteTableBuilder::new();
    for port_entry in &dto.ports {
        let port = port_entry.port as u16;
        let bg = match &port_entry.backend_group {
            Some(bg) => Arc::new(bg_from_wire(bg, pool, 0)?.group),
            None => continue,
        };
        builder = builder.add_route(port, bg);
    }
    Ok(builder.build())
}

/// Reconstruct a [`UdpRouteTable`] from its wire DTO (UDPRoute, GEP-2645, #506).
///
/// Same shape as [`tcp_table_from_wire`] — port-keyed, no SNI dimension.
///
/// # Errors
///
/// Returns [`WireError`] if any backend group fails to decode (malformed
/// address, missing required field, etc.).
#[must_use = "the rebuilt UDP route table must be stored for the proxy to use it"]
pub(crate) fn udp_table_from_wire(
    dto: &p::UdpRouteTable,
    pool: &EndpointPool,
) -> Result<UdpRouteTable, WireError> {
    let mut builder = UdpRouteTableBuilder::new();
    for port_entry in &dto.ports {
        let port = port_entry.port as u16;
        let bg = match &port_entry.backend_group {
            Some(bg) => Arc::new(bg_from_wire(bg, pool, 0)?.group),
            None => continue,
        };
        builder = builder.add_route(port, bg);
    }
    Ok(builder.build())
}

// ────────────────────────────────────────────────────────────────────────────
// Resource-oriented world decode (#383)
// ────────────────────────────────────────────────────────────────────────────

/// The two L7 route tables decoded from a resource set.
///
/// Test-only oracle (#383): production decode is now partition-wise through
/// [`build_route_table`] (routes) and cell-wise through the L4/TLS decoders
/// (`crate::apply`). This whole-table variant survives only for the wire round-
/// trip tests, which assert an encode→decode fixed point on the route tables; the
/// coarse cells (TLS, client-cert, listener-status, L4) have their own direct
/// per-cell round-trip tests and are intentionally not reassembled here.
#[cfg(test)]
pub(crate) struct DecodedWorld {
    /// Ingress L7 routing table.
    pub(crate) ingress: IngressRoutingTable,
    /// Gateway API L7 routing table.
    pub(crate) gateway: GatewayRoutingTable,
}

/// Decode the route-table half of a resource set into its two L7 tables (#383).
///
/// Builds the message's transient [`EndpointPool`] first (referential integrity:
/// every ref must resolve against it), reshapes the flat `route_host` resources
/// into per-table, per-port DTOs, and replays the whole-table decoders. A
/// resource with no payload arm — a future variant this build cannot decode — is
/// a protocol error per invariant 7; non-route resources are ignored (each has
/// its own direct round-trip test).
///
/// Test-only oracle — see [`DecodedWorld`].
///
/// # Errors
///
/// Returns the first [`WireError`] from endpoint parsing, a dangling ref, an
/// unkeyable route resource, or any field-level decode failure.
#[cfg(test)]
#[must_use = "the decoded route tables are the assertion target of the wire round-trip test"]
pub(crate) fn decode_world(resources: &[p::Resource]) -> Result<DecodedWorld, WireError> {
    let pool = endpoint_pool_from_resources(resources)?;

    let mut ingress_ports: std::collections::BTreeMap<u16, Vec<p::HostEntry>> =
        std::collections::BTreeMap::new();
    let mut gateway_ports: std::collections::BTreeMap<u16, Vec<p::HostEntry>> =
        std::collections::BTreeMap::new();

    for resource in resources {
        let payload = resource
            .payload
            .as_ref()
            .ok_or(WireError::UnknownResourceKey {
                reason: "resource carries no payload arm (unknown future variant)",
            })?;
        if let p::resource::Payload::RouteHost(rh) = payload {
            let host = rh.host.clone().ok_or(WireError::UnknownResourceKey {
                reason: "route_host resource missing its host bucket",
            })?;
            let port = rh.port as u16;
            match p::RouteTableKind::try_from(rh.table).unwrap_or(p::RouteTableKind::Unspecified) {
                p::RouteTableKind::Ingress => ingress_ports.entry(port).or_default().push(host),
                p::RouteTableKind::Gateway => gateway_ports.entry(port).or_default().push(host),
                p::RouteTableKind::Unspecified => {
                    return Err(WireError::UnknownResourceKey {
                        reason: "route_host resource has an unspecified table kind",
                    });
                }
            }
        }
    }

    let to_dto = |ports: std::collections::BTreeMap<u16, Vec<p::HostEntry>>| p::RoutingTable {
        ports: ports
            .into_iter()
            .map(|(port, hosts)| p::PortEntry {
                port: u32::from(port),
                hosts,
            })
            .collect(),
    };

    Ok(DecodedWorld {
        ingress: ingress_from_wire(&to_dto(ingress_ports), &pool)?,
        gateway: gateway_from_wire(&to_dto(gateway_ports), &pool)?,
    })
}
