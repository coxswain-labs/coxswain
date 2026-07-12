//! Core `HTTPRoute`/`Gateway` reconciliation: builds routing table entries from
//! listener bindings and resolved backend groups.

use super::GatewayApiReconciler;
use super::backend_policy::{BackendPolicyIndex, ResolvedBackendPolicy};
use super::backend_tls::{BackendTlsIndex, ResolvedPolicy};
use super::bindings::{ListenerBinding, compute_listener_bindings};
use super::reconcile_tls::{
    GatewayTlsTarget, grants_for_source, resolve_listener_tls, resolve_route_client_cert,
};
use crate::endpoints;
use crate::endpoints::pool::EndpointCache;
use crate::gw_types::{
    HttpRoute,
    v::httproutes::{
        HttpRouteRulesBackendRefs, HttpRouteRulesFilters, HttpRouteRulesFiltersType,
        HttpRouteRulesMatchesPathType,
    },
};
use crate::k8s_utils::metadata_created_at;
use crate::keys::ListenerKey;
use crate::status::{GatewayListenerStatus, ListenerInfo, ListenerReadiness, ListenerStatusKey};
use coxswain_core::crd::{
    BasicAuth, Compression, CoxswainExternalAuth, IpAccessControl, JwtAuth, PathRewriteRegex,
    RateLimit, RequestSizeLimit, RetryPolicy,
};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::{
    BackendClientCert, BackendGroup, BackendProtocol, CompressionConfig, FilterAction,
    GatewayRoutingTableBuilder, HostRouterBuilder, IngressAuthConfig, MatchPredicates,
    RateLimitConfig, RouteEntry, RouteTimeouts, UpstreamTls, WildcardKind,
};
use coxswain_core::tls::PortTlsStoreBuilder;
use k8s_openapi::api::core::v1::{Secret, Service};
use kube::runtime::reflector;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

/// Precomputed lookup tables consumed by [`GatewayApiReconciler::reconcile`].
///
/// Bundles the per-rebuild context that doesn't change between routes — the
/// listener-binding table, the `BackendTLSPolicy` index, and the `RateLimit`
/// CR store — so the function stays under the workspace
/// `clippy::too_many_arguments` threshold without each call site repeating the
/// three-arg suffix. `Copy` (every field is a shared reference) so the same
/// value can cheaply feed both [`route_fingerprint`] (planning, by reference)
/// and `reconcile` (translation, by value) for #511's partitioned rebuild
/// without constructing it twice.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct RouteResolution<'a> {
    /// `(gw_ns, gw_name, listener_name) → (hostname, port)` mapping for every
    /// listener on every Gateway we own.
    pub listener_info: &'a HashMap<ListenerKey, ListenerBinding>,
    /// Per-(Service, port) `BackendTLSPolicy` lookup table; lookups try
    /// `(svc, Some(port))` first and fall back to `(svc, None)`.
    pub policy_index: &'a BackendTlsIndex,
    /// Per-`Service` connect/idle timeout index from `CoxswainBackendPolicy` (#354).
    /// The highest-weight backendRef's Service policy is applied to the rule's
    /// `BackendGroup`.
    pub backend_policy_index: &'a BackendPolicyIndex,
    /// `RateLimit` CR store for resolving `ExtensionRef` filters on
    /// `HTTPRouteRule`s. Looked up by `(namespace, name)` from the filter;
    /// missing CRs produce a WARN and fail-open (route is not limited).
    pub rate_limits: &'a reflector::Store<RateLimit>,
    /// `RetryPolicy` CR store for resolving `ExtensionRef` filters on `HTTPRouteRule`s
    /// (#445). The resolved policy is attached to the rule's `BackendGroup`s; a missing
    /// CR fails open (no retries). Protocol-agnostic — GRPCRoute uses the same store.
    pub retry_policies: &'a reflector::Store<RetryPolicy>,
    /// `PathRewriteRegex` CR store for resolving `ExtensionRef` filters on
    /// `HTTPRouteRule`s.
    pub path_rewrites: &'a reflector::Store<PathRewriteRegex>,
    /// `IpAccessControl` CR store for resolving `ExtensionRef` filters on
    /// `HTTPRouteRule`s into per-route `allow`/`deny` source-IP CIDR sets (#479).
    /// Looked up by `(namespace, name)`; a missing CR fails open (no filtering).
    pub ip_access: &'a reflector::Store<IpAccessControl>,
    /// `BasicAuth` CR store for resolving `ExtensionRef` filters on `HTTPRouteRule`s
    /// (#442). HTTPRoute-only — not supported on GRPCRoute.
    pub basic_auths: &'a reflector::Store<BasicAuth>,
    /// `CoxswainExternalAuth` CR store for resolving `ExternalAuth` `ExtensionRef`
    /// filters on `HTTPRouteRule`s into per-route ext_authz config (#23).
    /// HTTPRoute-only. The auth-service `backendRef` is resolved to endpoints
    /// against `services`/`endpoint_cache`, gated by the same backend `grants`.
    pub external_auths: &'a reflector::Store<CoxswainExternalAuth>,
    /// Per-Gateway ext-auth mandate from `CoxswainExternalAuth` policies attached
    /// via `targetRefs` (#23, GEP-713). A route bound to a Gateway present here has
    /// the mandate **prepended** to every rule's auth chain — additive precedence:
    /// a route filter can add checks but cannot remove the Gateway-level one.
    pub external_auth_gateway_index: &'a super::ExternalAuthGatewayIndex,
    /// `JwtAuth` CR store for resolving `ExtensionRef` filters on `HTTPRouteRule`s
    /// into per-route JWT (JWKS bearer-token) validation config (#441).
    pub jwt_auths: &'a reflector::Store<JwtAuth>,
    /// Controller-fetched remote-JWKS cache, read synchronously when resolving a
    /// `JwtAuth` CR that names a `jwks.remote` (#441). Never populated by the
    /// proxy — see [`crate::jwks`].
    pub jwks_cache: &'a crate::jwks::SharedJwksCache,
    /// Label-scoped htpasswd Secrets (`ingress.coxswain-labs.dev/auth-basic=true`)
    /// consumed by a resolved `BasicAuth` CR's `secretRef` (#442). The same store
    /// the Ingress `auth-basic-secret` annotation reads — no duplicate watcher.
    pub auth_secrets: &'a reflector::Store<Secret>,
    /// `BasicAuth → Secret` ReferenceGrants (#520). A `BasicAuth` CR whose
    /// `secretRef.namespace` differs from the route namespace requires a matching
    /// grant; without one the cross-namespace ref fails closed, so a tenant cannot
    /// bind another namespace's auth Secret.
    pub basic_auth_secret_grants: &'a HashSet<ReferenceGrantKey>,
    /// `RequestSizeLimit` CR store for resolving `ExtensionRef` filters on
    /// `HTTPRouteRule`s (#443). HTTPRoute-only — NOT enforced on GRPCRoute (#509): a
    /// mid-stream body cap on HTTP/2 deadlocks the client under pingora, and gRPC
    /// sends no `Content-Length` for the up-front check; gRPC relies on the backend's
    /// own `max_recv_msg_size` until pingora ships request-body buffering (#816/#780).
    pub request_size_limits: &'a reflector::Store<RequestSizeLimit>,
    /// `Compression` CR store for resolving `ExtensionRef` filters on
    /// `HTTPRouteRule`s (#446). HTTPRoute-only — not supported on GRPCRoute.
    pub compressions: &'a reflector::Store<Compression>,
    /// `ObjectKey(gw_ns, gw_name) → BackendClientCert` for Gateways that resolved a
    /// `spec.tls.backend.clientCertificateRef` (GEP-3155). A route's effective client
    /// cert comes from its owned parent Gateway; it is attached to any `UpstreamTls`
    /// the route's backends carry (BackendTLSPolicy-driven TLS).
    pub backend_client_certs: &'a HashMap<ObjectKey, Arc<BackendClientCert>>,
    /// `ObjectKey(gw_ns, gw_name)` for Gateways whose `clientCertificateRef` is
    /// configured but failed to resolve. A route inheriting from such a Gateway
    /// fails closed (502) on BackendTLSPolicy-driven upstreams (GEP-3155): the proxy
    /// must not connect without the configured client identity. Empty when no owned
    /// Gateway has a broken ref.
    pub backend_client_cert_failures: &'a HashSet<ObjectKey>,
}

/// Spec-static fingerprint of everything [`GatewayApiReconciler::reconcile`]
/// would need to translate `route`, without running the translation (#511).
/// Combines:
/// - `route`'s own `resourceVersion` — catches every change to its own spec
///   (hostnames, backendRefs, filters, rules) in one hash, computed once here.
/// - for every rule's `ExtensionRef`-targeted CR (via the shared [`ext_refs`]
///   scanner), that CR's own `resourceVersion` — catches a CR being edited
///   independently of the route that references it.
/// - for every rule's `backendRefs`, [`EndpointCache::fingerprint`] for that
///   `(namespace, service, port)` — catches endpoint/Service-port churn on a
///   backend this route uses, independent of the route's own spec.
///
/// Deliberately does **not** track: Gateway-attached policies resolved via
/// `targetRef` (`BackendTLSPolicy`, `CoxswainBackendPolicy`, the Gateway-level
/// `CoxswainExternalAuth` mandate, GEP-3155 backend client certs), nor a
/// `BasicAuth` CR's own `secretRef` target. These are index-based or one-hop
/// indirections a per-route static scan can't cheaply and precisely resolve;
/// the partitioned rebuild instead folds [`fingerprint::store_epoch`] of
/// their source stores into every partition uniformly, so any change there
/// invalidates the whole table for one rebuild pass rather than risking a
/// partition wrongly believing itself unaffected (see
/// `reconciler::route_builder`'s partition-fingerprint assembly).
pub(crate) fn route_fingerprint(
    route: &HttpRoute,
    endpoint_cache: &EndpointCache,
    services: &reflector::Store<Service>,
    resolution: &RouteResolution<'_>,
) -> u64 {
    let mut fp: u64 = 0;
    let mut hasher = DefaultHasher::new();
    route.metadata.resource_version.hash(&mut hasher);
    fp ^= hasher.finish();

    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    for rule in route.spec.rules.as_deref().unwrap_or(&[]) {
        for (_group, kind, name) in super::filters::ext_refs(rule.filters.as_deref().unwrap_or(&[]))
        {
            fp ^= ext_ref_fingerprint(route_ns, kind, name, resolution);
        }
        for b in rule.backend_refs.as_deref().unwrap_or(&[]) {
            let Some(port) = b.port else { continue };
            let ns = b.namespace.as_deref().unwrap_or(route_ns);
            fp ^= endpoint_cache.fingerprint(ns, &b.name, port, services);
        }
    }
    fp
}

/// Fingerprint of a single spec-static `ExtensionRef` target `(kind, name)`
/// in `route_ns` — the referenced CR's own `resourceVersion`, via a direct
/// store lookup (no full scan). An unrecognized `kind` still folds in
/// `(kind, name)` directly rather than being silently dropped, so an
/// `ExtensionRef` this dispatch doesn't know about still moves the
/// fingerprint deterministically — safe (it just forfeits reuse for that
/// route instead of risking staleness).
fn ext_ref_fingerprint(
    route_ns: &str,
    kind: &str,
    name: &str,
    resolution: &RouteResolution<'_>,
) -> u64 {
    match kind {
        "RateLimit" => {
            crate::fingerprint::object_fingerprint(resolution.rate_limits, route_ns, name)
        }
        "RetryPolicy" => {
            crate::fingerprint::object_fingerprint(resolution.retry_policies, route_ns, name)
        }
        "PathRewriteRegex" => {
            crate::fingerprint::object_fingerprint(resolution.path_rewrites, route_ns, name)
        }
        "IpAccessControl" => {
            crate::fingerprint::object_fingerprint(resolution.ip_access, route_ns, name)
        }
        "BasicAuth" => {
            crate::fingerprint::object_fingerprint(resolution.basic_auths, route_ns, name)
        }
        "CoxswainExternalAuth" => {
            crate::fingerprint::object_fingerprint(resolution.external_auths, route_ns, name)
        }
        "JwtAuth" => crate::fingerprint::object_fingerprint(resolution.jwt_auths, route_ns, name),
        "RequestSizeLimit" => {
            crate::fingerprint::object_fingerprint(resolution.request_size_limits, route_ns, name)
        }
        "Compression" => {
            crate::fingerprint::object_fingerprint(resolution.compressions, route_ns, name)
        }
        _ => {
            let mut hasher = DefaultHasher::new();
            kind.hash(&mut hasher);
            name.hash(&mut hasher);
            hasher.finish()
        }
    }
}

impl GatewayApiReconciler {
    /// Skips routes whose `spec.parentRefs` do not include at least one Gateway
    /// managed by this controller. Never queries the API server.
    ///
    /// `resolution` bundles the precomputed lookup tables used to resolve a route:
    /// - `listener_info` maps `(gw_ns, gw_name, listener_name) → (hostname, port)`, used
    ///   to scope routes to the correct per-port routing table slot and listener hostname.
    /// - `policy_index` maps `(svc, port?)` to an `UpstreamTls` derived from an attached
    ///   `BackendTLSPolicy`. When a backend ref matches, the group is forced to TLS and
    ///   the policy's SNI / CA override is attached.
    pub fn reconcile(
        route: &HttpRoute,
        endpoint_cache: &EndpointCache,
        services: &reflector::Store<Service>,
        owned_gateways: &HashSet<ObjectKey>,
        grants: &HashSet<ReferenceGrantKey>,
        resolution: RouteResolution<'_>,
        builder: &mut GatewayRoutingTableBuilder,
    ) {
        let RouteResolution {
            listener_info,
            policy_index,
            backend_policy_index,
            rate_limits,
            retry_policies,
            path_rewrites,
            ip_access,
            basic_auths,
            external_auths,
            external_auth_gateway_index,
            jwt_auths,
            jwks_cache,
            auth_secrets,
            basic_auth_secret_grants,
            request_size_limits,
            compressions,
            backend_client_certs,
            backend_client_cert_failures,
        } = resolution;
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let route_name = route.metadata.name.as_deref().unwrap_or("unknown");
        let route_id = format!("{route_ns}/{route_name}");
        let created_at = metadata_created_at(&route.metadata);

        // Only reconcile routes attached to at least one listener we serve — an
        // owned Gateway, or a ListenerSet attached to one (GEP-1713).
        let has_owned_parent = route
            .spec
            .parent_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|p| {
                super::bindings::parent_ref_attaches(
                    p.group.as_deref(),
                    p.kind.as_deref(),
                    p.namespace.as_deref(),
                    &p.name,
                    route_ns,
                    owned_gateways,
                    listener_info,
                )
            });

        if !has_owned_parent {
            tracing::debug!(
                name = ?route.metadata.name,
                ns = route_ns,
                "Skipping HTTPRoute — no parentRef to a Coxswain-managed Gateway"
            );
            return;
        }

        // GEP-3155: the backend client cert the Gateway presents on upstream TLS is
        // gateway-scoped. A route inherits it from its first owned parent Gateway that
        // resolved a `spec.tls.backend.clientCertificateRef`. Attached below to any
        // `UpstreamTls` the route's backends carry (BackendTLSPolicy-driven TLS).
        //
        // A route attached to multiple owned Gateways with *different* backend client
        // certs resolves to the first such parentRef in declaration order: the cert
        // rides the route's single shared `BackendGroup`, so per-parent divergence
        // cannot be expressed. Deterministic (parentRefs is an ordered list); the
        // single-Gateway case (and conformance) is unambiguous.
        let (route_client_cert, route_client_cert_failed) = resolve_route_client_cert(
            route.spec.parent_refs.as_deref().unwrap_or(&[]),
            route_ns,
            owned_gateways,
            backend_client_certs,
            backend_client_cert_failures,
        );

        let rules = match route.spec.rules.as_deref() {
            Some(r) if !r.is_empty() => r,
            _ => return,
        };

        let route_hostnames: Vec<&str> = route
            .spec
            .hostnames
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();

        let bindings = compute_listener_bindings(
            &route_hostnames,
            route.spec.parent_refs.as_deref().unwrap_or(&[]),
            route_ns,
            listener_info,
        );

        // Gateway-attached ext-auth mandate (#23): the resolved check for every
        // owned Gateway this route is parented to. Prepended to each rule's auth
        // chain below — additive precedence, so a route-level filter can add
        // checks but never remove the Gateway-level one. Deduped by Gateway key so
        // a route with two parentRefs to the same Gateway prepends the check once.
        let gateway_auths: Vec<Arc<IngressAuthConfig>> = {
            let mut seen: HashSet<ObjectKey> = HashSet::new();
            let mut out: Vec<Arc<IngressAuthConfig>> = Vec::new();
            for p in route.spec.parent_refs.as_deref().unwrap_or(&[]) {
                let is_gateway = p
                    .group
                    .as_deref()
                    .is_none_or(|g| g.is_empty() || g == "gateway.networking.k8s.io")
                    && p.kind.as_deref().is_none_or(|k| k == "Gateway");
                if !is_gateway {
                    continue;
                }
                let gw_ns = p.namespace.as_deref().unwrap_or(route_ns);
                let gw_key = ObjectKey::new(gw_ns, &p.name);
                if !seen.insert(gw_key.clone()) {
                    continue;
                }
                if let Some(cfg) = external_auth_gateway_index.get(&gw_key) {
                    out.push(Arc::clone(cfg));
                }
            }
            out
        };

        tracing::debug!(
            name = ?route.metadata.name,
            ns = route_ns,
            rules = rules.len(),
            bindings = bindings.len(),
            "Reconciling HTTPRoute"
        );

        for (rule_index, rule) in rules.iter().enumerate() {
            // A named rule (GEP-995) gets a reorder-stable identifier; an
            // unnamed rule keeps the positional index it always had, so
            // existing `route` metric labels / `route_id` access-log values
            // are unaffected unless the operator opts into naming.
            let metric_route_id: Arc<str> = match rule.name.as_deref() {
                Some(name) => Arc::from(format!("httproute/{route_ns}/{route_name}:{name}")),
                None => Arc::from(format!("httproute/{route_ns}/{route_name}:{rule_index}")),
            };
            let rule_filters = rule.filters.as_deref().unwrap_or(&[]);
            let rule_timeouts = rule
                .timeouts
                .as_ref()
                .map(super::timeouts::parse_rule_timeouts)
                .unwrap_or_default();

            // Rules with RequestRedirect are terminal: the proxy fires the redirect before
            // consulting any upstream, so no BackendGroup is needed.
            let has_redirect = rule_filters
                .iter()
                .any(|f| matches!(f.r#type, HttpRouteRulesFiltersType::RequestRedirect));

            let (group, error_status, circuit_breaker): (
                Option<Arc<BackendGroup>>,
                Option<u16>,
                Option<Arc<coxswain_core::routing::CircuitBreakerConfig>>,
            ) = if has_redirect {
                (None, None, None)
            } else {
                // A rule with omitted or empty `backendRefs` is not skipped: the
                // Gateway API requires it to route with a distinct 500 response
                // (conformance `HTTPRouteNoBackendRefs`), not fall through to a
                // 404. Feeding an empty slice through the normal pipeline yields
                // an empty `BackendGroup` whose `error_status` resolves to 500
                // below (no backend ref failed to *resolve* — there simply were
                // none — so `ResolvedRefs` stays True).
                let backend_refs: &[HttpRouteRulesBackendRefs] =
                    rule.backend_refs.as_deref().unwrap_or(&[]);

                let resolved = resolve_weighted_backends(
                    backend_refs,
                    route_ns,
                    endpoint_cache,
                    services,
                    grants,
                );
                let group_name = backend_group_name(backend_refs, route_ns);
                let protocols: Vec<BackendProtocol> =
                    resolved.iter().map(|(r, _)| r.app_protocol).collect();
                let protocol = pick_route_protocol(&protocols, &group_name);
                // Per-backend filters from `backendRefs[].filters` — index-aligned
                // with the `resolved` list so they match the order `BackendGroup`
                // stores backends in. Backends that were dropped from `resolved`
                // (zero weight, missing addrs) also contribute nothing here.
                let per_backend_filters: Vec<Vec<FilterAction>> = resolved
                    .iter()
                    .zip(backend_refs.iter())
                    .filter(|((r, w), _)| *w > 0 && !r.addrs.is_empty())
                    .map(|((_, _), bref)| {
                        bref.filters
                            .as_deref()
                            .map(super::filters::build_backend_ref_filters)
                            .unwrap_or_default()
                    })
                    .collect();
                // A backendRef that points to an existing Service which currently
                // has zero ready endpoints drives a 503; invalid refs (missing
                // Service, wrong kind, denied cross-namespace) and all-zero-weight
                // rules drive a 500. Computed before `resolved` is consumed below.
                let has_valid_empty_backend = resolved
                    .iter()
                    .any(|(r, w)| *w > 0 && r.service_exists && r.addrs.is_empty());
                let weighted: Vec<(Vec<SocketAddr>, u16)> = resolved
                    .into_iter()
                    .filter(|(r, w)| *w > 0 && !r.addrs.is_empty())
                    .map(|(r, w)| (r.addrs, w))
                    .collect();

                // Look up BackendTLSPolicy for this rule's backends. Highest-weight ref
                // wins on conflicts (ties break by backendRefs array order).
                let policy_match =
                    pick_backend_tls(backend_refs, route_ns, policy_index, &group_name);
                let invalid_policy = matches!(policy_match, PolicyMatch::Invalid);
                let policy_tls = match policy_match {
                    PolicyMatch::Valid(tls) => Some(tls),
                    PolicyMatch::None | PolicyMatch::Invalid => None,
                };
                // GEP-3155 fail-closed: this backend speaks upstream TLS (BackendTLSPolicy)
                // AND an owned parent Gateway's `clientCertificateRef` is configured but
                // unresolvable. The proxy must present the operator-configured identity or
                // not connect at all — return 502 rather than silently dropping the cert.
                let client_cert_fail_closed = route_client_cert_failed && policy_tls.is_some();

                let mut group = BackendGroup::weighted(group_name, weighted)
                    .with_protocol(protocol)
                    .with_per_backend_filters(per_backend_filters);
                if let Some(tls) = policy_tls {
                    // Attach the gateway's GEP-3155 client cert to the policy-derived
                    // UpstreamTls so the proxy presents it for upstream mTLS. Clones the
                    // shared Arc'd UpstreamTls only on the rare route that has both a
                    // BackendTLSPolicy and a gateway backend client cert.
                    let tls = match route_client_cert {
                        Some(cc) => Arc::new((*tls).clone().with_client_cert(Arc::clone(cc))),
                        None => tls,
                    };
                    group = group.with_tls(tls);
                }
                // CoxswainBackendPolicy: apply per-backend connect/idle timeouts
                // (#354), the LB algorithm (#389), and session persistence (#554)
                // to the BackendGroup from the highest-weight backendRef's Service
                // policy. The circuit breaker (#478) is RouteEntry-level, carried
                // out to the RuleContext below.
                let bp = pick_backend_policy(backend_refs, route_ns, backend_policy_index);
                if let Some(bp) = bp {
                    if bp.connect.is_some() {
                        group = group.with_connect_timeout(bp.connect);
                    }
                    if bp.idle.is_some() {
                        group = group.with_keepalive_timeout(bp.idle);
                    }
                    if let Some(lb) = &bp.load_balance {
                        group = group.with_load_balance(lb.clone());
                    }
                    if bp.session_affinity.is_some() {
                        group = group.with_session_affinity(bp.session_affinity.clone());
                    }
                }
                // RetryPolicy ExtensionRef (#445): attach the resolved retry policy to the
                // group (upstream retrying is a backend concern). Default (disabled) when no
                // RetryPolicy ref is present or the CR is missing. HTTPRoute ⇒ `is_grpc=false`.
                let retry = super::filters::resolve_retry_policy(
                    rule_filters,
                    route_ns,
                    retry_policies,
                    false,
                );
                group = group.with_retries(retry);
                let circuit_breaker = bp.and_then(|bp| bp.circuit_breaker.clone());
                let group = Arc::new(group);
                if invalid_policy || client_cert_fail_closed {
                    // GEP-1897: a backend covered by an invalid BackendTLSPolicy MUST
                    // return 5xx, not silently fall back to plain HTTP. 502 reads as
                    // "upstream not reachable" which matches the spec intent. GEP-3155
                    // applies the same fail-closed 502 when the gateway client cert ref
                    // is configured but unresolvable.
                    (Some(group), Some(502u16), circuit_breaker)
                } else if group.endpoints().is_empty() {
                    // HTTPRoute spec: a valid Service with zero ready endpoints
                    // SHOULD return 503; an invalid/missing backend or all-zero-
                    // weight rule MUST return 500.
                    let status = if has_valid_empty_backend {
                        503u16
                    } else {
                        500u16
                    };
                    tracing::warn!(
                        route = ?route.metadata.name,
                        status,
                        "No ready endpoints for rule — installing error route"
                    );
                    (Some(group), Some(status), circuit_breaker)
                } else {
                    (Some(group), None, circuit_breaker)
                }
            };

            let rate_limit =
                super::filters::resolve_rate_limit(rule_filters, route_ns, rate_limits);
            let (allow_source_range, deny_source_range) =
                super::filters::resolve_ip_access(rule_filters, route_ns, ip_access);
            let basic_auth = super::filters::resolve_basic_auth(
                rule_filters,
                route_ns,
                basic_auths,
                auth_secrets,
                basic_auth_secret_grants,
            );
            let ext_auth = super::filters::resolve_external_auth(
                rule_filters,
                route_ns,
                external_auths,
                services,
                endpoint_cache,
                grants,
            );
            let jwt_auth =
                super::filters::resolve_jwt_auth(rule_filters, route_ns, jwt_auths, jwks_cache);
            // Additive chain (#23, #441): Gateway-attached mandate(s) first, then
            // the route-level BasicAuth, ExternalAuth, and JwtAuth `ExtensionRef`s.
            // Every check runs in order and the first hard-deny wins at the proxy —
            // a route cannot weaken a Gateway-level auth mandate (GEP-713 override
            // posture).
            let auth: Arc<[Arc<IngressAuthConfig>]> = gateway_auths
                .iter()
                .cloned()
                .chain([basic_auth, ext_auth, jwt_auth].into_iter().flatten())
                .collect();
            let max_body_size = super::filters::resolve_request_size_limit(
                rule_filters,
                route_ns,
                request_size_limits,
            );
            let compression =
                super::filters::resolve_compression(rule_filters, route_ns, compressions);
            let ctx = RuleContext {
                filters: rule_filters,
                timeouts: &rule_timeouts,
                error_status,
                route_id: &route_id,
                metric_route_id: &metric_route_id,
                created_at,
                rate_limit,
                allow_source_range,
                deny_source_range,
                circuit_breaker,
                auth,
                max_body_size,
                compression,
                route_ns,
                path_rewrites,
                endpoint_cache,
                services,
                grants,
            };
            for (hostname_opt, port) in &bindings {
                let pb = builder.for_port(*port);
                let hb = match hostname_opt {
                    None => pb.catchall(),
                    Some(h) if h.starts_with("*.") => pb.wildcard_host(h, WildcardKind::MultiLabel),
                    Some(h) => pb.exact_host(h),
                };
                apply_rule(hb, rule, group.as_ref(), &ctx);
            }
            // If bindings is empty, the route has no matching listener — skip.
        }
    }
}

/// Resolve each backendRef to `(pod_addresses, weight)`.
///
/// Weight defaults to 1 when absent (per the Gateway API spec). Refs with
/// `weight: 0`, non-Service kind, denied cross-namespace access, or no ready
/// endpoints contribute an empty entry and are naturally dropped by
/// `Upstream::weighted`.
fn resolve_weighted_backends(
    backend_refs: &[HttpRouteRulesBackendRefs],
    route_ns: &str,
    endpoint_cache: &EndpointCache,
    services: &reflector::Store<Service>,
    grants: &HashSet<ReferenceGrantKey>,
) -> Vec<(endpoints::ResolvedEndpoints, u16)> {
    backend_refs
        .iter()
        .filter_map(|b| b.port.map(|port| (b, port)))
        .map(|(b, port)| {
            let weight = weight_of(b);
            if weight == 0 {
                return (endpoints::ResolvedEndpoints::empty(), 0);
            }

            let b_kind = b.kind.as_deref().unwrap_or("Service");
            let b_group = b.group.as_deref().unwrap_or("");
            if b_kind != "Service" || (!b_group.is_empty() && b_group != "core") {
                return (endpoints::ResolvedEndpoints::empty(), weight);
            }

            let ns = b.namespace.as_deref().unwrap_or(route_ns);
            if ns != route_ns
                && !reference_grants::backend_ref_allowed(route_ns, ns, &b.name, grants)
            {
                tracing::warn!(
                    route_ns,
                    backend_ns = ns,
                    backend_svc = %b.name,
                    "Cross-namespace backendRef denied — no matching ReferenceGrant"
                );
                return (endpoints::ResolvedEndpoints::empty(), weight);
            }

            (
                (*endpoint_cache.get(ns, &b.name, port, services)).clone(),
                weight,
            )
        })
        .collect()
}

struct RuleContext<'a> {
    filters: &'a [HttpRouteRulesFilters],
    timeouts: &'a RouteTimeouts,
    error_status: Option<u16>,
    route_id: &'a str,
    metric_route_id: &'a Arc<str>,
    created_at: Option<SystemTime>,
    rate_limit: Option<Arc<RateLimitConfig>>,
    /// Source-IP allow-list resolved from the rule's `IpAccessControl`
    /// `ExtensionRef` (#479). Shared across every entry the rule installs.
    allow_source_range: Option<Arc<Vec<ipnet::IpNet>>>,
    /// Source-IP deny-list resolved from the same `IpAccessControl`. Enforced
    /// before `allow_source_range` in the proxy.
    deny_source_range: Option<Arc<Vec<ipnet::IpNet>>>,
    /// Per-backend circuit breaker from the rule's winning `CoxswainBackendPolicy`
    /// (#478). Shared across every entry the rule installs (one refcount bump each).
    circuit_breaker: Option<Arc<coxswain_core::routing::CircuitBreakerConfig>>,
    /// Additive authentication chain resolved from the rule's `BasicAuth` and
    /// `CoxswainExternalAuth` `ExtensionRef`s (#442, #23). Every check runs in
    /// order; the first hard-deny wins. Empty = no auth on the rule.
    auth: Arc<[Arc<IngressAuthConfig>]>,
    /// Request-body byte cap resolved from the rule's `RequestSizeLimit`
    /// `ExtensionRef` (#443).
    max_body_size: Option<u64>,
    /// Response-compression config resolved from the rule's `Compression`
    /// `ExtensionRef` (#446).
    compression: Option<Arc<CompressionConfig>>,
    route_ns: &'a str,
    path_rewrites: &'a reflector::Store<PathRewriteRegex>,
    endpoint_cache: &'a EndpointCache,
    services: &'a reflector::Store<Service>,
    grants: &'a HashSet<ReferenceGrantKey>,
}

/// Installs one HTTPRoute rule into a `HostRouterBuilder`.
///
/// When `group` is `None`, the rule has a `RequestRedirect` filter and no
/// upstream backend — `RouteEntry::redirect_only` is used in that case.
fn apply_rule(
    pb: &mut HostRouterBuilder,
    rule: &crate::gw_types::v::httproutes::HttpRouteRules,
    group: Option<&Arc<BackendGroup>>,
    ctx: &RuleContext<'_>,
) {
    let make_entry = |predicates: MatchPredicates, filter_list: Vec<FilterAction>| -> RouteEntry {
        let entry = match group {
            Some(g) => {
                let mut e = RouteEntry::with_filters(
                    Arc::clone(g),
                    predicates,
                    filter_list,
                    ctx.timeouts.clone(),
                    ctx.route_id.to_string(),
                    ctx.created_at,
                );
                e.error_status = ctx.error_status;
                e
            }
            None => RouteEntry::redirect_only(
                predicates,
                filter_list,
                ctx.timeouts.clone(),
                ctx.route_id.to_string(),
                ctx.created_at,
            ),
        };
        entry
            .with_metric_route_id(Arc::clone(ctx.metric_route_id))
            .with_rate_limit(ctx.rate_limit.clone())
            .with_allow_source_range(ctx.allow_source_range.clone())
            .with_deny_source_range(ctx.deny_source_range.clone())
            .with_circuit_breaker(ctx.circuit_breaker.clone())
            .with_auth_chain(ctx.auth.clone())
            .with_max_body_size(ctx.max_body_size)
            .with_compression(ctx.compression.clone())
    };

    let backend_stores = super::filters::BackendStores {
        endpoint_cache: ctx.endpoint_cache,
        services: ctx.services,
        grants: ctx.grants,
    };
    match rule.matches.as_deref() {
        None | Some([]) => {
            let filter_list = super::filters::build_filters(
                ctx.filters,
                "/",
                false,
                ctx.route_ns,
                ctx.path_rewrites,
                &backend_stores,
            );
            pb.add_prefix_route(
                "/",
                Arc::new(
                    make_entry(MatchPredicates::default(), filter_list)
                        .with_path_pattern(Arc::from("/")),
                ),
            );
        }
        Some(ms) => {
            for m in ms {
                // Build predicates, skipping this match if any regex is invalid.
                let predicates = match super::filters::build_predicates(m) {
                    Some(p) => p,
                    None => {
                        tracing::warn!(
                            "Skipping HTTPRouteMatch — invalid regex in header or query predicate"
                        );
                        continue;
                    }
                };

                let val = m
                    .path
                    .as_ref()
                    .and_then(|p| p.value.as_deref())
                    .unwrap_or("/");

                let is_prefix = matches!(
                    m.path.as_ref().and_then(|p| p.r#type.as_ref()),
                    None | Some(HttpRouteRulesMatchesPathType::PathPrefix)
                );
                let filter_list = super::filters::build_filters(
                    ctx.filters,
                    val,
                    is_prefix,
                    ctx.route_ns,
                    ctx.path_rewrites,
                    &backend_stores,
                );
                let e =
                    Arc::new(make_entry(predicates, filter_list).with_path_pattern(Arc::from(val)));

                match m.path.as_ref().and_then(|p| p.r#type.as_ref()) {
                    Some(HttpRouteRulesMatchesPathType::Exact) => {
                        pb.add_exact_route(val, e);
                    }
                    Some(HttpRouteRulesMatchesPathType::RegularExpression) => {
                        pb.add_regex_route(val, e);
                    }
                    // PathPrefix is the default per spec
                    _ => {
                        pb.add_prefix_route(val, e);
                    }
                }
            }
        }
    }
}

/// Extract weight from a backendRef, clamped to u16. Defaults to 1 when absent.
fn weight_of(b: &HttpRouteRulesBackendRefs) -> u16 {
    match b.weight {
        None => 1,
        Some(w) if w <= 0 => 0,
        Some(w) => w.min(u16::MAX as i32) as u16,
    }
}

/// Build a logging-only name for a rule's backend group.
fn backend_group_name(refs: &[HttpRouteRulesBackendRefs], ns: &str) -> String {
    match refs {
        [] => format!("{ns}/empty"),
        [single] => format!("{ns}/{}", single.name),
        [first, rest @ ..] => format!("{ns}/{}+{}more", first.name, rest.len()),
    }
}

/// Choose the representative `BackendProtocol` for a rule whose backendRefs
/// may declare different `appProtocol` values (per GEP-1911, mixed protocols
/// within a single rule are undefined).
///
/// Returns the first non-`Http1` protocol; falls back to `Http1` if all are
/// default. Emits a warning when more than one distinct non-default protocol
/// is present.
fn pick_route_protocol(protocols: &[BackendProtocol], group_name: &str) -> BackendProtocol {
    let non_default: Vec<BackendProtocol> = protocols
        .iter()
        .copied()
        .filter(|&p| p != BackendProtocol::Http1)
        .collect();

    match non_default.as_slice() {
        [] => BackendProtocol::Http1,
        [single] => *single,
        [first, ..] => {
            let all_same = non_default.iter().all(|&p| p == *first);
            if !all_same {
                tracing::warn!(
                    backend_group = group_name,
                    "Mixed appProtocol across backendRefs is undefined per GEP-1911; \
                     using first non-default"
                );
            }
            *first
        }
    }
}

/// Result of looking up a `BackendTLSPolicy` for a rule's backend refs.
enum PolicyMatch {
    /// No backend in this rule has an attached policy — route as normal.
    None,
    /// A valid policy is attached; install TLS to upstream with this configuration.
    Valid(Arc<UpstreamTls>),
    /// A policy is attached but invalid (e.g. CA cert ref unresolvable). Per
    /// GEP-1897 the data plane MUST return 5xx instead of falling back to plain
    /// HTTP; the caller installs a 502 error route for this rule.
    Invalid,
}

/// Select the `BackendTLSPolicy` to attach to a rule's `BackendGroup`.
///
/// Scans `backend_refs` and looks each up in `policy_index`. If ANY backend has
/// an invalid policy, the rule is blocked and the result is `PolicyMatch::Invalid`
/// — this is conservative but correct per GEP-1897, which forbids silently
/// falling back to plain HTTP when a policy was meant to apply.
///
/// Otherwise, when one or more backends have valid policies, the policy of the
/// highest-weight ref wins (ties broken by array order). When the matched
/// policies differ across backends, the winner is logged.
fn pick_backend_tls(
    backend_refs: &[HttpRouteRulesBackendRefs],
    route_ns: &str,
    policy_index: &BackendTlsIndex,
    group_name: &str,
) -> PolicyMatch {
    let mut best: Option<(Arc<UpstreamTls>, u16)> = None; // (tls, weight)
    let mut saw_invalid = false;

    // Per-port best-match lookup: try (svc, Some(port)) first (section-name policy
    // applied to this specific port), then fall back to (svc, None) (catch-all
    // policy covering the whole Service). This matches the GEP-1897 spec where
    // section-name policies override the catch-all for their specific port.
    let lookup = |svc_ns: &str, svc_name: &str, port: u16| -> Option<&ResolvedPolicy> {
        policy_index
            .iter()
            .find(|((k, p), _)| k.ns == svc_ns && k.name == svc_name && *p == Some(port))
            .or_else(|| {
                policy_index
                    .iter()
                    .find(|((k, p), _)| k.ns == svc_ns && k.name == svc_name && p.is_none())
            })
            .map(|(_, v)| v)
    };

    for b in backend_refs {
        let b_ns = b.namespace.as_deref().unwrap_or(route_ns);
        let Some(port) = b.port.and_then(|p| u16::try_from(p).ok()) else {
            continue;
        };
        let Some(resolved) = lookup(b_ns, &b.name, port) else {
            continue;
        };
        let Some(tls) = resolved.tls.as_ref() else {
            saw_invalid = true;
            continue;
        };
        let w = match b.weight {
            None => 1u16,
            Some(w) if w <= 0 => 0u16,
            Some(w) => w.min(u16::MAX as i32) as u16,
        };
        match &best {
            None => best = Some((Arc::clone(tls), w)),
            Some((_, best_w)) if w > *best_w => best = Some((Arc::clone(tls), w)),
            _ => {}
        }
    }

    if saw_invalid {
        tracing::warn!(
            backend_group = group_name,
            "BackendTLSPolicy attached to one of this rule's backends is invalid — \
             rule will return 502 (GEP-1897)"
        );
        return PolicyMatch::Invalid;
    }

    if let Some((ref tls, _)) = best {
        tracing::debug!(
            backend_group = group_name,
            sni = %tls.sni,
            "BackendTLSPolicy attached — originating TLS to upstream"
        );
        let distinct = backend_refs
            .iter()
            .filter_map(|b| {
                let b_ns = b.namespace.as_deref().unwrap_or(route_ns);
                let port = b.port.and_then(|p| u16::try_from(p).ok())?;
                lookup(b_ns, &b.name, port)
            })
            .map(|r| &r.policy_key)
            .collect::<HashSet<_>>()
            .len();
        if distinct > 1 {
            tracing::warn!(
                backend_group = group_name,
                "Multiple BackendTLSPolicies across backendRefs in one rule — \
                 using highest-weight ref's policy"
            );
        }
    }

    match best {
        Some((tls, _)) => PolicyMatch::Valid(tls),
        None => PolicyMatch::None,
    }
}

/// Select the `CoxswainBackendPolicy` timeouts to attach to a rule's
/// `BackendGroup` (#354).
///
/// Scans `backend_refs`, looking each backend's Service up in
/// `backend_policy_index` (keyed by `ObjectKey(svc_ns, svc_name)`). The
/// highest-weight ref's policy wins (ties break by array order), mirroring
/// [`pick_backend_tls`]. Returns `None` when no targeted Service carries a
/// policy with a parseable timeout.
fn pick_backend_policy<'a>(
    backend_refs: &[HttpRouteRulesBackendRefs],
    route_ns: &str,
    backend_policy_index: &'a BackendPolicyIndex,
) -> Option<&'a ResolvedBackendPolicy> {
    let mut best: Option<(&ResolvedBackendPolicy, u16)> = None;
    for b in backend_refs {
        let b_ns = b.namespace.as_deref().unwrap_or(route_ns);
        let Some(resolved) = backend_policy_index.get(&ObjectKey::new(b_ns, &b.name)) else {
            continue;
        };
        let w = match b.weight {
            None => 1u16,
            Some(w) if w <= 0 => 0u16,
            Some(w) => w.min(u16::MAX as i32) as u16,
        };
        match &best {
            None => best = Some((resolved, w)),
            Some((_, best_w)) if w > *best_w => best = Some((resolved, w)),
            _ => {}
        }
    }
    best.map(|(r, _)| r)
}

// ── Gateway TLS listener reconciliation ──────────────────────────────────────

impl GatewayApiReconciler {
    /// Walks `gateway.spec.listeners`, resolves TLS certificates for HTTPS
    /// listeners, and registers them in `builder`. Returns a per-listener health
    /// map so the controller can set accurate Gateway status conditions.
    ///
    /// Only `protocol: HTTPS` with `tls.mode: Terminate` (the default) is handled here.
    /// `protocol: TLS, tls.mode: Passthrough` listeners are handled by `build_passthrough_routes`
    /// in the route builder and are returned as `NotApplicable` by this function.
    /// The rejection in `resolve_listener_tls` only fires for the invalid combination
    /// `protocol: HTTPS, tls.mode: Passthrough`. Non-HTTPS listeners are `NotApplicable`.
    /// Cross-namespace `certificateRefs` require a matching entry in `cert_grants`.
    /// `internal_ports` maps this Gateway's `listenerPort → internalPort` (#472):
    /// in shared mode each listener binds an allocated internal port, so its
    /// terminate certs key under that port in the per-port store and the proxy's
    /// per-port `SniCertSelector` finds them. Listeners absent from the map
    /// (dedicated mode, Ingress) key under their spec port (internal == spec).
    /// Walks a Gateway's **effective** listeners (its own plus those merged from
    /// attached ListenerSets, GEP-1713), resolves TLS certificates for HTTPS
    /// listeners, and registers them in `builder`. Returns a per-listener health
    /// map keyed by [`ListenerStatusKey`] so the controller can attribute each
    /// listener's status to the resource that declared it.
    ///
    /// `gw_name` is the parent Gateway's name (for log context); each listener's
    /// `certificateRefs` resolve in its OWN `owning_namespace` — the Gateway's
    /// namespace for a Gateway listener, the ListenerSet's for a ListenerSet
    /// listener. A `conflicted` listener (lost a port-compatibility conflict) is
    /// recorded with `conflicted=true` but installs no cert and is not programmed.
    ///
    /// Only `protocol: HTTPS` with `tls.mode: Terminate` (the default) installs a
    /// cert here. `protocol: TLS, tls.mode: Passthrough` listeners are handled by
    /// `build_passthrough_routes`. Non-HTTPS listeners are `NotApplicable`.
    /// Cross-namespace `certificateRefs` require a matching entry in `cert_grants`.
    pub(crate) fn reconcile_tls(
        target: &GatewayTlsTarget<'_>,
        secrets: &reflector::Store<Secret>,
        cert_grants: &HashSet<ReferenceGrantKey>,
        ls_cert_grants: &HashSet<ReferenceGrantKey>,
        builder: &mut PortTlsStoreBuilder,
    ) -> GatewayListenerStatus {
        let mut map = BTreeMap::new();

        for listener in target.listeners {
            let listener_port = listener.port as u16;
            let internal_port = target
                .internal_ports
                .get(&listener_port)
                .copied()
                .unwrap_or(0);
            // A VIP Service is created asynchronously after the Gateway first appears.
            // Until it exists, internal_port is 0 and kube-proxy has not yet been
            // programmed to route VIP traffic to the proxy's NodePort. Emitting
            // TlsPassthrough / TlsTerminate (both healthy) while internal_port is 0
            // would cause the controller to publish Programmed=True + status.addresses
            // prematurely — the proxy binds the spec port, but kube-proxy routes to a
            // different internal port, causing ECONNREFUSED until the second rebuild.
            // Callers must ensure internal_port is non-zero when readiness is expected
            // (shared reconciler: VIP-based; dedicated reconciler: identity mapping).
            let vip_pending = internal_port == 0;
            // Bind port the proxy accepts this listener on (= internal port when
            // allocated, else the spec port); the cert store keys on it.
            let bind_port = if internal_port != 0 {
                internal_port
            } else {
                listener_port
            };
            let readiness = if listener.conflict.is_conflicted() {
                // Lost a port-compatibility conflict to a higher-precedence
                // listener (GEP-1713) — not programmed, no cert installed.
                ListenerReadiness::NotApplicable
            } else if listener.protocol == "TLS"
                && listener.tls.as_ref().is_some_and(|t| t.passthrough)
            {
                if vip_pending {
                    ListenerReadiness::VipPending
                } else {
                    // TLS passthrough: proxy peeks SNI and forwards raw stream; no cert needed.
                    ListenerReadiness::TlsPassthrough
                }
            } else if listener.protocol == "TLS" {
                // TLS/Terminate (TLSRouteModeTerminate, #481): resolve the cert exactly as for
                // HTTPS and install it into the per-port TLS store so the proxy's SniCertSelector
                // finds it. Remap Resolved → TlsTerminate so the bin layer creates a TlsL4
                // proxy port (L4 splice) rather than an HTTPS (L7 HTTP) listener. Resolve refs
                // FIRST so a terminal ref failure (RefNotPermitted / InvalidCertificateRef)
                // surfaces on `ResolvedRefs` regardless of VIP allocation; only the install is
                // deferred while `vip_pending`, in which case a cleanly-resolved cert becomes
                // VipPending until the next rebuild binds it at the real port.
                let grants = grants_for_source(&listener.source, cert_grants, ls_cert_grants);
                match resolve_listener_tls(
                    target.gw_name,
                    listener,
                    secrets,
                    grants,
                    builder,
                    bind_port,
                    !vip_pending,
                ) {
                    ListenerReadiness::Resolved if vip_pending => ListenerReadiness::VipPending,
                    ListenerReadiness::Resolved => ListenerReadiness::TlsTerminate,
                    other => other,
                }
            } else if listener.protocol == "HTTP" {
                // Cleartext HTTP: nothing to resolve, ready by default.
                ListenerReadiness::NotApplicable
            } else if listener.protocol == "TCP" {
                // Raw TCP proxy (GEP-1901 / TCPRoute): no cert, no SNI, no
                // passthrough-vs-terminate split — a TCP listener has exactly one mode.
                if vip_pending {
                    ListenerReadiness::VipPending
                } else {
                    ListenerReadiness::TcpProxy
                }
            } else if listener.protocol == "UDP" {
                // UDP datagram forwarder (GEP-2645 / UDPRoute): no cert, no SNI, no
                // passthrough-vs-terminate split — a UDP listener has exactly one mode.
                if vip_pending {
                    ListenerReadiness::VipPending
                } else {
                    ListenerReadiness::UdpProxy
                }
            } else if listener.protocol != "HTTPS" {
                // Not TLS (handled above), not HTTP, not TCP, not UDP, not HTTPS → a
                // protocol coxswain does not route. GatewayListenerUnsupportedProtocol
                // (#517): the listener is not Accepted and its owning Gateway
                // rolls up to `ListenersNotValid`.
                ListenerReadiness::UnsupportedProtocol {
                    message: format!(
                        "listener protocol {:?} is not supported; coxswain routes HTTP, HTTPS, TLS, TCP, and UDP",
                        listener.protocol
                    ),
                }
            } else {
                // HTTPS. Resolve refs FIRST so a terminal ref failure
                // (RefNotPermitted / InvalidCertificateRef) surfaces on
                // `ResolvedRefs` regardless of VIP allocation: a listener whose
                // cert ref is not permitted is invalid whether or not its VIP
                // internal port exists — and an invalid listener may never be
                // allocated one, so gating ref resolution on the port would strand
                // it at `Pending` forever. Only the cert *install* is deferred
                // while `vip_pending`; a cleanly-resolved cert with no port yet
                // becomes `VipPending` (Programmed deferred, per the kube-proxy NAT
                // race), and the next rebuild installs it at the real bind port.
                //
                // A ListenerSet listener's cross-namespace cert is permitted by a
                // `from.kind: ListenerSet` grant; a Gateway listener's by
                // `from.kind: Gateway` (GEP-1713). Pick the matching grant set.
                let grants = grants_for_source(&listener.source, cert_grants, ls_cert_grants);
                match resolve_listener_tls(
                    target.gw_name,
                    listener,
                    secrets,
                    grants,
                    builder,
                    bind_port,
                    !vip_pending,
                ) {
                    ListenerReadiness::Resolved if vip_pending => ListenerReadiness::VipPending,
                    other => other,
                }
            };
            let mut li = ListenerInfo::default();
            li.readiness = readiness;
            li.attached_routes = 0;
            li.hostname = listener.hostname.clone().unwrap_or_default();
            li.route_namespaces = listener.route_namespaces.clone();
            li.port = listener_port;
            li.internal_port = internal_port;
            li.conflict = listener.conflict.clone();
            map.insert(
                ListenerStatusKey {
                    source: listener.source.clone(),
                    name: listener.name.clone(),
                },
                li,
            );
        }

        let mut glh = GatewayListenerStatus::default();
        glh.listeners = map;
        glh
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_api::tests::*;
    use crate::reconciler::listener_merge::EffectiveListener;
    use crate::status::ListenerSource;

    // ── GEP-1713: ListenerSet cross-namespace cert grant selection ────────────

    /// A ListenerSet HTTPS listener whose `certificateRefs` points at a Secret in
    /// another namespace must be permitted by a `from.kind: ListenerSet` grant —
    /// NOT a `from.kind: Gateway` grant (which only permits Gateway listeners).
    #[test]
    fn listener_set_cross_namespace_cert_requires_listenerset_from_grant() {
        use crate::reconciler::listener_merge::{
            EffectiveCertRef, EffectiveListener, EffectiveTls,
        };
        use crate::status::ConflictReason;
        use coxswain_core::ownership::ObjectKey;
        use coxswain_core::reference_grants::ReferenceGrantKey;

        let ls_key = ObjectKey::new("team-a", "ls");
        let listener = EffectiveListener {
            source: ListenerSource::ListenerSet(ls_key.clone()),
            owning_namespace: "team-a".to_string(),
            name: "https".to_string(),
            port: 8443,
            protocol: "HTTPS".to_string(),
            hostname: None,
            tls: Some(EffectiveTls {
                passthrough: false,
                certificate_refs: vec![EffectiveCertRef {
                    group: None,
                    kind: None,
                    name: "cert".to_string(),
                    namespace: Some("certs".to_string()),
                }],
            }),
            route_namespaces: coxswain_core::listener_status::RouteNamespaceSet::All,
            allowed_route_kinds: vec![],
            conflict: ConflictReason::None,
        };

        let mut secrets_w = reflector::store::Writer::<Secret>::default();
        secrets_w.apply_watcher_event(&kube::runtime::watcher::Event::InitDone);
        let secrets = secrets_w.as_reader();

        // The grant lives in the WRONG set (Gateway-from). The cross-namespace
        // check must ignore it → RefNotPermitted.
        let grant: HashSet<ReferenceGrantKey> =
            std::iter::once(ReferenceGrantKey::specific("team-a", "certs", "cert")).collect();
        let empty = HashSet::new();
        // Provide a real internal_port so VipPending doesn't short-circuit cert validation.
        let ports = HashMap::from([(8443u16, 30001u16)]);
        let mut builder = PortTlsStoreBuilder::new();
        let health = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &ports,
            },
            &secrets,
            &grant, // cert_grants (Gateway-from) — must NOT permit an LS listener
            &empty, // ls_cert_grants empty
            &mut builder,
        );
        let outcome =
            &health.listeners[&ListenerStatusKey::listener_set(ls_key.clone(), "https")].readiness;
        assert!(
            matches!(outcome, ListenerReadiness::RefNotPermitted { .. }),
            "a Gateway-from grant must not permit a ListenerSet listener's cross-ns cert, got {outcome:?}"
        );

        // Same grant placed in the ListenerSet-from set → the cross-namespace
        // check passes; the (absent) Secret then fails as InvalidCertificateRef,
        // proving the grant was accepted (no longer RefNotPermitted).
        let mut builder2 = PortTlsStoreBuilder::new();
        let health2 = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &ports,
            },
            &secrets,
            &empty, // cert_grants empty
            &grant, // ls_cert_grants (ListenerSet-from) — permits the LS listener
            &mut builder2,
        );
        let outcome2 =
            &health2.listeners[&ListenerStatusKey::listener_set(ls_key, "https")].readiness;
        assert!(
            !matches!(outcome2, ListenerReadiness::RefNotPermitted { .. }),
            "a ListenerSet-from grant must permit the cross-ns cert ref, got {outcome2:?}"
        );
    }

    /// Conformance regression (`ListenerSetReferenceGrant`): a ListenerSet
    /// listener whose cross-namespace cert ref has NO permitting grant must be
    /// `RefNotPermitted` on `ResolvedRefs` **even when its VIP internal port is
    /// not allocated** (`internal_ports` empty → `internal_port = 0`). An invalid
    /// listener may never be allocated a port at all, so a VIP-pending short
    /// circuit here strands `ResolvedRefs` at `Pending "waiting for VIP port
    /// allocation"` forever instead of settling `RefNotPermitted` — the exact
    /// failure the conformance suite catches.
    #[test]
    fn listener_set_unpermitted_cross_ns_cert_is_refnotpermitted_without_vip() {
        use crate::reconciler::listener_merge::{
            EffectiveCertRef, EffectiveListener, EffectiveTls,
        };
        use crate::status::ConflictReason;
        use coxswain_core::ownership::ObjectKey;

        let ls_key = ObjectKey::new("team-a", "ls");
        let listener = EffectiveListener {
            source: ListenerSource::ListenerSet(ls_key.clone()),
            owning_namespace: "team-a".to_string(),
            name: "https".to_string(),
            port: 8443,
            protocol: "HTTPS".to_string(),
            hostname: None,
            tls: Some(EffectiveTls {
                passthrough: false,
                certificate_refs: vec![EffectiveCertRef {
                    group: None,
                    kind: None,
                    name: "cert".to_string(),
                    namespace: Some("certs".to_string()),
                }],
            }),
            route_namespaces: coxswain_core::listener_status::RouteNamespaceSet::All,
            allowed_route_kinds: vec![],
            conflict: ConflictReason::None,
        };
        let secrets = empty_secrets();
        let empty = HashSet::new();
        let mut builder = PortTlsStoreBuilder::new();
        let health = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &HashMap::new(), // no VIP → internal_port = 0
            },
            &secrets,
            &empty, // no cert_grants
            &empty, // no ls_cert_grants → the cross-ns ref is not permitted
            &mut builder,
        );
        let outcome =
            &health.listeners[&ListenerStatusKey::listener_set(ls_key, "https")].readiness;
        assert!(
            matches!(outcome, ListenerReadiness::RefNotPermitted { .. }),
            "an unpermitted cross-ns cert with no VIP port must be RefNotPermitted, not VipPending, got {outcome:?}"
        );
    }

    // ── VipPending: deferred readiness when internal_port is not yet allocated ──

    fn tls_listener(protocol: &str, passthrough: bool) -> EffectiveListener {
        use crate::reconciler::listener_merge::{
            EffectiveCertRef, EffectiveListener, EffectiveTls,
        };
        use crate::status::ConflictReason;
        EffectiveListener {
            source: ListenerSource::Gateway,
            owning_namespace: "default".to_string(),
            name: "tls".to_string(),
            port: 8443,
            protocol: protocol.to_string(),
            hostname: Some("tls.example.com".to_string()),
            tls: Some(EffectiveTls {
                passthrough,
                certificate_refs: if passthrough {
                    vec![]
                } else {
                    vec![EffectiveCertRef {
                        group: None,
                        kind: None,
                        name: "cert".to_string(),
                        namespace: None,
                    }]
                },
            }),
            route_namespaces: coxswain_core::listener_status::RouteNamespaceSet::All,
            allowed_route_kinds: vec![],
            conflict: ConflictReason::None,
        }
    }

    fn empty_secrets() -> kube::runtime::reflector::Store<Secret> {
        let mut w = reflector::store::Writer::<Secret>::default();
        w.apply_watcher_event(&kube::runtime::watcher::Event::InitDone);
        w.as_reader()
    }

    /// TLS/Passthrough with no VIP Service yet → VipPending (not TlsPassthrough).
    #[test]
    fn tls_passthrough_without_vip_is_pending() {
        let listener = tls_listener("TLS", true);
        let secrets = empty_secrets();
        let empty = HashSet::new();
        let mut builder = PortTlsStoreBuilder::new();
        let health = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &HashMap::new(), // no VIP yet
            },
            &secrets,
            &empty,
            &empty,
            &mut builder,
        );
        let outcome = &health.listeners[&ListenerStatusKey::gateway("tls")].readiness;
        assert!(
            matches!(outcome, ListenerReadiness::VipPending),
            "TLS/Passthrough with internal_port=0 must be VipPending, got {outcome:?}"
        );
    }

    /// TLS/Passthrough once VIP is allocated → TlsPassthrough (healthy).
    #[test]
    fn tls_passthrough_with_vip_is_healthy() {
        let listener = tls_listener("TLS", true);
        let secrets = empty_secrets();
        let empty = HashSet::new();
        let mut builder = PortTlsStoreBuilder::new();
        let health = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &std::collections::HashMap::from([(8443u16, 30001u16)]),
            },
            &secrets,
            &empty,
            &empty,
            &mut builder,
        );
        let outcome = &health.listeners[&ListenerStatusKey::gateway("tls")].readiness;
        assert!(
            matches!(outcome, ListenerReadiness::TlsPassthrough),
            "TLS/Passthrough with VIP allocated must be TlsPassthrough, got {outcome:?}"
        );
    }

    /// A minimal `kubernetes.io/tls` Secret that [`load_tls_cert`] accepts
    /// (correct type + `-----BEGIN` PEM markers; the leaf-parse failure it
    /// tolerates). Enough to drive the `Resolved` path in tests.
    fn resolvable_tls_secret(ns: &str, name: &str) -> Secret {
        use k8s_openapi::ByteString;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        let mut data = std::collections::BTreeMap::new();
        data.insert(
            "tls.crt".to_string(),
            ByteString(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".to_vec()),
        );
        data.insert(
            "tls.key".to_string(),
            ByteString(b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n".to_vec()),
        );
        Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            type_: Some("kubernetes.io/tls".to_string()),
            data: Some(data),
            ..Default::default()
        }
    }

    /// TLS/Terminate whose cert *resolves* but whose VIP port is not yet
    /// allocated → `VipPending`: `Programmed` is deferred until the internal port
    /// is known, and the cert is NOT installed at the wrong bind port (deferred
    /// to the next rebuild). This is the legitimate VIP-defer path.
    #[test]
    fn tls_terminate_resolved_cert_without_vip_defers_install() {
        let listener = tls_listener("TLS", false);
        let secrets = make_secret_store(vec![resolvable_tls_secret("default", "cert")]);
        let empty = HashSet::new();
        let mut builder = PortTlsStoreBuilder::new();
        let health = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &HashMap::new(), // no VIP yet
            },
            &secrets,
            &empty,
            &empty,
            &mut builder,
        );
        let outcome = &health.listeners[&ListenerStatusKey::gateway("tls")].readiness;
        assert!(
            matches!(outcome, ListenerReadiness::VipPending),
            "TLS/Terminate with a resolvable cert but no VIP port must be VipPending, got {outcome:?}"
        );
        // The cert install is deferred — nothing keyed at the (unknown) bind port.
        assert_eq!(builder.build().port_count(), 0);
    }

    /// A terminal cert-ref failure must surface on `ResolvedRefs` **independent of
    /// VIP allocation**: a TLS/Terminate listener whose Secret is missing is
    /// `InvalidCertificateRef` even with no internal port — the VIP-pending state
    /// must NOT mask it (regression: it used to short-circuit to `VipPending`).
    #[test]
    fn tls_terminate_missing_cert_is_invalid_even_without_vip() {
        let listener = tls_listener("TLS", false);
        let secrets = empty_secrets();
        let empty = HashSet::new();
        let mut builder = PortTlsStoreBuilder::new();
        let health = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &HashMap::new(), // no VIP yet
            },
            &secrets,
            &empty,
            &empty,
            &mut builder,
        );
        let outcome = &health.listeners[&ListenerStatusKey::gateway("tls")].readiness;
        assert!(
            matches!(outcome, ListenerReadiness::InvalidCertificateRef { .. }),
            "a missing cert must surface as InvalidCertificateRef regardless of VIP, got {outcome:?}"
        );
        assert_eq!(builder.build().port_count(), 0);
    }

    // ── L4 proxy listeners: TCPRoute (#505) / UDPRoute (#506) ─────────────────

    /// A raw L4 proxy listener (`protocol: TCP` or `protocol: UDP`): no TLS
    /// field, no hostname — routing is by listener port alone.
    fn l4_listener(protocol: &str) -> EffectiveListener {
        use crate::status::ConflictReason;
        EffectiveListener {
            source: ListenerSource::Gateway,
            owning_namespace: "default".to_string(),
            name: "l4-proxy".to_string(),
            port: 5000,
            protocol: protocol.to_string(),
            hostname: None,
            tls: None,
            route_namespaces: coxswain_core::listener_status::RouteNamespaceSet::All,
            allowed_route_kinds: vec![],
            conflict: ConflictReason::None,
        }
    }

    /// `protocol: TCP` with no VIP Service yet → VipPending, not TcpProxy.
    /// Regression for the class of bug this guards: a hardcoded protocol match
    /// in `reconcile_tls` that never gained a `"TCP"` arm would silently fall
    /// through to `UnsupportedProtocol`, exactly like the UDP gap below.
    #[test]
    fn tcp_proxy_without_vip_is_pending() {
        let listener = l4_listener("TCP");
        let secrets = empty_secrets();
        let empty = HashSet::new();
        let mut builder = PortTlsStoreBuilder::new();
        let health = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &HashMap::new(), // no VIP yet
            },
            &secrets,
            &empty,
            &empty,
            &mut builder,
        );
        let outcome = &health.listeners[&ListenerStatusKey::gateway("l4-proxy")].readiness;
        assert!(
            matches!(outcome, ListenerReadiness::VipPending),
            "TCP proxy with internal_port=0 must be VipPending, got {outcome:?}"
        );
    }

    /// `protocol: TCP` once VIP is allocated → TcpProxy (healthy), never
    /// `UnsupportedProtocol`.
    #[test]
    fn tcp_proxy_with_vip_is_healthy() {
        let listener = l4_listener("TCP");
        let secrets = empty_secrets();
        let empty = HashSet::new();
        let mut builder = PortTlsStoreBuilder::new();
        let health = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &HashMap::from([(5000u16, 30002u16)]),
            },
            &secrets,
            &empty,
            &empty,
            &mut builder,
        );
        let outcome = &health.listeners[&ListenerStatusKey::gateway("l4-proxy")].readiness;
        assert!(
            matches!(outcome, ListenerReadiness::TcpProxy),
            "TCP proxy with VIP allocated must be TcpProxy, got {outcome:?}"
        );
    }

    /// `protocol: UDP` with no VIP Service yet → VipPending, not UdpProxy.
    #[test]
    fn udp_proxy_without_vip_is_pending() {
        let listener = l4_listener("UDP");
        let secrets = empty_secrets();
        let empty = HashSet::new();
        let mut builder = PortTlsStoreBuilder::new();
        let health = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &HashMap::new(), // no VIP yet
            },
            &secrets,
            &empty,
            &empty,
            &mut builder,
        );
        let outcome = &health.listeners[&ListenerStatusKey::gateway("l4-proxy")].readiness;
        assert!(
            matches!(outcome, ListenerReadiness::VipPending),
            "UDP proxy with internal_port=0 must be VipPending, got {outcome:?}"
        );
    }

    /// `protocol: UDP` once VIP is allocated → UdpProxy (healthy), never
    /// `UnsupportedProtocol`. Regression for #506: `reconcile_tls` originally
    /// had no `"UDP"` arm, so every `protocol: UDP` listener fell through to
    /// `UnsupportedProtocol` even though `SUPPORTED_LISTENER_PROTOCOLS` and
    /// every other UDPRoute code path had already been updated — caught only
    /// by a live e2e run, not by any unit test.
    #[test]
    fn udp_proxy_with_vip_is_healthy() {
        let listener = l4_listener("UDP");
        let secrets = empty_secrets();
        let empty = HashSet::new();
        let mut builder = PortTlsStoreBuilder::new();
        let health = GatewayApiReconciler::reconcile_tls(
            &GatewayTlsTarget {
                gw_name: "gw",
                listeners: std::slice::from_ref(&listener),
                internal_ports: &HashMap::from([(5000u16, 30003u16)]),
            },
            &secrets,
            &empty,
            &empty,
            &mut builder,
        );
        let outcome = &health.listeners[&ListenerStatusKey::gateway("l4-proxy")].readiness;
        assert!(
            matches!(outcome, ListenerReadiness::UdpProxy),
            "UDP proxy with VIP allocated must be UdpProxy, got {outcome:?}"
        );
    }

    // ── Original path-matching tests (unchanged behaviour) ────────────────────

    #[test]
    fn reconcile_exact_path() {
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(vec![path_match(
                "/api",
                HttpRouteRulesMatchesPathType::Exact,
            )]),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route(80, "example.com", "/api", &ctx).is_some());
        assert!(table.route(80, "example.com", "/api/users", &ctx).is_none());
    }

    #[test]
    fn reconcile_prefix_path() {
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(vec![path_match(
                "/api",
                HttpRouteRulesMatchesPathType::PathPrefix,
            )]),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route(80, "example.com", "/api", &ctx).is_some());
        assert!(table.route(80, "example.com", "/api/users", &ctx).is_some());
    }

    #[test]
    fn reconcile_regex_path() {
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(vec![path_match(
                r"/item/\d+",
                HttpRouteRulesMatchesPathType::RegularExpression,
            )]),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route(80, "example.com", "/item/42", &ctx).is_some());
        assert!(table.route(80, "example.com", "/item/abc", &ctx).is_none());
    }

    #[test]
    fn reconcile_no_matches_defaults_to_root_prefix() {
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route(80, "example.com", "/anything", &ctx).is_some());
    }

    #[test]
    fn reconcile_skips_route_without_owned_parent() {
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route("default", &["example.com"], None, "svc");
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &owned(&[("other", "gw")]),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);

        assert!(table.route(80, "example.com", "/", &ctx).is_none());
    }

    // ── New predicate tests ────────────────────────────────────────────────────

    #[test]
    fn reconcile_header_exact_routes_to_correct_backend() {
        let store = endpoint_cache(vec![
            make_slice("default", "svc-a", "10.0.0.1"),
            make_slice("default", "svc-b", "10.0.0.2"),
        ]);

        // Two rules: same path, different header → different backends.
        let route = HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![
                    HttpRouteRules {
                        matches: Some(vec![header_exact_match("/", "x-tenant", "a")]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-a".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                    HttpRouteRules {
                        matches: Some(vec![header_exact_match("/", "x-tenant", "b")]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-b".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                ]),
            },
            ..Default::default()
        };

        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();

        let hdrs_a = headers_from(&[("x-tenant", "a")]);
        let hdrs_b = headers_from(&[("x-tenant", "b")]);
        let ctx_a = ctx_with(&Method::GET, &hdrs_a, None);
        let ctx_b = ctx_with(&Method::GET, &hdrs_b, None);

        assert_eq!(
            table.route(80, "example.com", "/", &ctx_a).unwrap().name(),
            "default/svc-a"
        );
        assert_eq!(
            table.route(80, "example.com", "/", &ctx_b).unwrap().name(),
            "default/svc-b"
        );
    }

    #[test]
    fn reconcile_header_regex_routes_to_correct_backend() {
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(vec![header_regex_match("/", "x-version", r"^v\d+$")]),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();

        let hdrs_ok = headers_from(&[("x-version", "v42")]);
        let hdrs_bad = headers_from(&[("x-version", "beta")]);
        let ctx_ok = ctx_with(&Method::GET, &hdrs_ok, None);
        let ctx_bad = ctx_with(&Method::GET, &hdrs_bad, None);

        assert!(table.route(80, "example.com", "/", &ctx_ok).is_some());
        assert!(table.route(80, "example.com", "/", &ctx_bad).is_none());
    }

    #[test]
    fn reconcile_method_routes_to_correct_backend() {
        let store = endpoint_cache(vec![
            make_slice("default", "svc-get", "10.0.0.1"),
            make_slice("default", "svc-post", "10.0.0.2"),
        ]);

        let route = HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![
                    HttpRouteRules {
                        matches: Some(vec![method_match("/", HttpRouteRulesMatchesMethod::Get)]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-get".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                    HttpRouteRules {
                        matches: Some(vec![method_match("/", HttpRouteRulesMatchesMethod::Post)]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-post".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                ]),
            },
            ..Default::default()
        };

        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();

        let h = HeaderMap::new();
        let ctx_get = ctx_with(&Method::GET, &h, None);
        let ctx_post = ctx_with(&Method::POST, &h, None);

        assert_eq!(
            table
                .route(80, "example.com", "/", &ctx_get)
                .unwrap()
                .name(),
            "default/svc-get"
        );
        assert_eq!(
            table
                .route(80, "example.com", "/", &ctx_post)
                .unwrap()
                .name(),
            "default/svc-post"
        );
    }

    #[test]
    fn reconcile_query_param_routes_to_correct_backend() {
        let store = endpoint_cache(vec![
            make_slice("default", "svc-v1", "10.0.0.1"),
            make_slice("default", "svc-v2", "10.0.0.2"),
        ]);

        let route = HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![
                    HttpRouteRules {
                        matches: Some(vec![query_exact_match("/", "version", "v1")]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-v1".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                    HttpRouteRules {
                        matches: Some(vec![query_exact_match("/", "version", "v2")]),
                        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                            name: "svc-v2".to_string(),
                            port: Some(80),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                ]),
            },
            ..Default::default()
        };

        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();

        let h = HeaderMap::new();
        let ctx_v1 = ctx_with(&Method::GET, &h, Some("version=v1"));
        let ctx_v2 = ctx_with(&Method::GET, &h, Some("version=v2"));

        assert_eq!(
            table.route(80, "example.com", "/", &ctx_v1).unwrap().name(),
            "default/svc-v1"
        );
        assert_eq!(
            table.route(80, "example.com", "/", &ctx_v2).unwrap().name(),
            "default/svc-v2"
        );
    }

    #[test]
    fn reconcile_invalid_regex_skips_match_entry() {
        let store = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
        let route = make_route(
            "default",
            &["example.com"],
            Some(vec![
                // invalid regex
                HttpRouteRulesMatches {
                    headers: Some(vec![HttpRouteRulesMatchesHeaders {
                        name: "x-bad".to_string(),
                        value: "[invalid".to_string(),
                        r#type: Some(HttpRouteRulesMatchesHeadersType::RegularExpression),
                    }]),
                    ..Default::default()
                },
                // valid path-only fallback
                path_match("/", HttpRouteRulesMatchesPathType::PathPrefix),
            ]),
            "svc",
        );
        let mut builder = RoutingTableBuilder::new();
        let grants = HashSet::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &grants,
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();

        let empty_hdrs = HeaderMap::new();
        let ctx = ctx_with(&Method::GET, &empty_hdrs, None);
        assert!(table.route(80, "example.com", "/", &ctx).is_some());
    }

    #[test]
    fn reconcile_header_name_dedup_keeps_first() {
        let m = HttpRouteRulesMatches {
            headers: Some(vec![
                HttpRouteRulesMatchesHeaders {
                    name: "X-Tenant".to_string(),
                    value: "first".to_string(),
                    r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
                },
                HttpRouteRulesMatchesHeaders {
                    name: "x-tenant".to_string(), // same header, different case
                    value: "second".to_string(),
                    r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
                },
            ]),
            ..Default::default()
        };
        let predicates = super::super::filters::build_predicates(&m).unwrap();
        assert_eq!(predicates.headers.len(), 1);
        match &predicates.headers[0].matcher {
            coxswain_core::routing::ValueMatch::Exact(v) => assert_eq!(v, "first"),
            _ => panic!("expected exact matcher"),
        }
    }

    // ── Weighted backendRefs (issue #17) ─────────────────────────────────────────

    fn weighted_route(ns: &str, refs: &[(&str, Option<i32>)]) -> HttpRoute {
        HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(
                        refs.iter()
                            .map(|(svc, w)| HttpRouteRulesBackendRefs {
                                name: svc.to_string(),
                                port: Some(80),
                                weight: *w,
                                ..Default::default()
                            })
                            .collect(),
                    ),
                    ..Default::default()
                }]),
            },
            ..Default::default()
        }
    }

    #[test]
    fn weighted_backends_80_20_split() {
        let a_ip = "10.0.0.1";
        let b_ip = "10.0.1.1";
        let store = endpoint_cache(vec![
            make_slice("default", "svc-a", a_ip),
            make_slice("default", "svc-b", b_ip),
        ]);
        let route = weighted_route("default", &[("svc-a", Some(4)), ("svc-b", Some(1))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let upstream = table.route(80, "example.com", "/", &ctx_get()).unwrap();

        let a: std::net::SocketAddr = format!("{a_ip}:80").parse().unwrap();
        let n = 1000usize;
        let mut a_count = 0usize;
        for _ in 0..n {
            let addr = upstream.next_endpoint().unwrap();
            if addr == a {
                a_count += 1;
            }
        }
        let ratio = a_count as f64 / n as f64;
        assert!(
            (0.75..=0.85).contains(&ratio),
            "backend-A ratio {ratio:.3} expected 0.75–0.85"
        );
    }

    #[test]
    fn zero_weight_backend_gets_no_traffic() {
        let a_ip = "10.0.0.1";
        let b_ip = "10.0.1.1";
        let store = endpoint_cache(vec![
            make_slice("default", "svc-a", a_ip),
            make_slice("default", "svc-b", b_ip),
        ]);
        let route = weighted_route("default", &[("svc-a", Some(0)), ("svc-b", Some(1))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let upstream = table.route(80, "example.com", "/", &ctx_get()).unwrap();

        let b: std::net::SocketAddr = format!("{b_ip}:80").parse().unwrap();
        for _ in 0..100 {
            assert_eq!(
                upstream.next_endpoint().unwrap(),
                b,
                "weight-0 backend should receive no traffic"
            );
        }
    }

    #[test]
    fn all_zero_weights_installs_error_route() {
        let store = endpoint_cache(vec![
            make_slice("default", "svc-a", "10.0.0.1"),
            make_slice("default", "svc-b", "10.0.1.1"),
        ]);
        let route = weighted_route("default", &[("svc-a", Some(0)), ("svc-b", Some(0))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        // All weights zero → empty upstream → error_status = Some(500) → RouteOutcome::Error
        let outcome = table.find(80, "example.com", "/", &ctx_get());
        assert!(
            matches!(outcome, coxswain_core::routing::RouteOutcome::Error(500)),
            "all-zero-weight rule must resolve to Error(500)"
        );
    }

    #[test]
    fn valid_service_zero_endpoints_installs_503() {
        // The referenced Service exists but has no ready endpoints (e.g. scaled
        // to zero). HTTPRoute spec: this SHOULD return 503, not 500.
        let svc = k8s_openapi::api::core::v1::Service {
            metadata: ObjectMeta {
                name: Some("svc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let route = weighted_route("default", &[("svc", Some(1))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &endpoint_cache(vec![]),
            &crate::tests::fixtures::make_svc_store(vec![svc]),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            matches!(
                table.find(80, "example.com", "/", &ctx_get()),
                coxswain_core::routing::RouteOutcome::Error(503)
            ),
            "valid Service with zero ready endpoints must resolve to 503"
        );
    }

    #[test]
    fn missing_service_installs_500() {
        // No such Service in the store → invalid backendRef → MUST return 500.
        let route = weighted_route("default", &[("svc", Some(1))]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &endpoint_cache(vec![]),
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            matches!(
                table.find(80, "example.com", "/", &ctx_get()),
                coxswain_core::routing::RouteOutcome::Error(500)
            ),
            "missing Service backendRef must resolve to 500"
        );
    }

    /// A route whose single rule matches `/` on `example.com` but carries the
    /// given `backend_refs` verbatim — used to exercise the omitted vs empty
    /// `backendRefs` cases (`HTTPRouteNoBackendRefs`).
    fn route_with_backend_refs(
        ns: &str,
        backend_refs: Option<Vec<HttpRouteRulesBackendRefs>>,
    ) -> HttpRoute {
        HttpRoute {
            metadata: ObjectMeta {
                name: Some("route".to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: default_parents(),
                hostnames: Some(vec!["example.com".to_string()]),
                rules: Some(vec![HttpRouteRules {
                    backend_refs,
                    ..Default::default()
                }]),
            },
            ..Default::default()
        }
    }

    /// Reconcile `route` against empty stores and return the built routing table.
    fn reconcile_route_only(route: &HttpRoute) -> coxswain_core::routing::GatewayRoutingTable {
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            route,
            &endpoint_cache(vec![]),
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        builder.build().unwrap()
    }

    #[test]
    fn omitted_backend_refs_installs_500() {
        // Rule with `backendRefs` entirely omitted (None). Gateway API
        // `HTTPRouteNoBackendRefs`: must route with a distinct 500, not fall
        // through to a 404 (which is what skipping the rule would produce).
        let table = reconcile_route_only(&route_with_backend_refs("default", None));
        assert!(
            matches!(
                table.find(80, "example.com", "/", &ctx_get()),
                coxswain_core::routing::RouteOutcome::Error(500)
            ),
            "rule with omitted backendRefs must resolve to Error(500), not NoPath/404"
        );
    }

    #[test]
    fn empty_backend_refs_installs_500() {
        // Rule with `backendRefs: []` (present but empty) — same 500 requirement
        // as the omitted case.
        let table = reconcile_route_only(&route_with_backend_refs("default", Some(vec![])));
        assert!(
            matches!(
                table.find(80, "example.com", "/", &ctx_get()),
                coxswain_core::routing::RouteOutcome::Error(500)
            ),
            "rule with empty backendRefs must resolve to Error(500), not NoPath/404"
        );
    }

    #[test]
    fn absent_weight_defaults_to_1() {
        let a_ip = "10.0.0.1";
        let b_ip = "10.0.1.1";
        let store = endpoint_cache(vec![
            make_slice("default", "svc-a", a_ip),
            make_slice("default", "svc-b", b_ip),
        ]);
        // weight field is None — should default to 1 each → roughly equal split
        let route = weighted_route("default", &[("svc-a", None), ("svc-b", None)]);
        let mut builder = RoutingTableBuilder::new();
        GatewayApiReconciler::reconcile(
            &route,
            &store,
            &empty_svc_store(),
            &default_owned(),
            &HashSet::new(),
            crate::gateway_api::RouteResolution {
                listener_info: &no_listener_info(),
                policy_index: &HashMap::new(),
                backend_policy_index: &HashMap::new(),
                rate_limits: &empty_rate_limit_store(),
                retry_policies: &empty_retry_policy_store(),
                path_rewrites: &empty_path_rewrite_store(),
                ip_access: &empty_ip_access_store(),
                basic_auths: &empty_basic_auth_store(),
                external_auths: &empty_external_auth_store(),
                external_auth_gateway_index: &std::collections::HashMap::new(),
                jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                auth_secrets: &empty_secret_store(),
                basic_auth_secret_grants: &std::collections::HashSet::new(),
                request_size_limits: &empty_request_size_limit_store(),
                compressions: &empty_compression_store(),
                backend_client_certs: &HashMap::new(),
                backend_client_cert_failures: &HashSet::new(),
            },
            &mut builder,
        );
        let table = builder.build().unwrap();
        let upstream = table.route(80, "example.com", "/", &ctx_get()).unwrap();

        let a: std::net::SocketAddr = format!("{a_ip}:80").parse().unwrap();
        let b: std::net::SocketAddr = format!("{b_ip}:80").parse().unwrap();
        let results: Vec<_> = (0..4).map(|_| upstream.next_endpoint().unwrap()).collect();
        // With equal weights, slots = [0, 1]; cycling: a, b, a, b
        assert_eq!(results, [a, b, a, b]);
    }

    // ── route_fingerprint (#511) ──────────────────────────────────────────────

    mod route_fingerprint_tests {
        use super::*;
        use crate::gw_types::v::httproutes::HttpRouteRulesFiltersExtensionRef;
        use crate::tests::fixtures::{make_rate_limit_store, make_svc_store};
        use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
        use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

        fn rate_limit_ext_ref(name: &str) -> HttpRouteRulesFilters {
            HttpRouteRulesFilters {
                r#type: HttpRouteRulesFiltersType::ExtensionRef,
                extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                    group: "gateway.coxswain-labs.dev".to_string(),
                    kind: "RateLimit".to_string(),
                    name: name.to_string(),
                }),
                ..Default::default()
            }
        }

        fn rate_limit_cr(ns: &str, name: &str, resource_version: &str) -> RateLimit {
            let yaml = format!(
                "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
                 kind: RateLimit\n\
                 metadata:\n  name: {name}\n  namespace: {ns}\n  resourceVersion: \"{resource_version}\"\n\
                 spec:\n  requestsPerSecond: 1\n",
            );
            serde_yaml::from_str(&yaml).expect("valid RateLimit")
        }

        fn service(ns: &str, name: &str, resource_version: &str) -> Service {
            Service {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    namespace: Some(ns.to_string()),
                    resource_version: Some(resource_version.to_string()),
                    ..Default::default()
                },
                spec: Some(ServiceSpec {
                    ports: Some(vec![ServicePort {
                        port: 80,
                        target_port: Some(IntOrString::Int(8080)),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            }
        }

        /// Builds a `RouteResolution` with every store empty except
        /// `rate_limits` (passed in by the caller); mirrors the
        /// exhaustive-field construction pattern used throughout this file's
        /// other tests. Every non-`rate_limits` field is a fresh, locally-owned
        /// empty store/map — cheap, and avoids fighting borrow lifetimes with
        /// a shared/static instance.
        macro_rules! resolution_with_rate_limits {
            ($rate_limits:expr) => {
                RouteResolution {
                    listener_info: &no_listener_info(),
                    policy_index: &HashMap::new(),
                    backend_policy_index: &HashMap::new(),
                    rate_limits: $rate_limits,
                    retry_policies: &empty_retry_policy_store(),
                    path_rewrites: &empty_path_rewrite_store(),
                    ip_access: &empty_ip_access_store(),
                    basic_auths: &empty_basic_auth_store(),
                    external_auths: &empty_external_auth_store(),
                    external_auth_gateway_index: &HashMap::new(),
                    jwt_auths: &crate::tests::fixtures::empty_jwt_auth_store(),
                    jwks_cache: &crate::tests::fixtures::empty_jwks_cache(),
                    auth_secrets: &empty_secret_store(),
                    basic_auth_secret_grants: &HashSet::new(),
                    request_size_limits: &empty_request_size_limit_store(),
                    compressions: &empty_compression_store(),
                    backend_client_certs: &HashMap::new(),
                    backend_client_cert_failures: &HashSet::new(),
                }
            };
        }

        #[test]
        fn deterministic_for_identical_inputs() {
            let route = make_route("default", &["example.com"], None, "svc");
            let cache = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
            let svcs = empty_svc_store();
            let rls = empty_rate_limit_store();
            let resolution = resolution_with_rate_limits!(&rls);
            let a = route_fingerprint(&route, &cache, &svcs, &resolution);
            let b = route_fingerprint(&route, &cache, &svcs, &resolution);
            assert_eq!(a, b);
        }

        #[test]
        fn changes_when_route_resource_version_changes() {
            let mut route = make_route("default", &["example.com"], None, "svc");
            let cache = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
            let svcs = empty_svc_store();
            let rls = empty_rate_limit_store();
            let resolution = resolution_with_rate_limits!(&rls);
            let before = route_fingerprint(&route, &cache, &svcs, &resolution);

            route.metadata.resource_version = Some("2".to_string());
            let after = route_fingerprint(&route, &cache, &svcs, &resolution);
            assert_ne!(before, after);
        }

        #[test]
        fn changes_when_referenced_rate_limit_cr_changes_independent_of_route() {
            let mut route = make_route("default", &["example.com"], None, "svc");
            route.spec.rules.as_mut().unwrap()[0].filters = Some(vec![rate_limit_ext_ref("rl")]);
            // The route's own resourceVersion never changes across the two
            // resolutions below — only the RateLimit CR it references does.
            route.metadata.resource_version = Some("1".to_string());
            let cache = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
            let svcs = empty_svc_store();

            let rls_v1 = make_rate_limit_store(vec![rate_limit_cr("default", "rl", "1")]);
            let before = route_fingerprint(
                &route,
                &cache,
                &svcs,
                &resolution_with_rate_limits!(&rls_v1),
            );

            let rls_v2 = make_rate_limit_store(vec![rate_limit_cr("default", "rl", "2")]);
            let after = route_fingerprint(
                &route,
                &cache,
                &svcs,
                &resolution_with_rate_limits!(&rls_v2),
            );

            assert_ne!(
                before, after,
                "editing the referenced RateLimit CR must move the fingerprint even though the route itself didn't change"
            );
        }

        #[test]
        fn unaffected_by_an_unrelated_rate_limit_cr_changing() {
            let mut route = make_route("default", &["example.com"], None, "svc");
            route.spec.rules.as_mut().unwrap()[0].filters = Some(vec![rate_limit_ext_ref("rl-a")]);
            route.metadata.resource_version = Some("1".to_string());
            let cache = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);
            let svcs = empty_svc_store();

            let rls_before = make_rate_limit_store(vec![
                rate_limit_cr("default", "rl-a", "1"),
                rate_limit_cr("default", "rl-b", "1"),
            ]);
            let before = route_fingerprint(
                &route,
                &cache,
                &svcs,
                &resolution_with_rate_limits!(&rls_before),
            );

            // rl-b (not referenced by this route) changes; rl-a is untouched.
            let rls_after = make_rate_limit_store(vec![
                rate_limit_cr("default", "rl-a", "1"),
                rate_limit_cr("default", "rl-b", "2"),
            ]);
            let after = route_fingerprint(
                &route,
                &cache,
                &svcs,
                &resolution_with_rate_limits!(&rls_after),
            );

            assert_eq!(
                before, after,
                "an unreferenced CR changing must not move this route's fingerprint"
            );
        }

        #[test]
        fn changes_when_backend_service_port_mapping_changes() {
            let route = make_route("default", &["example.com"], None, "svc");
            let rls = empty_rate_limit_store();
            let cache = endpoint_cache(vec![make_slice("default", "svc", "10.0.0.1")]);

            let svcs_v1 = make_svc_store(vec![service("default", "svc", "1")]);
            let before = route_fingerprint(
                &route,
                &cache,
                &svcs_v1,
                &resolution_with_rate_limits!(&rls),
            );

            let svcs_v2 = make_svc_store(vec![service("default", "svc", "2")]);
            let after = route_fingerprint(
                &route,
                &cache,
                &svcs_v2,
                &resolution_with_rate_limits!(&rls),
            );

            assert_ne!(
                before, after,
                "a backend Service edit must move the fingerprint via the EndpointCache, \
                 independent of the route's own spec"
            );
        }

        #[test]
        fn unaffected_by_an_unrelated_services_endpoints() {
            let route = make_route("default", &["example.com"], None, "svc");
            let rls = empty_rate_limit_store();
            let svcs = empty_svc_store();

            let cache_before = endpoint_cache(vec![
                make_slice("default", "svc", "10.0.0.1"),
                make_slice("default", "other-svc", "10.0.1.1"),
            ]);
            let before = route_fingerprint(
                &route,
                &cache_before,
                &svcs,
                &resolution_with_rate_limits!(&rls),
            );

            // other-svc's endpoint changes; svc's slice (and its EndpointSlice
            // object name/resourceVersion) is untouched.
            let cache_after = endpoint_cache(vec![
                make_slice("default", "svc", "10.0.0.1"),
                make_slice("default", "other-svc", "10.0.1.2"),
            ]);
            let after = route_fingerprint(
                &route,
                &cache_after,
                &svcs,
                &resolution_with_rate_limits!(&rls),
            );

            assert_eq!(
                before, after,
                "an unreferenced service's endpoint churn must not move this route's fingerprint"
            );
        }
    }
}
