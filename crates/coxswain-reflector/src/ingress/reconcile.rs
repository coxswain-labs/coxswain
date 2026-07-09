//! Core Ingress reconciliation: maps rules to routing-table entries.

use super::IngressReconciler;
use super::annotations::{AnnotationIssue, IngressAnnotations};
use super::backend::resolve_backend_port;
use super::class::{ResolvedClassParams, claimed_ingress_class};
use super::ports::IngressPorts;
use super::reconcile_helpers::{
    build_ingress_backend_group, prepend_ssl_redirect, resolve_basic_auth_config,
    resolve_compression_config, resolve_ext_auth_config, resolve_host_builder,
    resolve_ip_access_control_config, resolve_jwt_auth_config, resolve_mirror_filter,
    resolve_rate_limit_config, resolve_retry_config,
};
use crate::endpoints;
use crate::k8s_utils::metadata_created_at;
use coxswain_core::crd::{
    Compression, CoxswainExternalAuth, IpAccessControl, RateLimit, RetryPolicy,
};
use coxswain_core::ownership::ObjectKey;
use coxswain_core::routing::{
    BackendGroup, CircuitBreakerConfig, FilterAction, IngressAuthConfig,
    IngressRoutingTableBuilder, PathModifier, RouteEntry, compile_path_regex,
};
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::reflector;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// The IngressClass-ownership context threaded into [`IngressReconciler::reconcile`].
///
/// Groups the three class-derived inputs a reconcile pass needs — the owned
/// class names, the owned default class (if any), and per-class parameters
/// resolved from `IngressClass.spec.parameters` (#190, #279) — so the
/// reconcile entry point stays under the workspace argument-count limit and so
/// callers thread one borrow instead of three.
#[non_exhaustive]
pub struct IngressClassContext<'a> {
    owned: &'a HashSet<String>,
    default: Option<&'a str>,
    params: &'a HashMap<String, ResolvedClassParams>,
}

impl<'a> IngressClassContext<'a> {
    /// Bundle the owned class names, owned default class, and per-class
    /// parameters for a single reconcile pass.
    #[must_use]
    pub(crate) fn new(
        owned: &'a HashSet<String>,
        default: Option<&'a str>,
        params: &'a HashMap<String, ResolvedClassParams>,
    ) -> Self {
        Self {
            owned,
            default,
            params,
        }
    }
}

/// The `namespace/name`-CRD-reference stores for the annotation family that
/// converges to a CR reference (#548): `Compression` (#550), `RetryPolicy`
/// (#551), `RateLimit` (#552), and `IpAccessControl` (#553). Grouped into its
/// own struct rather than four more parameters on
/// [`IngressExtensionStores::new`]. `CoxswainBackendPolicy` (#554) does *not*
/// join this family: it is a GEP-713 direct-attachment policy targeting the
/// backend `Service` itself, not referenced by a `namespace/name` annotation —
/// see [`IngressExtensionStores::backend_policy_index`].
#[non_exhaustive]
pub struct IngressCrRefStores<'a> {
    pub(crate) compressions: &'a reflector::Store<Compression>,
    pub(crate) retry_policies: &'a reflector::Store<RetryPolicy>,
    pub(crate) rate_limits: &'a reflector::Store<RateLimit>,
    pub(crate) ip_access_controls: &'a reflector::Store<IpAccessControl>,
}

impl<'a> IngressCrRefStores<'a> {
    /// Bundle the converged-CR-reference stores for a single reconcile pass.
    #[must_use]
    pub fn new(
        compressions: &'a reflector::Store<Compression>,
        retry_policies: &'a reflector::Store<RetryPolicy>,
        rate_limits: &'a reflector::Store<RateLimit>,
        ip_access_controls: &'a reflector::Store<IpAccessControl>,
    ) -> Self {
        Self {
            compressions,
            retry_policies,
            rate_limits,
            ip_access_controls,
        }
    }
}

/// The extension-CRD stores threaded into [`IngressReconciler::reconcile`].
///
/// Groups the label-scoped htpasswd Secret store (`auth-basic-secret`) with
/// the `CoxswainExternalAuth` CR store (`ext-auth`, #549), the `JwtAuth` CR
/// store and JWKS cache (`auth-jwt`, #441), the backend `ReferenceGrant` set
/// (needed to resolve a `CoxswainExternalAuth` CR's cross-namespace
/// `backendRef`), the converged-CR-reference stores ([`IngressCrRefStores`]),
/// and the per-Service `CoxswainBackendPolicy` index
/// (`backend_policy_index`, #554) — so `reconcile` stays under the workspace
/// argument-count limit. Not auth-specific despite the auth-heavy history —
/// every extension-CRD input an Ingress reconcile pass needs lands here.
#[non_exhaustive]
pub struct IngressExtensionStores<'a> {
    pub(crate) auth_secrets: &'a reflector::Store<Secret>,
    pub(crate) external_auths: &'a reflector::Store<CoxswainExternalAuth>,
    pub(crate) jwt_auths: &'a reflector::Store<coxswain_core::crd::JwtAuth>,
    pub(crate) jwks_cache: &'a crate::jwks::SharedJwksCache,
    pub(crate) backend_grants: &'a crate::reference_grants::GrantSet,
    pub(crate) compressions: &'a reflector::Store<Compression>,
    pub(crate) retry_policies: &'a reflector::Store<RetryPolicy>,
    pub(crate) rate_limits: &'a reflector::Store<RateLimit>,
    pub(crate) ip_access_controls: &'a reflector::Store<IpAccessControl>,
    /// Per-Service connection policy resolved from `CoxswainBackendPolicy`
    /// (#554). Looked up per backend Service — a single Ingress can route
    /// different paths to different Services, each with its own policy —
    /// unlike the CR-reference stores above, which are looked up by an
    /// annotation-carried name.
    pub(crate) backend_policy_index: &'a crate::gateway_api::BackendPolicyIndex,
}

impl<'a> IngressExtensionStores<'a> {
    /// Bundle the extension-CRD stores for a single reconcile pass.
    #[must_use]
    pub fn new(
        auth_secrets: &'a reflector::Store<Secret>,
        external_auths: &'a reflector::Store<CoxswainExternalAuth>,
        jwt_auths: &'a reflector::Store<coxswain_core::crd::JwtAuth>,
        jwks_cache: &'a crate::jwks::SharedJwksCache,
        backend_grants: &'a crate::reference_grants::GrantSet,
        cr_refs: IngressCrRefStores<'a>,
        backend_policy_index: &'a crate::gateway_api::BackendPolicyIndex,
    ) -> Self {
        Self {
            auth_secrets,
            external_auths,
            jwt_auths,
            jwks_cache,
            backend_grants,
            compressions: cr_refs.compressions,
            retry_policies: cr_refs.retry_policies,
            rate_limits: cr_refs.rate_limits,
            ip_access_controls: cr_refs.ip_access_controls,
            backend_policy_index,
        }
    }
}

impl IngressReconciler {
    /// Skips the Ingress when it does not reference an owned IngressClass.
    /// When `owned_default_class` is `Some`, an Ingress with neither
    /// `spec.ingressClassName` nor the legacy annotation is also claimed.
    /// Never queries the API server.
    ///
    /// Routes are inserted on `http_port` and `https_port` (whichever are `Some`).
    /// When both are `None` the Ingress is skipped with a warning.
    ///
    /// `auth` bundles the label-scoped Secret store
    /// (`ingress.coxswain-labs.dev/auth-basic=true`, used to resolve
    /// `auth-basic-secret` into an htpasswd credential list) with the `JwtAuth`
    /// CR store and JWKS cache (used to resolve `auth-jwt`, #441).
    /// Returns the annotation diagnostics collected during parsing so the caller
    /// can forward them as Kubernetes Warning Events on the Ingress object.
    /// An empty vec means all annotations were valid (or no annotations were set).
    #[must_use = "caller should forward annotation issues as Kubernetes Events"]
    pub fn reconcile(
        ingress: &Ingress,
        slices: &reflector::Store<EndpointSlice>,
        services: &reflector::Store<Service>,
        classes: &IngressClassContext<'_>,
        ports: IngressPorts,
        builder: &mut IngressRoutingTableBuilder,
        auth_stores: &IngressExtensionStores<'_>,
    ) -> Vec<AnnotationIssue> {
        let claimed_class = claimed_ingress_class(ingress);

        // The class this Ingress is served under: its explicit class, or the
        // owned default class when unclassified. Drives both the ownership gate
        // and the per-class annotation-defaults lookup below.
        let effective_class = match claimed_class {
            None => match classes.default {
                Some(default) => default,
                None => {
                    tracing::debug!(name = ?ingress.metadata.name, "Skipping Ingress — no ingressClassName or annotation");
                    return vec![];
                }
            },
            Some(class) if !classes.owned.contains(class) => {
                tracing::debug!(name = ?ingress.metadata.name, %class, "Skipping Ingress — class not owned by this controller");
                return vec![];
            }
            Some(class) => class,
        };

        // Capture the HTTP listener port before shadowing `ports` as a Vec.
        // Used by ssl-redirect to scope the redirect filter to the HTTP port only.
        let http_port = ports.http;
        let ports: Vec<u16> = [ports.http, ports.https].into_iter().flatten().collect();
        if ports.is_empty() {
            tracing::warn!(
                name = ?ingress.metadata.name,
                "No HTTP or HTTPS listener port configured — skipping Ingress routes"
            );
            return vec![];
        }

        let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");
        let ingress_name = ingress.metadata.name.as_deref().unwrap_or("unknown");
        let route_id = format!("{ns}/{ingress_name}");
        let created_at = metadata_created_at(&ingress.metadata);
        let spec = ingress.spec.as_ref();
        let rules = spec.and_then(|s| s.rules.as_deref()).unwrap_or(&[]);

        // Resolve the per-class params for this Ingress's effective class (#190, #279).
        let resolved_params = classes.params.get(effective_class);

        // Layer class-level annotation defaults (#190) under the Ingress's own
        // annotations: a key set on the Ingress wins per-key; unset keys inherit
        // the class default. No (or empty) class default → keep the existing
        // zero-allocation path on the Ingress's own annotation map.
        let merged_annotations = resolved_params
            .map(|p| &p.default_annotations)
            .filter(|defaults| !defaults.is_empty())
            .map(|defaults| {
                let mut effective = defaults.clone();
                if let Some(own) = ingress.metadata.annotations.as_ref() {
                    effective.extend(own.clone());
                }
                effective
            });

        // Per-class access-log override (#279): propagated directly from
        // CoxswainIngressClassParameters.spec.accessLog. Class-scoped only,
        // mirroring Istio's Telemetry granularity.
        let class_access_log_enabled = resolved_params.and_then(|p| p.access_log_enabled);

        // Parse ingress.coxswain-labs.dev/* annotations once per Ingress.
        // Invalid values WARN + use default; the Ingress is never dropped.
        let (ann, mut annotation_issues) = IngressAnnotations::parse(
            merged_annotations
                .as_ref()
                .or(ingress.metadata.annotations.as_ref()),
            &route_id,
        );

        // Build the Ingress-wide base filter list once.  Header modifiers and the generic
        // redirect are port-independent and go here; the rewrite filter is appended
        // per-path below because regex paths rebuild it against their own compiled pattern.
        let mut base_filters: Vec<FilterAction> = Vec::new();
        if let Some(hm) = ann.request_headers.clone() {
            base_filters.push(FilterAction::RequestHeaderModifier(hm));
        }
        if let Some(hm) = ann.response_headers.clone() {
            base_filters.push(FilterAction::ResponseHeaderModifier(hm));
        }
        if let Some(redirect) = ann.redirect.clone() {
            base_filters.push(redirect);
        }

        // Mirror target (#283): resolve the annotation's service ref to a BackendGroup.
        // Uses the same endpoint-resolution path as the primary backend. An absent/invalid
        // Service WARNs and skips the mirror filter — the Ingress keeps serving normally.
        // An empty-endpoint group is installed (proxy WARNs on dispatch and drops the mirror).
        if let Some(filter) = ann
            .mirror_target
            .as_ref()
            .and_then(|m| resolve_mirror_filter(m, ns, &route_id, slices, services))
        {
            base_filters.push(filter);
        }

        // ssl-redirect fires only on the HTTP listener; it is suppressed when an explicit
        // redirect-* annotation is already present (redirect-* takes precedence).
        let needs_ssl_redirect = ann.ssl_redirect && ann.redirect.is_none();

        // Build the source-IP allow/deny lists once and share the same Arcs across
        // every route entry of this Ingress — cloning them onto each path is then a
        // refcount bump. Resolved via the same `resolve_spec` the HTTPRoute/GRPCRoute
        // ExtensionRef path uses (#553); a missing IpAccessControl CR fails open (no
        // filtering), unlike the auth resolvers below.
        let (allow_source_range, deny_source_range) = resolve_ip_access_control_config(
            ann.ip_access_control.as_ref(),
            auth_stores.ip_access_controls,
            &route_id,
        );
        // Resolve auth annotations once per Ingress; share one Arc chain across
        // every path. `ext-auth` (#549), `auth-basic-secret` (#24), and
        // `auth-jwt` (#441) are independently additive — every configured
        // check must pass, mirroring the HTTPRoute ExtensionRef chain (#23).
        let basic_auth = resolve_basic_auth_config(
            ann.auth_basic.as_ref(),
            auth_stores.auth_secrets,
            &route_id,
            ns,
            &mut annotation_issues,
        );
        let ext_auth = resolve_ext_auth_config(
            ann.auth_ext.as_ref(),
            auth_stores.external_auths,
            services,
            slices,
            auth_stores.backend_grants,
            &route_id,
        );
        let jwt_auth = resolve_jwt_auth_config(
            ann.auth_jwt.as_ref(),
            auth_stores.jwt_auths,
            auth_stores.jwks_cache,
            &route_id,
        );
        let auth: Arc<[Arc<IngressAuthConfig>]> = [basic_auth, ext_auth, jwt_auth]
            .into_iter()
            .flatten()
            .map(Arc::new)
            .collect();
        // Build the compression config once and share one Arc across every route entry.
        // Resolved via the same `resolve_spec` the HTTPRoute ExtensionRef path uses
        // (#550); a missing/no-op Compression CR fails open (no compression), unlike
        // the auth resolvers above.
        let compression = resolve_compression_config(
            ann.compression.as_ref(),
            auth_stores.compressions,
            &route_id,
        );
        // Build the retry policy once and share it across every backend group.
        // Resolved via the same `resolve_spec` the HTTPRoute ExtensionRef path uses
        // (#551); a missing RetryPolicy CR fails open (no retries), unlike the auth
        // resolvers above.
        let retries =
            resolve_retry_config(ann.retry.as_ref(), auth_stores.retry_policies, &route_id);
        // Build the rate-limit config once and share one Arc across every route entry.
        // Resolved via the same `resolve_spec` the HTTPRoute/GRPCRoute ExtensionRef path
        // uses (#552); a missing RateLimit CR fails open (no rate limiting), unlike the
        // auth resolvers above. `has_auth` mirrors the auth-family checks above and
        // suppresses the header-keying bypass-risk advisory (#411) when an auth check
        // is also configured on this Ingress.
        let has_auth = ann.auth_ext.is_some() || ann.auth_basic.is_some();
        let rate_limit = resolve_rate_limit_config(
            ann.rate_limit.as_ref(),
            auth_stores.rate_limits,
            &route_id,
            has_auth,
            &mut annotation_issues,
        );
        // Build the trusted-proxy forwarded-IP config once and share one Arc across every path.
        let forwarded_for = ann.forwarded_for.clone().map(Arc::new);

        // One RouteEntry builder shared by all three insertion sites — rule path,
        // ssl-redirect variant, and spec.defaultBackend. Centralising the chain
        // guarantees every per-route knob is applied uniformly; the defaultBackend
        // path previously hand-rolled the chain and silently dropped knobs (#397).
        // Captures the Ingress-wide knobs by reference; callers pass the per-entry
        // group, path pattern, metric id, filter list, and circuit breaker. The
        // circuit breaker is per-call, not captured, because it comes from the
        // `CoxswainBackendPolicy` attached to *this path's* backend Service (#554)
        // — a single Ingress can route different paths to different Services,
        // each with its own policy.
        let build_route_entry =
            |group: Arc<BackendGroup>,
             path_pattern: Arc<str>,
             metric_route_id: Arc<str>,
             filters: Vec<FilterAction>,
             circuit_breaker: Option<Arc<CircuitBreakerConfig>>| {
                RouteEntry::path_only(group, route_id.clone(), created_at)
                    .with_path_pattern(path_pattern)
                    .with_metric_route_id(metric_route_id)
                    .with_timeouts(ann.timeouts.clone())
                    .with_filter_actions(filters)
                    .with_max_body_size(ann.max_body_size)
                    .with_allow_source_range(allow_source_range.clone())
                    .with_deny_source_range(deny_source_range.clone())
                    .with_access_log_enabled(class_access_log_enabled)
                    .with_rate_limit(rate_limit.clone())
                    .with_auth_chain(auth.clone())
                    .with_compression(compression.clone())
                    .with_forwarded_for(forwarded_for.clone())
                    .with_circuit_breaker(circuit_breaker.clone())
            };

        tracing::debug!(name = ?ingress.metadata.name, ns, rules = rules.len(), "Reconciling Ingress");

        for (rule_index, rule) in rules.iter().enumerate() {
            let http = match rule.http.as_ref() {
                Some(h) => h,
                None => continue,
            };

            for (path_index, path_rule) in http.paths.iter().enumerate() {
                let svc = match path_rule.backend.service.as_ref() {
                    Some(s) => s,
                    None => {
                        if let Some(resource) = path_rule.backend.resource.as_ref() {
                            tracing::warn!(
                                ingress = %route_id,
                                path = ?path_rule.path,
                                api_group = ?resource.api_group,
                                kind = %resource.kind,
                                name = %resource.name,
                                "Ingress path backend uses Resource type — only Service backends are supported; skipping path"
                            );
                        }
                        continue;
                    }
                };
                let port = match resolve_backend_port(ns, svc, services) {
                    Some(p) => p,
                    None => continue,
                };

                let resolved = endpoints::resolve(ns, &svc.name, port, slices, services);
                // A backend that resolves but has zero ready endpoints is kept as
                // a dead route that returns 503 — NOT pruned. Pruning would let
                // the path fall through to a broader route (a catch-all "/", or
                // another Ingress claiming the same host) and silently serve the
                // wrong backend, and it would hide the outage from operators.
                // This mirrors the Gateway-API path, which installs an error
                // route for the same case. (503 = Service Unavailable, the
                // ingress-controller convention for "no ready upstreams";
                // unresolvable backends — missing Service/port — are still
                // skipped above, before this point.)
                let dead = resolved.addrs.is_empty();
                if dead {
                    tracing::warn!(
                        ingress = ?ingress.metadata.name,
                        svc = %svc.name,
                        "No ready endpoints — installing dead route (503)"
                    );
                }
                // CoxswainBackendPolicy (#554): looked up per backend Service — this
                // path's Service may differ from another path's within the same
                // Ingress, each carrying its own attached policy.
                let backend_policy = auth_stores
                    .backend_policy_index
                    .get(&ObjectKey::new(ns, &svc.name));
                // Backend wire protocol comes from the Service port `appProtocol` (GEP-1911).
                let group = Arc::new(build_ingress_backend_group(
                    ns,
                    &svc.name,
                    resolved.addrs,
                    resolved.app_protocol,
                    backend_policy,
                    &retries,
                ));
                let circuit_breaker = backend_policy.and_then(|bp| bp.circuit_breaker.clone());
                let path = path_rule.path.as_deref().unwrap_or("/");

                // Every Ingress path must be absolute — the Kubernetes API server
                // enforces this for all pathTypes, including `ImplementationSpecific`
                // regex paths. A regex pattern is therefore always rooted at '/'
                // (e.g. `/svc/(.*)`), never anchored with a leading `^`.
                if !path.starts_with('/') {
                    tracing::warn!(
                        ingress = %route_id,
                        host = ?rule.host,
                        path = %path,
                        "Ingress path does not start with '/' — skipping rule"
                    );
                    continue;
                }

                // Regex mode is per-path: the Ingress-wide `use-regex` annotation only
                // arms `pathType: ImplementationSpecific` rules.
                let is_regex_path =
                    ann.use_regex && path_rule.path_type.as_str() == "ImplementationSpecific";

                // Compile the regex here (the safe-compile guard) so an uncompilable
                // pattern skips just this path instead of reaching `build()` and dropping
                // the whole table.
                let path_regex = if is_regex_path {
                    match compile_path_regex(path) {
                        Ok(re) => Some(Arc::new(re)),
                        Err(e) => {
                            tracing::warn!(
                                ingress = %route_id,
                                host = ?rule.host,
                                path = %path,
                                error = %e,
                                "use-regex path is not a valid regular expression — skipping path"
                            );
                            continue;
                        }
                    }
                } else {
                    None
                };

                // Per-path filter vec: start from the shared base (header mods + generic
                // redirect), then append the rewrite filter.  On a regex path the
                // rewrite-target template is rebuilt as a capture-group substitution
                // against this path's own compiled pattern.
                let path_filters = {
                    let mut f = base_filters.clone();
                    match (&path_regex, &ann.rewrite) {
                        (Some(re), Some(PathModifier::ReplaceFullPath(target))) => {
                            f.push(FilterAction::UrlRewrite {
                                hostname: None,
                                path: Some(PathModifier::RegexReplace {
                                    regex: Arc::clone(re),
                                    replacement: target.as_str().into(),
                                }),
                            });
                        }
                        _ => {
                            if let Some(pm) = &ann.rewrite {
                                f.push(FilterAction::UrlRewrite {
                                    hostname: None,
                                    path: Some(pm.clone()),
                                });
                            }
                        }
                    }
                    f
                };

                let metric_route_id: Arc<str> = Arc::from(format!(
                    "ingress/{ns}/{ingress_name}:{rule_index}.{path_index}"
                ));
                let mut base_entry = build_route_entry(
                    Arc::clone(&group),
                    Arc::from(path),
                    Arc::clone(&metric_route_id),
                    path_filters.clone(),
                    circuit_breaker.clone(),
                );
                if dead {
                    base_entry.error_status = Some(503);
                }
                // When ssl-redirect is active the HTTP-port entry carries an extra leading
                // RequestRedirect filter; the HTTPS-port entry does not (the request is
                // already over TLS).  When ssl-redirect is inactive both ports share the
                // same Arc<RouteEntry>.
                let e = Arc::new(base_entry);
                let e_ssl = needs_ssl_redirect.then(|| {
                    let ssl_filters =
                        prepend_ssl_redirect(ann.ssl_redirect_code.unwrap_or(308), &path_filters);
                    let mut entry = build_route_entry(
                        Arc::clone(&group),
                        Arc::from(path),
                        Arc::clone(&metric_route_id),
                        ssl_filters,
                        circuit_breaker.clone(),
                    );
                    if dead {
                        entry.error_status = Some(503);
                    }
                    Arc::new(entry)
                });

                // Regex paths route to the regex matcher; otherwise "Exact" is exact and
                // "Prefix"/"ImplementationSpecific" both map to prefix matching.
                for &listener_port in &ports {
                    let route_entry = match &e_ssl {
                        Some(ssl_e) if Some(listener_port) == http_port => Arc::clone(ssl_e),
                        _ => Arc::clone(&e),
                    };
                    let host_builder = resolve_host_builder(
                        builder,
                        listener_port,
                        rule.host.as_deref(),
                        ann.path_normalize,
                    );
                    if path_regex.is_some() {
                        host_builder.add_regex_route(path, route_entry);
                    } else {
                        match path_rule.path_type.as_str() {
                            "Exact" => {
                                host_builder.add_exact_route(path, route_entry);
                            }
                            _ => {
                                host_builder.add_prefix_route(path, route_entry);
                            }
                        }
                    }
                }
            }
        }

        // Install spec.defaultBackend as prefix "/" on:
        //   - each rule host  → catches path-misses on hosts named in spec.rules
        //   - the catchall    → catches requests to hosts not named in any rule,
        //                       including rules-less Ingresses that claim all traffic
        //
        // Per-rule routes registered above are inserted as exact or as specific
        // prefix paths, so they outrank "/" via matchit's longest-match lookup.
        // The controller-wide --ingress-default-backend uses created_at = None
        // (sorts last), so this per-Ingress entry naturally wins on the catchall.
        if let Some(default_backend) = spec.and_then(|s| s.default_backend.as_ref()) {
            if let Some(default_svc) = default_backend.service.as_ref() {
                if let Some(port) = resolve_backend_port(ns, default_svc, services) {
                    let resolved =
                        endpoints::resolve(ns, &default_svc.name, port, slices, services);
                    if resolved.addrs.is_empty() {
                        tracing::warn!(
                            ingress = ?ingress.metadata.name,
                            svc = %default_svc.name,
                            "No ready endpoints for defaultBackend — skipping"
                        );
                    } else {
                        // CoxswainBackendPolicy (#554): looked up for the defaultBackend's
                        // own Service, independent of any per-rule path's policy.
                        let backend_policy = auth_stores
                            .backend_policy_index
                            .get(&ObjectKey::new(ns, &default_svc.name));
                        // Backend wire protocol comes from the Service port `appProtocol` (GEP-1911).
                        let group = Arc::new(build_ingress_backend_group(
                            ns,
                            &default_svc.name,
                            resolved.addrs,
                            resolved.app_protocol,
                            backend_policy,
                            &retries,
                        ));
                        let circuit_breaker =
                            backend_policy.and_then(|bp| bp.circuit_breaker.clone());
                        let default_metric_route_id: Arc<str> =
                            Arc::from(format!("ingress/{ns}/{ingress_name}:default"));
                        // Build the defaultBackend filter vec (same base as rule-path
                        // entries; rewrite applied as a literal full-path replace since
                        // defaultBackend always matches prefix "/", never a regex).
                        let mut default_filters = base_filters.clone();
                        if let Some(pm) = &ann.rewrite {
                            default_filters.push(FilterAction::UrlRewrite {
                                hostname: None,
                                path: Some(pm.clone()),
                            });
                        }
                        let make_entry = |filters: Vec<FilterAction>| {
                            Arc::new(build_route_entry(
                                Arc::clone(&group),
                                Arc::from("/"),
                                Arc::clone(&default_metric_route_id),
                                filters,
                                circuit_breaker.clone(),
                            ))
                        };
                        for &listener_port in &ports {
                            let effective =
                                if needs_ssl_redirect && Some(listener_port) == http_port {
                                    prepend_ssl_redirect(
                                        ann.ssl_redirect_code.unwrap_or(308),
                                        &default_filters,
                                    )
                                } else {
                                    default_filters.clone()
                                };
                            for rule in rules {
                                resolve_host_builder(
                                    builder,
                                    listener_port,
                                    rule.host.as_deref(),
                                    ann.path_normalize,
                                )
                                .add_prefix_route("/", make_entry(effective.clone()));
                            }
                            resolve_host_builder(builder, listener_port, None, ann.path_normalize)
                                .add_prefix_route("/", make_entry(effective));
                        }
                    }
                }
            } else if let Some(resource) = default_backend.resource.as_ref() {
                tracing::warn!(
                    ingress = %route_id,
                    api_group = ?resource.api_group,
                    kind = %resource.kind,
                    name = %resource.name,
                    "Ingress defaultBackend uses Resource type — only Service backends are supported; skipping"
                );
            }
        }
        annotation_issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::tests::*;
    use coxswain_core::routing::{RequestContext, RoutingTableBuilder};
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, IngressBackend, IngressRule, IngressServiceBackend,
        IngressSpec, ServiceBackendPort,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::api::ObjectMeta;

    fn make_ingress_with_timestamp(
        ns: &str,
        host: Option<&str>,
        path: &str,
        path_type: &str,
        svc: &str,
        created_at_ms: i64,
    ) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some(format!("{svc}-ingress")),
                namespace: Some(ns.to_string()),
                creation_timestamp: Some(Time(
                    k8s_openapi::jiff::Timestamp::from_millisecond(created_at_ms).unwrap(),
                )),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: Some(vec![IngressRule {
                    host: host.map(str::to_string),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some(path.to_string()),
                            path_type: path_type.to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: svc.to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(80),
                                        ..Default::default()
                                    }),
                                }),
                                ..Default::default()
                            },
                        }],
                    }),
                }]),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn reconcile_default_backend_catches_path_miss() {
        let store = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            make_slice("default", "default-svc", "10.0.0.2"),
        ]);
        let ingress = make_ingress_with_default(
            "default",
            Some("example.com"),
            "/api",
            "rule-svc",
            Some("default-svc"),
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table
                .route(80, "example.com", "/api/v1", &ctx)
                .unwrap()
                .name(),
            "default/rule-svc"
        );
        assert_eq!(
            table
                .route(80, "example.com", "/other", &ctx)
                .unwrap()
                .name(),
            "default/default-svc"
        );
    }

    #[test]
    fn reconcile_default_backend_only_routes_all_traffic() {
        let store = slice_store(vec![make_slice("default", "default-svc", "10.0.0.1")]);
        let ingress = make_default_only_ingress("default", "default-svc");
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route(80, "any.host.com", "/", &ctx).unwrap().name(),
            "default/default-svc"
        );
        assert_eq!(
            table.route(80, "other.io", "/api/v1", &ctx).unwrap().name(),
            "default/default-svc"
        );
    }

    #[test]
    fn reconcile_default_backend_catches_unmatched_host() {
        let store = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            make_slice("default", "default-svc", "10.0.0.2"),
        ]);
        let ingress = make_ingress_with_default(
            "default",
            Some("a.com"),
            "/api",
            "rule-svc",
            Some("default-svc"),
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route(80, "a.com", "/api", &ctx).unwrap().name(),
            "default/rule-svc"
        );
        assert_eq!(
            table.route(80, "a.com", "/other", &ctx).unwrap().name(),
            "default/default-svc"
        );
        assert_eq!(
            table.route(80, "b.com", "/", &ctx).unwrap().name(),
            "default/default-svc"
        );
    }

    #[test]
    fn reconcile_older_ingress_wins_same_prefix_path() {
        let store = slice_store(vec![
            make_slice("default", "old-svc", "10.0.0.1"),
            make_slice("default", "new-svc", "10.0.0.2"),
        ]);
        let old_ingress = make_ingress_with_timestamp(
            "default",
            Some("example.com"),
            "/foo",
            "Prefix",
            "old-svc",
            1000,
        );
        let new_ingress = make_ingress_with_timestamp(
            "default",
            Some("example.com"),
            "/foo",
            "Prefix",
            "new-svc",
            2000,
        );

        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &old_ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        reconcile_no_default(
            &new_ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route(80, "example.com", "/foo", &ctx).unwrap().name(),
            "default/old-svc",
            "older Ingress should win on conflicting Prefix /foo"
        );
    }

    #[test]
    fn reconcile_exact_beats_prefix_same_path() {
        let store = slice_store(vec![
            make_slice("default", "exact-svc", "10.0.0.1"),
            make_slice("default", "prefix-svc", "10.0.0.2"),
        ]);
        let ingress = Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: Some(vec![IngressRule {
                    host: Some("example.com".to_string()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![
                            HTTPIngressPath {
                                path: Some("/foo".to_string()),
                                path_type: "Exact".to_string(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "exact-svc".to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(80),
                                            ..Default::default()
                                        }),
                                    }),
                                    ..Default::default()
                                },
                            },
                            HTTPIngressPath {
                                path: Some("/foo".to_string()),
                                path_type: "Prefix".to_string(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "prefix-svc".to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(80),
                                            ..Default::default()
                                        }),
                                    }),
                                    ..Default::default()
                                },
                            },
                        ],
                    }),
                }]),
                ..Default::default()
            }),
            status: None,
        };
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table.route(80, "example.com", "/foo", &ctx).unwrap().name(),
            "default/exact-svc",
            "Exact /foo should win over Prefix /foo"
        );
        assert_eq!(
            table
                .route(80, "example.com", "/foo/sub", &ctx)
                .unwrap()
                .name(),
            "default/prefix-svc",
            "Prefix /foo should still match /foo/sub"
        );
    }

    #[test]
    fn reconcile_default_backend_skipped_when_no_endpoints() {
        let store = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            // no slice for default-svc → no endpoints
        ]);
        let ingress = make_ingress_with_default(
            "default",
            Some("example.com"),
            "/api",
            "rule-svc",
            Some("default-svc"),
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route(80, "example.com", "/api", &ctx).is_some());
        assert!(table.route(80, "example.com", "/other", &ctx).is_none());
    }

    #[test]
    fn reconcile_default_backend_on_wildcard_host() {
        let store = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            make_slice("default", "default-svc", "10.0.0.2"),
        ]);
        let ingress = make_ingress_with_default(
            "default",
            Some("*.example.com"),
            "/api",
            "rule-svc",
            Some("default-svc"),
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table
                .route(80, "api.example.com", "/api", &ctx)
                .unwrap()
                .name(),
            "default/rule-svc"
        );
        assert_eq!(
            table
                .route(80, "api.example.com", "/other", &ctx)
                .unwrap()
                .name(),
            "default/default-svc"
        );
    }

    #[test]
    fn reconcile_rule_root_path_wins_over_default_backend() {
        let store = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            make_slice("default", "default-svc", "10.0.0.2"),
        ]);
        // Rule already claims "/"; defaultBackend should not override it.
        let ingress = make_ingress_with_default(
            "default",
            Some("example.com"),
            "/",
            "rule-svc",
            Some("default-svc"),
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table
                .route(80, "example.com", "/anything", &ctx)
                .unwrap()
                .name(),
            "default/rule-svc"
        );
    }

    #[test]
    fn reconcile_exact_path_type() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/api",
            "Exact",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route(80, "example.com", "/api", &ctx).is_some());
        assert!(table.route(80, "example.com", "/api/users", &ctx).is_none());
    }

    #[test]
    fn reconcile_named_port_resolves_to_route() {
        let slices = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let svcs = make_svc_store(vec![make_service_with_named_port(
            "default", "svc", "http", 80,
        )]);
        let ingress = make_ingress_named_port("default", Some("example.com"), "svc", "http");
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &slices,
            &svcs,
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        let route = table.route(80, "example.com", "/named", &ctx);
        assert!(
            route.is_some(),
            "named port backend should resolve to a route"
        );
        assert_eq!(route.unwrap().name(), "default/svc");
    }

    #[test]
    fn reconcile_named_port_skips_when_service_missing() {
        let slices = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        // No Service in the store → port_for_name returns None → path skipped
        let ingress = make_ingress_named_port("default", Some("example.com"), "svc", "http");
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &slices,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table
                .route(80, "example.com", "/named", &RequestContext::default())
                .is_none()
        );
    }

    #[test]
    fn reconcile_named_port_skips_when_port_name_not_found() {
        let slices = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        // Service exists but has port name "grpc", not "http"
        let svcs = make_svc_store(vec![make_service_with_named_port(
            "default", "svc", "grpc", 9000,
        )]);
        let ingress = make_ingress_named_port("default", Some("example.com"), "svc", "http");
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &slices,
            &svcs,
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table
                .route(80, "example.com", "/named", &RequestContext::default())
                .is_none()
        );
    }

    #[test]
    fn reconcile_named_port_default_backend_resolves() {
        let slices = slice_store(vec![
            make_slice("default", "rule-svc", "10.0.0.1"),
            make_slice("default", "default-svc", "10.0.0.2"),
        ]);
        let svcs = make_svc_store(vec![make_service_with_named_port(
            "default",
            "default-svc",
            "http",
            80,
        )]);
        let ingress = Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: Some(vec![IngressRule {
                    host: Some("example.com".to_string()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some("/api".to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: "rule-svc".to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(80),
                                        ..Default::default()
                                    }),
                                }),
                                ..Default::default()
                            },
                        }],
                    }),
                }]),
                default_backend: Some(IngressBackend {
                    service: Some(IngressServiceBackend {
                        name: "default-svc".to_string(),
                        port: Some(ServiceBackendPort {
                            name: Some("http".to_string()),
                            number: None,
                        }),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
        };
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &slices,
            &svcs,
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert_eq!(
            table
                .route(80, "example.com", "/api/v1", &ctx)
                .unwrap()
                .name(),
            "default/rule-svc"
        );
        assert_eq!(
            table
                .route(80, "example.com", "/other", &ctx)
                .unwrap()
                .name(),
            "default/default-svc"
        );
    }

    #[test]
    fn reconcile_prefix_path_type() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/api",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route(80, "example.com", "/api", &ctx).is_some());
        assert!(table.route(80, "example.com", "/api/users", &ctx).is_some());
        assert!(table.route(80, "example.com", "/other", &ctx).is_none());
    }

    #[test]
    fn reconcile_implementation_specific_maps_to_prefix() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/api",
            "ImplementationSpecific",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route(80, "example.com", "/api", &ctx).is_some());
        assert!(table.route(80, "example.com", "/api/v2", &ctx).is_some());
    }

    // ── use-regex (#265) ──────────────────────────────────────────────────────

    /// Build an Ingress on `default` with one rule, arbitrary `(path, pathType)`
    /// pairs, and arbitrary `ingress.coxswain-labs.dev/*` annotations.
    fn make_regex_ingress(
        host: Option<&str>,
        paths: &[(&str, &str)],
        svc: &str,
        annotations: &[(&str, &str)],
    ) -> Ingress {
        let mut ann_map: BTreeMap<String, String> = annotations
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        ann_map
            .entry("kubernetes.io/ingress.class".to_string())
            .or_insert_with(|| "coxswain".to_string());
        Ingress {
            metadata: ObjectMeta {
                name: Some("regex-ingress".to_string()),
                namespace: Some("default".to_string()),
                annotations: Some(ann_map),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: Some(vec![IngressRule {
                    host: host.map(str::to_string),
                    http: Some(HTTPIngressRuleValue {
                        paths: paths
                            .iter()
                            .map(|(p, pt)| HTTPIngressPath {
                                path: Some((*p).to_string()),
                                path_type: (*pt).to_string(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: svc.to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(80),
                                            ..Default::default()
                                        }),
                                    }),
                                    ..Default::default()
                                },
                            })
                            .collect(),
                    }),
                }]),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn reconcile_use_regex_matches_implementation_specific_as_regex() {
        use crate::ingress::annotations::USE_REGEX;
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_regex_ingress(
            Some("example.com"),
            &[(r"/item/[0-9]+", "ImplementationSpecific")],
            "svc",
            &[(USE_REGEX, "true")],
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        // Digits match; non-digits do not — pattern is a regex, not a prefix.
        assert!(table.route(80, "example.com", "/item/42", &ctx).is_some());
        assert!(table.route(80, "example.com", "/item/abc", &ctx).is_none());
    }

    #[test]
    fn reconcile_use_regex_off_does_not_treat_path_as_regex() {
        use crate::ingress::annotations::USE_REGEX;
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_regex_ingress(
            Some("example.com"),
            &[(r"/item/[0-9]+", "ImplementationSpecific")],
            "svc",
            &[(USE_REGEX, "false")],
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        // With the opt-in off, the path is a literal Prefix: `/item/42` does not
        // start with the literal `/item/[0-9]+`, so it does not match (it would if
        // the metacharacters were interpreted as a regex).
        assert!(table.route(80, "example.com", "/item/42", &ctx).is_none());
    }

    #[test]
    fn reconcile_use_regex_rewrite_target_substitutes_captures() {
        use crate::ingress::annotations::{REWRITE_TARGET, USE_REGEX};
        use coxswain_core::routing::{FilterAction, PathModifier, RouteOutcome};
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_regex_ingress(
            Some("example.com"),
            &[(r"/svc/(.*)", "ImplementationSpecific")],
            "svc",
            &[(USE_REGEX, "true"), (REWRITE_TARGET, "/$1")],
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        match table.find(80, "example.com", "/svc/users/42", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                let pm = filters
                    .iter()
                    .find_map(|f| match f {
                        FilterAction::UrlRewrite {
                            path: Some(pm @ PathModifier::RegexReplace { .. }),
                            ..
                        } => Some(pm),
                        _ => None,
                    })
                    .expect("expected a RegexReplace UrlRewrite filter");
                // The capture group is expanded against this path's own pattern.
                assert_eq!(pm.apply("/svc/users/42"), "/users/42");
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn reconcile_invalid_regex_skips_only_that_path() {
        use crate::ingress::annotations::USE_REGEX;
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        // One valid and one uncompilable regex path on the same Ingress.
        let ingress = make_regex_ingress(
            Some("example.com"),
            &[
                (r"/good/[0-9]+$", "ImplementationSpecific"),
                (r"/bad/(", "ImplementationSpecific"),
            ],
            "svc",
            &[(USE_REGEX, "true")],
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        // The whole table still builds — the bad path was skipped, not fatal.
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route(80, "example.com", "/good/42", &ctx).is_some());
        // The bad path installed no route, so nothing serves it.
        assert!(
            table
                .route(80, "example.com", "/bad/anything", &ctx)
                .is_none()
        );
        assert!(logs_contain("not a valid regular expression"));
    }

    #[test]
    fn reconcile_exact_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route(80, "example.com", "/", &ctx).is_some());
        assert!(table.route(80, "other.com", "/", &ctx).is_none());
    }

    #[test]
    fn reconcile_wildcard_hostname() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("*.example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route(80, "api.example.com", "/", &ctx).is_some());
        assert!(table.route(80, "example.com", "/", &ctx).is_none());
        // Ingress spec: multi-label subdomains must NOT match `*.example.com`.
        assert!(table.route(80, "v2.api.example.com", "/", &ctx).is_none());
    }

    #[test]
    fn reconcile_no_host_goes_to_catchall() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            None,
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(table.route(80, "any-host.example.com", "/", &ctx).is_some());
        assert!(table.route(80, "other.io", "/", &ctx).is_some());
    }

    #[test]
    fn reconcile_keeps_dead_route_when_no_endpoints() {
        let store = slice_store(vec![]); // no slices → zero ready endpoints
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        // The route is KEPT (not pruned), so the path can't fall through to a
        // broader route, and it resolves to a 503 error route rather than a
        // served backend.
        assert!(
            matches!(
                table.find(80, "example.com", "/", &ctx),
                coxswain_core::routing::RouteOutcome::Error(503)
            ),
            "an Ingress path with zero ready endpoints must stay in the table as a 503 route"
        );
    }

    #[test]
    fn reconcile_matches_owned_class_name() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route(80, "example.com", "/", &RequestContext::default())
                .is_some()
        );
    }

    #[test]
    fn reconcile_skips_unowned_class_name() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("nginx"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route(80, "example.com", "/", &RequestContext::default())
                .is_none()
        );
    }

    #[test]
    fn reconcile_matches_via_legacy_annotation() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            None,
            Some("coxswain"),
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route(80, "example.com", "/", &RequestContext::default())
                .is_some()
        );
    }

    #[test]
    fn reconcile_skips_unowned_legacy_annotation() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            None,
            Some("nginx"),
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route(80, "example.com", "/", &RequestContext::default())
                .is_none()
        );
    }

    #[test]
    fn reconcile_skips_when_both_unset() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            None,
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route(80, "example.com", "/", &RequestContext::default())
                .is_none()
        );
    }

    #[test]
    fn reconcile_claims_unclassified_when_owned_default_exists() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            None,
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        let no_class_defaults = HashMap::new();
        // Diagnostics return ignored: these tests assert on the built routing
        // table, not the forwarded annotation issues.
        let _ = IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &IngressClassContext::new(&owned(&["coxswain"]), Some("coxswain"), &no_class_defaults),
            IngressPorts::new(Some(80), None),
            &mut builder,
            &IngressExtensionStores::new(
                &empty_secret_store(),
                &empty_external_auth_store(),
                &empty_jwt_auth_store(),
                &empty_jwks_cache(),
                &empty_backend_grants(),
                IngressCrRefStores::new(
                    &empty_compression_store(),
                    &empty_retry_policy_store(),
                    &empty_rate_limit_store(),
                    &empty_ip_access_store(),
                ),
                &empty_backend_policy_index(),
            ),
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route(80, "example.com", "/", &RequestContext::default())
                .is_some()
        );
    }

    #[test]
    fn reconcile_skips_unclassified_when_no_owned_default() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            None,
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        let no_class_defaults = HashMap::new();
        // Diagnostics return ignored: these tests assert on the built routing
        // table, not the forwarded annotation issues.
        let _ = IngressReconciler::reconcile(
            &ingress,
            &store,
            &empty_svc_store(),
            &IngressClassContext::new(&owned(&["coxswain"]), None, &no_class_defaults),
            IngressPorts::new(Some(80), None),
            &mut builder,
            &IngressExtensionStores::new(
                &empty_secret_store(),
                &empty_external_auth_store(),
                &empty_jwt_auth_store(),
                &empty_jwks_cache(),
                &empty_backend_grants(),
                IngressCrRefStores::new(
                    &empty_compression_store(),
                    &empty_retry_policy_store(),
                    &empty_rate_limit_store(),
                    &empty_ip_access_store(),
                ),
                &empty_backend_policy_index(),
            ),
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route(80, "example.com", "/", &RequestContext::default())
                .is_none()
        );
    }

    #[test]
    fn reconcile_skips_when_owned_set_empty() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&[]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route(80, "example.com", "/", &RequestContext::default())
                .is_none()
        );
    }

    #[test]
    fn reconcile_path_resource_backend_skipped() {
        use k8s_openapi::api::core::v1::TypedLocalObjectReference;

        let store = slice_store(vec![]);
        let ingress = Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: Some(vec![IngressRule {
                    host: Some("example.com".to_string()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some("/api".to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: None,
                                resource: Some(TypedLocalObjectReference {
                                    api_group: Some("example.com".to_string()),
                                    kind: "StorageBucket".to_string(),
                                    name: "my-bucket".to_string(),
                                }),
                            },
                        }],
                    }),
                }]),
                ..Default::default()
            }),
            status: None,
        };
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table
                .route(80, "example.com", "/api", &RequestContext::default())
                .is_none(),
            "Resource backend path rule should not install a route"
        );
    }

    #[test]
    fn reconcile_default_backend_resource_skipped() {
        use k8s_openapi::api::core::v1::TypedLocalObjectReference;

        let store = slice_store(vec![]);
        let ingress = Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                ingress_class_name: Some("coxswain".to_string()),
                rules: None,
                default_backend: Some(IngressBackend {
                    service: None,
                    resource: Some(TypedLocalObjectReference {
                        api_group: Some("example.com".to_string()),
                        kind: "StorageBucket".to_string(),
                        name: "my-bucket".to_string(),
                    }),
                }),
                ..Default::default()
            }),
            status: None,
        };
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table
                .route(80, "any.host.com", "/", &RequestContext::default())
                .is_none(),
            "Resource defaultBackend should not install a catchall route"
        );
    }

    #[test]
    fn reconcile_field_takes_precedence_over_annotation() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        // field = "coxswain" (owned), annotation = "nginx" (not owned) → should reconcile
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            Some("nginx"),
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        assert!(
            builder
                .build()
                .unwrap()
                .route(80, "example.com", "/", &RequestContext::default())
                .is_some()
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn reconcile_skips_path_without_leading_slash() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ingress = make_ingress(
            "default",
            Some("example.com"),
            "api/v1",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let mut builder = RoutingTableBuilder::new();
        reconcile_no_default(
            &ingress,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        assert!(
            table.route(80, "example.com", "/api/v1", &ctx).is_none(),
            "malformed path without leading slash should not install a route"
        );
        assert!(
            logs_contain("does not start with '/'"),
            "expected warning about missing leading slash"
        );
        assert!(
            logs_contain("api/v1"),
            "warning should include the malformed path"
        );
    }

    // ── Annotation round-trip tests ───────────────────────────────────────────

    fn find_timeouts(
        table: &coxswain_core::routing::IngressRoutingTable,
        host: &str,
        path: &str,
    ) -> coxswain_core::routing::RouteTimeouts {
        use coxswain_core::routing::RouteOutcome;
        let ctx = RequestContext::default();
        match table.find(80, host, path, &ctx) {
            RouteOutcome::Found(m) => m.timeouts,
            _other => panic!("expected Found"),
        }
    }

    #[test]
    fn annotation_timeouts_stored_on_route_entry() {
        use crate::ingress::annotations::{READ_TIMEOUT, SEND_TIMEOUT};
        use std::time::Duration;
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/",
            "svc",
            &[(READ_TIMEOUT, "30s"), (SEND_TIMEOUT, "10s")],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_no_default(&ing, &store, &svcs, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();
        let t = find_timeouts(&table, "example.com", "/");
        // `connect` has no annotation source — it converged onto
        // `CoxswainBackendPolicy.timeouts.connect` (#554).
        assert!(t.connect.is_none());
        assert_eq!(t.read, Some(Duration::from_secs(30)));
        assert_eq!(t.send, Some(Duration::from_secs(10)));
        assert!(t.request.is_none(), "request timeout is gateway-api only");
        assert!(
            t.backend_request.is_none(),
            "backend_request is gateway-api only"
        );
    }

    #[test]
    fn annotation_retry_ref_resolves_to_backend_group_policy() {
        use crate::ingress::annotations::traffic_policy::RETRY;
        use coxswain_core::crd::RetryPolicy;

        let yaml = "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RetryPolicy\n\
             metadata:\n  name: r\n  namespace: default\n\
             spec:\n  attempts: 3\n  codes: [502, 503]\n  backoff: 100ms\n";
        let cr: RetryPolicy =
            serde_yaml::from_str(yaml).unwrap_or_else(|e| panic!("valid RetryPolicy: {e}"));
        let retry_policies = make_retry_policy_store(vec![cr]);

        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/",
            "svc",
            &[(RETRY, "default/r")],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        let no_class_defaults = HashMap::new();
        let _ = IngressReconciler::reconcile(
            &ing,
            &store,
            &svcs,
            &IngressClassContext::new(&owned(&["coxswain"]), None, &no_class_defaults),
            IngressPorts::new(Some(80), None),
            &mut builder,
            &IngressExtensionStores::new(
                &empty_secret_store(),
                &empty_external_auth_store(),
                &empty_jwt_auth_store(),
                &empty_jwks_cache(),
                &empty_backend_grants(),
                IngressCrRefStores::new(
                    &empty_compression_store(),
                    &retry_policies,
                    &empty_rate_limit_store(),
                    &empty_ip_access_store(),
                ),
                &empty_backend_policy_index(),
            ),
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();
        let group = table
            .route(80, "example.com", "/", &ctx)
            .expect("route not found");
        let policy = group.retry_policy();
        assert_eq!(policy.attempts, 3);
        assert_eq!(&*policy.http_codes, &[502, 503]);
        assert_eq!(policy.backoff, Some(std::time::Duration::from_millis(100)));
    }

    #[test]
    fn annotation_rewrite_target_stored_as_url_rewrite_filter() {
        use crate::ingress::annotations::REWRITE_TARGET;
        use coxswain_core::routing::{FilterAction, PathModifier, RouteOutcome};
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/old",
            "svc",
            &[(REWRITE_TARGET, "/new")],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_no_default(&ing, &store, &svcs, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();
        match table.find(80, "example.com", "/old", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                let rewrite = filters.iter().find(|f| {
                    matches!(
                        f,
                        FilterAction::UrlRewrite {
                            hostname: None,
                            path: Some(PathModifier::ReplaceFullPath(_)),
                        }
                    )
                });
                assert!(
                    rewrite.is_some(),
                    "expected UrlRewrite filter with ReplaceFullPath"
                );
                if let Some(FilterAction::UrlRewrite {
                    path: Some(PathModifier::ReplaceFullPath(target)),
                    ..
                }) = rewrite
                {
                    assert_eq!(target, "/new");
                }
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn invalid_annotation_warns_but_route_still_installed() {
        use crate::ingress::annotations::READ_TIMEOUT;
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/",
            "svc",
            &[(READ_TIMEOUT, "not-a-duration")],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_no_default(&ing, &store, &svcs, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();
        // Route is installed despite invalid annotation.
        assert!(table.route(80, "example.com", "/", &ctx).is_some());
        // A warning was emitted.
        assert!(logs_contain("invalid duration — using default"));
    }

    // ── Header modifier + redirect filter reconcile tests (#79, #262) ────────

    #[test]
    fn annotation_request_header_modifier_stored_as_filter() {
        use crate::ingress::annotations::{REQUEST_HEADER_REMOVE, REQUEST_HEADER_SET};
        use coxswain_core::routing::{FilterAction, RouteOutcome};
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/",
            "svc",
            &[
                (REQUEST_HEADER_SET, "X-Env: prod"),
                (REQUEST_HEADER_REMOVE, "X-Debug"),
            ],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_no_default(&ing, &store, &svcs, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();
        match table.find(80, "example.com", "/", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                let has_req_mod = filters
                    .iter()
                    .any(|f| matches!(f, FilterAction::RequestHeaderModifier(_)));
                assert!(has_req_mod, "expected RequestHeaderModifier filter");
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn annotation_response_header_modifier_stored_as_filter() {
        use crate::ingress::annotations::{RESPONSE_HEADER_ADD, RESPONSE_HEADER_REMOVE};
        use coxswain_core::routing::{FilterAction, RouteOutcome};
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/",
            "svc",
            &[
                (RESPONSE_HEADER_ADD, "X-Powered-By: coxswain"),
                (RESPONSE_HEADER_REMOVE, "X-Internal"),
            ],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_no_default(&ing, &store, &svcs, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();
        match table.find(80, "example.com", "/", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                let has_resp_mod = filters
                    .iter()
                    .any(|f| matches!(f, FilterAction::ResponseHeaderModifier(_)));
                assert!(has_resp_mod, "expected ResponseHeaderModifier filter");
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn annotation_redirect_stored_as_filter() {
        use crate::ingress::annotations::{REDIRECT_HOSTNAME, REDIRECT_STATUS_CODE};
        use coxswain_core::routing::{FilterAction, RouteOutcome};
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/",
            "svc",
            &[
                (REDIRECT_HOSTNAME, "new.example.com"),
                (REDIRECT_STATUS_CODE, "301"),
            ],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_no_default(&ing, &store, &svcs, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();
        match table.find(80, "example.com", "/", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                let redirect = filters.iter().find(|f| {
                    matches!(
                        f,
                        FilterAction::RequestRedirect {
                            hostname: Some(_),
                            status_code: 301,
                            ..
                        }
                    )
                });
                assert!(redirect.is_some(), "expected RequestRedirect with 301");
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn annotation_header_modifier_and_rewrite_coexist_on_same_route() {
        use crate::ingress::annotations::{REQUEST_HEADER_SET, REWRITE_TARGET};
        use coxswain_core::routing::{FilterAction, RouteOutcome};
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/old",
            "svc",
            &[
                (REQUEST_HEADER_SET, "X-Version: 2"),
                (REWRITE_TARGET, "/new"),
            ],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_no_default(&ing, &store, &svcs, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();
        match table.find(80, "example.com", "/old", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                let has_req_mod = filters
                    .iter()
                    .any(|f| matches!(f, FilterAction::RequestHeaderModifier(_)));
                let has_rewrite = filters
                    .iter()
                    .any(|f| matches!(f, FilterAction::UrlRewrite { path: Some(_), .. }));
                assert!(has_req_mod, "expected RequestHeaderModifier filter");
                assert!(has_rewrite, "expected UrlRewrite filter");
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn annotation_invalid_header_value_drops_modifier_but_route_still_serves() {
        use crate::ingress::annotations::REQUEST_HEADER_SET;
        use coxswain_core::routing::{FilterAction, RouteOutcome};
        // Header values cannot contain control characters.
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/",
            "svc",
            &[(REQUEST_HEADER_SET, "X-Bad: value\x01with-ctrl")],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_no_default(&ing, &store, &svcs, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();
        // Route is still installed.
        match table.find(80, "example.com", "/", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                let has_req_mod = filters
                    .iter()
                    .any(|f| matches!(f, FilterAction::RequestHeaderModifier(_)));
                assert!(
                    !has_req_mod,
                    "expected no RequestHeaderModifier (modifier was invalid)"
                );
            }
            _ => panic!("expected Found"),
        }
        assert!(logs_contain("invalid header annotation"));
    }

    #[test]
    fn annotation_ssl_redirect_on_http_port_only() {
        use crate::ingress::annotations::SSL_REDIRECT;
        use coxswain_core::routing::{FilterAction, RouteOutcome};
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/",
            "svc",
            &[(SSL_REDIRECT, "true")],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        // Reconcile with BOTH HTTP (80) and HTTPS (443) ports active.
        let no_class_defaults = HashMap::new();
        // Diagnostics return ignored: these tests assert on the built routing
        // table, not the forwarded annotation issues.
        let _ = IngressReconciler::reconcile(
            &ing,
            &store,
            &svcs,
            &IngressClassContext::new(&owned(&["coxswain"]), None, &no_class_defaults),
            IngressPorts::new(Some(80), Some(443)),
            &mut builder,
            &IngressExtensionStores::new(
                &empty_secret_store(),
                &empty_external_auth_store(),
                &empty_jwt_auth_store(),
                &empty_jwks_cache(),
                &empty_backend_grants(),
                IngressCrRefStores::new(
                    &empty_compression_store(),
                    &empty_retry_policy_store(),
                    &empty_rate_limit_store(),
                    &empty_ip_access_store(),
                ),
                &empty_backend_policy_index(),
            ),
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();

        // HTTP port: entry carries the ssl-redirect.
        match table.find(80, "example.com", "/", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                let ssl_redir = filters.iter().find(|f| {
                    matches!(
                        f,
                        FilterAction::RequestRedirect {
                            scheme: Some(_),
                            ..
                        }
                    )
                });
                assert!(
                    ssl_redir.is_some(),
                    "expected ssl-redirect RequestRedirect on HTTP port"
                );
                if let Some(FilterAction::RequestRedirect {
                    scheme,
                    status_code,
                    ..
                }) = ssl_redir
                {
                    assert_eq!(scheme.as_deref(), Some("https"));
                    assert_eq!(*status_code, 308);
                }
            }
            _ => panic!("expected Found on port 80"),
        }

        // HTTPS port: entry must NOT carry the ssl-redirect.
        match table.find(443, "example.com", "/", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                let ssl_redir = filters.iter().find(|f| {
                    matches!(
                        f,
                        FilterAction::RequestRedirect {
                            scheme: Some(_),
                            ..
                        }
                    )
                });
                assert!(
                    ssl_redir.is_none(),
                    "ssl-redirect must not appear on the HTTPS port entry"
                );
            }
            _ => panic!("expected Found on port 443"),
        }
    }

    #[test]
    fn annotation_explicit_redirect_takes_precedence_over_ssl_redirect() {
        use crate::ingress::annotations::{REDIRECT_HOSTNAME, SSL_REDIRECT};
        use coxswain_core::routing::{FilterAction, RouteOutcome};
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/",
            "svc",
            &[
                (REDIRECT_HOSTNAME, "new.example.com"),
                (SSL_REDIRECT, "true"),
            ],
        );
        let svcs = empty_svc_store();
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_no_default(&ing, &store, &svcs, &owned(&["coxswain"]), &mut builder);
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();
        match table.find(80, "example.com", "/", &ctx) {
            RouteOutcome::Found(m) => {
                let filters = m.filters;
                // Exactly one RequestRedirect — the explicit redirect-*.
                let redirect_count = filters
                    .iter()
                    .filter(|f| matches!(f, FilterAction::RequestRedirect { .. }))
                    .count();
                assert_eq!(redirect_count, 1, "expected exactly one RequestRedirect");
                // The single redirect uses the explicit hostname, not https scheme.
                if let Some(FilterAction::RequestRedirect { hostname, .. }) = filters
                    .iter()
                    .find(|f| matches!(f, FilterAction::RequestRedirect { .. }))
                {
                    assert_eq!(hostname.as_deref(), Some("new.example.com"));
                }
            }
            _ => panic!("expected Found"),
        }
    }

    // ── Class-level annotation defaults (#190) ────────────────────────────────

    /// Per-class params map keyed by IngressClass name, with one annotation each.
    fn class_defaults(
        class: &str,
        anns: &[(&str, &str)],
    ) -> HashMap<String, crate::ingress::ResolvedClassParams> {
        use crate::ingress::ResolvedClassParams;
        let mut map = BTreeMap::new();
        for (k, v) in anns {
            map.insert((*k).to_string(), (*v).to_string());
        }
        let mut out = HashMap::new();
        out.insert(
            class.to_string(),
            ResolvedClassParams {
                default_annotations: map,
                access_log_enabled: None,
            },
        );
        out
    }

    #[test]
    fn class_default_annotation_applies_when_ingress_unset() {
        use crate::ingress::annotations::READ_TIMEOUT;
        use std::time::Duration;
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        // Ingress claims "coxswain" but sets no annotations of its own.
        let ing = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        let defaults = class_defaults("coxswain", &[(READ_TIMEOUT, "7s")]);
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_with_class_defaults(
            &ing,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &defaults,
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert_eq!(
            find_timeouts(&table, "example.com", "/").read,
            Some(Duration::from_secs(7)),
            "Ingress must inherit the class default read-timeout"
        );
    }

    #[test]
    fn ingress_annotation_overrides_class_default() {
        use crate::ingress::annotations::READ_TIMEOUT;
        use std::time::Duration;
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        // Ingress sets read-timeout=2s; class default is 7s → Ingress wins.
        let ing = make_ingress_with_annotations(
            "default",
            Some("example.com"),
            "/",
            "svc",
            &[(READ_TIMEOUT, "2s")],
        );
        let defaults = class_defaults("coxswain", &[(READ_TIMEOUT, "7s")]);
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_with_class_defaults(
            &ing,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &defaults,
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert_eq!(
            find_timeouts(&table, "example.com", "/").read,
            Some(Duration::from_secs(2)),
            "per-Ingress annotation must override the class default per-key"
        );
    }

    #[test]
    fn unknown_class_default_key_is_inert() {
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        // A key outside the coxswain annotation namespace is carried but ignored
        // by the parser — the route installs and carries no parsed knobs.
        let defaults = class_defaults("coxswain", &[("nginx.ingress.kubernetes.io/whatever", "x")]);
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_with_class_defaults(
            &ing,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &defaults,
            &mut builder,
        );
        let table = builder.build().unwrap();
        let ctx = RequestContext::default();
        assert!(table.route(80, "example.com", "/", &ctx).is_some());
        assert!(find_timeouts(&table, "example.com", "/").connect.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn empty_string_class_default_warns_and_falls_back() {
        use crate::ingress::annotations::READ_TIMEOUT;
        let store = slice_store(vec![make_slice("default", "svc", "10.0.0.1")]);
        let ing = make_ingress(
            "default",
            Some("example.com"),
            "/",
            "Prefix",
            "svc",
            Some("coxswain"),
            None,
        );
        // An empty string is not an "unset" sentinel: it is parsed, WARNs, and
        // falls back to the built-in default — same as a per-Ingress empty value.
        let defaults = class_defaults("coxswain", &[(READ_TIMEOUT, "")]);
        let mut builder = IngressRoutingTableBuilder::new();
        reconcile_with_class_defaults(
            &ing,
            &store,
            &empty_svc_store(),
            &owned(&["coxswain"]),
            &defaults,
            &mut builder,
        );
        let table = builder.build().unwrap();
        assert!(
            table
                .route(80, "example.com", "/", &RequestContext::default())
                .is_some()
        );
        assert!(
            find_timeouts(&table, "example.com", "/").read.is_none(),
            "empty class default must fall back to the built-in default"
        );
        assert!(logs_contain("invalid duration — using default"));
    }
}
