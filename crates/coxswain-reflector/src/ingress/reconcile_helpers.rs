//! Free helper functions extracted from [`super::reconcile`]: backend-group
//! construction, mirror-filter resolution, the auth-config resolution ladder,
//! the ssl-redirect filter prepend, and host-router builder resolution. Kept
//! beside the reconcile entry point but out of it to bound that file's size.

use super::annotations::AnnotationIssue;
use super::annotations::auth::{SecretRef, parse_htpasswd};
use super::annotations::traffic_policy;
use crate::endpoints;
use coxswain_core::crd::{
    Compression, CoxswainExternalAuth, IpAccessControl, RateLimit, RetryPolicy,
};
use coxswain_core::routing::{
    BackendGroup, BackendProtocol, BasicCredential, CompressionConfig, FilterAction,
    HostRouterBuilder, IngressAuthConfig, IngressRoutingTableBuilder, NormalizeLevel,
    RateLimitConfig, RetryPolicyConfig, WildcardKind,
};
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::reflector;
use std::net::SocketAddr;
use std::sync::Arc;

// ── Backend group construction ────────────────────────────────────────────────

/// Build a [`BackendGroup`] from resolved endpoints and Ingress-wide traffic-policy
/// annotations.
///
/// Used by both the per-rule path loop and `spec.defaultBackend` — centralises the
/// builder chain so annotation knobs are applied uniformly to every backend.
///
/// `retries` is passed in already resolved (via [`resolve_retry_config`]) rather
/// than read off `ann` directly — unlike the other knobs here, the `retry`
/// annotation is a CR reference that needs a store lookup, so the caller
/// resolves it once per Ingress and shares the result across every backend
/// group (#551).
pub(super) fn build_ingress_backend_group(
    ns: &str,
    svc_name: &str,
    addrs: Vec<SocketAddr>,
    protocol: BackendProtocol,
    ann: &super::annotations::IngressAnnotations,
    retries: &RetryPolicyConfig,
) -> BackendGroup {
    BackendGroup::new(format!("{ns}/{svc_name}"), addrs)
        .with_protocol(protocol)
        .with_retries(retries.clone())
        .with_session_affinity(ann.session_affinity.clone())
        .with_keepalive_timeout(ann.keepalive_timeout)
        .with_load_balance(ann.load_balance.clone())
}

// ── Mirror filter resolution ──────────────────────────────────────────────────

/// Resolve a mirror-target annotation into a [`FilterAction::Mirror`].
///
/// Returns `None` (and emits a `WARN`) when:
/// - the mirror namespace differs from the Ingress namespace (cross-namespace refs forbidden)
/// - the target Service does not exist in the store
///
/// Returns `Some(FilterAction::Mirror { … })` — with an empty [`BackendGroup`] and its
/// own `WARN` — when the Service exists but has no ready endpoints, so the proxy can
/// install the mirror entry and warn at dispatch time rather than silently dropping it.
pub(super) fn resolve_mirror_filter(
    mirror_ref: &super::annotations::traffic_policy::MirrorTargetRef,
    ns: &str,
    route_id: &str,
    slices: &reflector::Store<EndpointSlice>,
    services: &reflector::Store<Service>,
) -> Option<FilterAction> {
    if mirror_ref.namespace != ns {
        tracing::warn!(
            ingress = %route_id,
            mirror_namespace = %mirror_ref.namespace,
            ingress_namespace = %ns,
            "mirror-target namespace differs from Ingress namespace — cross-namespace \
             mirror references are not permitted; mirror disabled"
        );
        return None;
    }
    let mirror_ns = &mirror_ref.namespace;
    let resolved = endpoints::resolve(
        mirror_ns,
        &mirror_ref.service,
        i32::from(mirror_ref.port),
        slices,
        services,
    );
    if !resolved.service_exists {
        tracing::warn!(
            ingress = %route_id,
            service = %mirror_ref.service,
            namespace = %mirror_ns,
            port = mirror_ref.port,
            "mirror-target Service not found — mirror disabled"
        );
        return None;
    }
    if resolved.addrs.is_empty() {
        tracing::warn!(
            ingress = %route_id,
            service = %mirror_ref.service,
            namespace = %mirror_ns,
            port = mirror_ref.port,
            "mirror-target has no ready endpoints"
        );
    }
    let mirror_group = Arc::new(BackendGroup::new(
        format!("{mirror_ns}/{}", mirror_ref.service),
        resolved.addrs,
    ));
    Some(FilterAction::Mirror {
        backend: mirror_group,
        fraction: None, // annotation mirror always sends 100%
    })
}

// ── Auth resolution ───────────────────────────────────────────────────────────

/// Resolve the `auth-basic-secret` annotation's `Secret` reference into a
/// concrete [`IngressAuthConfig`] using the label-scoped `auth_secrets` store.
///
/// Looked up in `auth_secrets` (the label-scoped reflector); on success, the
/// `"auth"` key is parsed with [`parse_htpasswd`]. Any failure (missing
/// secret, missing key, no parseable entries) emits a contextual `WARN` and
/// returns `IngressAuthConfig::Unavailable` so the proxy fails closed with
/// 503 rather than silently bypassing auth. `annotation: None` returns `None`
/// (no basic-auth check configured).
pub(super) fn resolve_basic_auth_config(
    annotation: Option<&SecretRef>,
    auth_secrets: &reflector::Store<Secret>,
    route_id: &str,
    ingress_ns: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<IngressAuthConfig> {
    let secret_ref = annotation?;
    // The `auth-basic-secret` annotation is `namespace/name`; the
    // namespace component defaults to the Ingress's own namespace.
    let ns = if secret_ref.namespace.is_empty() {
        ingress_ns
    } else {
        &secret_ref.namespace
    };
    let key = reflector::ObjectRef::<Secret>::new(&secret_ref.name).within(ns);
    let Some(secret) = auth_secrets.get(&key) else {
        tracing::warn!(
            ingress = %route_id,
            secret_ns = %ns,
            secret_name = %secret_ref.name,
            "auth-basic-secret not found in auth-secret reflector — \
             is the Secret labeled ingress.coxswain-labs.dev/auth-basic=true? \
             failing closed (503)"
        );
        return Some(IngressAuthConfig::Unavailable);
    };
    // Belt-and-suspenders: the label-scoped reflector only shows
    // labeled secrets, but guard against label removal during a
    // reconcile race.
    let has_label = secret
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get("ingress.coxswain-labs.dev/auth-basic"))
        .is_some_and(|v| v == "true");
    if !has_label {
        tracing::warn!(
            ingress = %route_id,
            secret_ns = %ns,
            secret_name = %secret_ref.name,
            "Secret is missing label ingress.coxswain-labs.dev/auth-basic=true — \
             failing closed (503)"
        );
        return Some(IngressAuthConfig::Unavailable);
    }
    let Some(data) = secret
        .data
        .as_ref()
        .and_then(|d| d.get("auth"))
        .map(|b| &b.0)
    else {
        tracing::warn!(
            ingress = %route_id,
            secret_ns = %ns,
            secret_name = %secret_ref.name,
            "auth-basic-secret has no 'auth' data key (expected htpasswd file) — \
             failing closed (503)"
        );
        return Some(IngressAuthConfig::Unavailable);
    };
    let creds: Vec<BasicCredential> = parse_htpasswd(data, route_id, diag);
    if creds.is_empty() {
        tracing::warn!(
            ingress = %route_id,
            secret_ns = %ns,
            secret_name = %secret_ref.name,
            "auth-basic-secret has no parseable htpasswd entries \
             (supported: bcrypt $2y/$2b/$2a, SHA1 {{SHA}}...) \
             failing closed (503)"
        );
        return Some(IngressAuthConfig::Unavailable);
    }
    Some(IngressAuthConfig::Basic(creds.into()))
}

/// Resolve the `ext-auth` annotation's `CoxswainExternalAuth` CR reference
/// into a concrete [`IngressAuthConfig`] — the Ingress-parity counterpart to
/// the HTTPRoute `ExtensionRef` filter (#549). Delegates to
/// [`crate::gateway_api::external_auth::resolve_spec`] so both surfaces
/// resolve the same CR to byte-identical runtime config.
///
/// `annotation: None` (absent/malformed `ext-auth`) returns `None` — no
/// external-auth check on the route. A present-but-missing CR fails
/// **closed** (`Unavailable`, 503) — matching every other Ingress auth
/// annotation resolver in this file: an operator who set `ext-auth` intends
/// the route to require the check, so a stale or typo'd reference must not
/// silently disable it. `policy_ns` passed to `resolve_spec` is the
/// referenced CR's own namespace (`r.namespace`) — the CR's `backendRef` is
/// resolved relative to where the CR lives, not the Ingress.
pub(super) fn resolve_ext_auth_config(
    annotation: Option<&SecretRef>,
    external_auths: &reflector::Store<CoxswainExternalAuth>,
    services: &reflector::Store<Service>,
    slices: &reflector::Store<EndpointSlice>,
    backend_grants: &crate::reference_grants::GrantSet,
    route_id: &str,
) -> Option<IngressAuthConfig> {
    let r = annotation?;
    let obj_ref = reflector::ObjectRef::<CoxswainExternalAuth>::new(&r.name).within(&r.namespace);
    let Some(cr) = external_auths.get(&obj_ref) else {
        tracing::warn!(
            ingress = %route_id,
            namespace = %r.namespace,
            name = %r.name,
            "CoxswainExternalAuth CR not found — failing closed (503)"
        );
        return Some(IngressAuthConfig::Unavailable);
    };
    Some(crate::gateway_api::external_auth::resolve_spec(
        &cr.spec,
        &r.namespace,
        services,
        slices,
        backend_grants,
    ))
}

/// Resolve the `auth-jwt` annotation's `JwtAuth` CR reference into a concrete
/// [`IngressAuthConfig`] — the Ingress-parity counterpart to the HTTPRoute
/// `ExtensionRef` filter (#441). Delegates to
/// [`crate::gateway_api::jwt_auth::resolve_spec`] so both surfaces resolve the
/// same CR to byte-identical runtime config.
///
/// `annotation: None` (absent/malformed `auth-jwt`) returns `None` — no JWT
/// check on the route. A present-but-missing CR fails **closed**
/// (`Unavailable`, 503) — matching every other Ingress auth annotation
/// resolver in this file (`auth-basic-secret`, `auth-url`): an operator who
/// set `auth-jwt` intends the route to require a bearer token, so a stale or
/// typo'd reference must not silently disable authentication. A present CR
/// with an unresolved JWKS also fails **closed** inside `resolve_spec`.
pub(super) fn resolve_jwt_auth_config(
    annotation: Option<&super::annotations::auth::SecretRef>,
    jwt_auths: &reflector::Store<coxswain_core::crd::JwtAuth>,
    jwks_cache: &crate::jwks::SharedJwksCache,
    route_id: &str,
) -> Option<IngressAuthConfig> {
    let r = annotation?;
    let obj_ref =
        reflector::ObjectRef::<coxswain_core::crd::JwtAuth>::new(&r.name).within(&r.namespace);
    let Some(cr) = jwt_auths.get(&obj_ref) else {
        tracing::warn!(
            ingress = %route_id,
            namespace = %r.namespace,
            name = %r.name,
            "JwtAuth CR not found — failing closed (503)"
        );
        return Some(IngressAuthConfig::Unavailable);
    };
    Some(crate::gateway_api::jwt_auth::resolve_spec(
        &cr.spec, jwks_cache, route_id,
    ))
}

// ── Compression resolution ──────────────────────────────────────────────────────

/// Resolve the `compression` annotation's `Compression` CR reference into a
/// concrete [`CompressionConfig`] — the Ingress-parity counterpart to the
/// HTTPRoute `ExtensionRef` filter (#550). Delegates to
/// [`crate::gateway_api::compression::resolve_spec`] so both surfaces resolve
/// the same CR to byte-identical runtime config.
///
/// `annotation: None` (absent/malformed `compression`) returns `None` — no
/// compression on the route. Unlike every auth resolver in this file, a
/// present-but-missing CR (or one with both `gzip`/`brotli` disabled) fails
/// **open** — `None`, no compression — matching the HTTPRoute `ExtensionRef`
/// path's fail-open posture: a broken compression reference degrades to
/// uncompressed responses, not a 503.
pub(super) fn resolve_compression_config(
    annotation: Option<&SecretRef>,
    compressions: &reflector::Store<Compression>,
    route_id: &str,
) -> Option<Arc<CompressionConfig>> {
    let r = annotation?;
    let obj_ref = reflector::ObjectRef::<Compression>::new(&r.name).within(&r.namespace);
    let Some(cr) = compressions.get(&obj_ref) else {
        tracing::warn!(
            ingress = %route_id,
            namespace = %r.namespace,
            name = %r.name,
            "Compression CR not found — compression skipped (fail-open)"
        );
        return None;
    };
    crate::gateway_api::compression::resolve_spec(&cr.spec)
}

// ── Retry resolution ─────────────────────────────────────────────────────────

/// Resolve the `retry` annotation's `RetryPolicy` CR reference into a concrete
/// [`RetryPolicyConfig`] — the Ingress-parity counterpart to the HTTPRoute
/// `ExtensionRef` filter (#551). Delegates to
/// [`crate::gateway_api::retry::resolve_spec`] so both surfaces resolve the
/// same CR to byte-identical runtime config. Ingress is HTTP-only, so
/// `is_grpc` is always `false`.
///
/// `annotation: None` (absent/malformed `retry`) returns
/// [`RetryPolicyConfig::default()`] — no retries. Unlike every auth resolver
/// in this file, a present-but-missing CR fails **open** — the default
/// disabled policy — matching the HTTPRoute `ExtensionRef` path's fail-open
/// posture: a broken retry reference degrades to no retries, not a 503.
pub(super) fn resolve_retry_config(
    annotation: Option<&SecretRef>,
    retry_policies: &reflector::Store<RetryPolicy>,
    route_id: &str,
) -> RetryPolicyConfig {
    let Some(r) = annotation else {
        return RetryPolicyConfig::default();
    };
    let obj_ref = reflector::ObjectRef::<RetryPolicy>::new(&r.name).within(&r.namespace);
    let Some(cr) = retry_policies.get(&obj_ref) else {
        tracing::warn!(
            ingress = %route_id,
            namespace = %r.namespace,
            name = %r.name,
            "RetryPolicy CR not found — retries disabled (fail-open)"
        );
        return RetryPolicyConfig::default();
    };
    crate::gateway_api::retry::resolve_spec(&cr.spec, false, route_id)
}

// ── Rate-limit resolution ───────────────────────────────────────────────────

/// Resolve the `rate-limit` annotation's `RateLimit` CR reference into a
/// concrete [`RateLimitConfig`] — the Ingress-parity counterpart to the
/// HTTPRoute/GRPCRoute `ExtensionRef` filter (#552). Delegates to
/// [`crate::gateway_api::rate_limit::resolve_spec`] so both surfaces resolve
/// the same CR to byte-identical runtime config.
///
/// A missing CR fails **open** (`None`, no rate limiting) — unlike the auth
/// resolvers above, a broken rate-limit reference degrades gracefully rather
/// than blocking traffic.
///
/// The `by_header` field is a CR field, unknown until the CR is resolved —
/// unlike the former inline `rate-limit-by` annotation, whose header-without-auth
/// bypass-risk advisory (#411) fired at parse time. That check moves here:
/// `has_auth` (computed by the caller from the Ingress's own auth annotations)
/// suppresses the advisory when an auth check is also configured on the route.
pub(super) fn resolve_rate_limit_config(
    annotation: Option<&SecretRef>,
    rate_limits: &reflector::Store<RateLimit>,
    route_id: &str,
    has_auth: bool,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<Arc<RateLimitConfig>> {
    let r = annotation?;
    let obj_ref = reflector::ObjectRef::<RateLimit>::new(&r.name).within(&r.namespace);
    let Some(cr) = rate_limits.get(&obj_ref) else {
        tracing::warn!(
            ingress = %route_id,
            namespace = %r.namespace,
            name = %r.name,
            "RateLimit CR not found — rate limiting skipped (fail-open)"
        );
        return None;
    };
    if cr.spec.by_header.is_some() && !has_auth {
        tracing::warn!(
            ingress = %route_id,
            annotation = traffic_policy::RATE_LIMIT,
            "header keying allows rate-limit bypass via header-value rotation; \
             pair with an ip-keyed RateLimit or an auth-* annotation"
        );
        diag.push(AnnotationIssue {
            annotation: traffic_policy::RATE_LIMIT,
            message: "header keying allows rate-limit bypass via header-value rotation; \
                      pair with an ip-keyed RateLimit or an auth-* annotation"
                .into(),
        });
    }
    crate::gateway_api::rate_limit::resolve_spec(&cr.spec)
}

// ── IP-access-control resolution ────────────────────────────────────────────

/// Resolve the `ip-access-control` annotation's `IpAccessControl` CR reference
/// into the `(allow, deny)` CIDR sets — the Ingress-parity counterpart to the
/// HTTPRoute/GRPCRoute `ExtensionRef` filter (#553). Delegates to
/// [`crate::gateway_api::ip_access_control::resolve_spec`] so both surfaces
/// resolve the same CR to byte-identical CIDR sets.
///
/// A missing CR fails **open** (`(None, None)`, no IP filtering) — matching
/// the `ExtensionRef` path's fail-open posture: a broken reference degrades to
/// unfiltered traffic rather than blocking every request.
pub(super) fn resolve_ip_access_control_config(
    annotation: Option<&SecretRef>,
    ip_access_controls: &reflector::Store<IpAccessControl>,
    route_id: &str,
) -> (
    crate::gateway_api::ip_access_control::CidrSet,
    crate::gateway_api::ip_access_control::CidrSet,
) {
    let Some(r) = annotation else {
        return (None, None);
    };
    let obj_ref = reflector::ObjectRef::<IpAccessControl>::new(&r.name).within(&r.namespace);
    let Some(cr) = ip_access_controls.get(&obj_ref) else {
        tracing::warn!(
            ingress = %route_id,
            namespace = %r.namespace,
            name = %r.name,
            "IpAccessControl CR not found — IP access control skipped (fail-open)"
        );
        return (None, None);
    };
    crate::gateway_api::ip_access_control::resolve_spec(&cr.spec, &r.namespace, &r.name)
}

/// Prepend an HTTPS `RequestRedirect` to `base`, returning the combined filter list.
///
/// The HTTP-listener entry of an `ssl-redirect` route carries this leading
/// redirect (308 by default); the HTTPS-listener entry serves `base` unchanged.
/// Shared by the rule-path and defaultBackend insertion sites so the two stay in
/// sync (#397).
pub(super) fn prepend_ssl_redirect(status_code: u16, base: &[FilterAction]) -> Vec<FilterAction> {
    let mut filters = Vec::with_capacity(base.len() + 1);
    filters.push(FilterAction::RequestRedirect {
        scheme: Some("https".to_string()),
        hostname: None,
        port: None,
        status_code,
        path: None,
    });
    filters.extend_from_slice(base);
    filters
}

/// Resolve the host-router builder for `(port, host)` and apply the Ingress's
/// path-normalize level (#280) before any routes are added.
///
/// First-writer-wins across Ingresses sharing the same host: the builder emits a
/// WARN and keeps the first level on conflict. Centralising the
/// `set_path_normalize` call here keeps the three host-builder resolution sites
/// (rule paths, defaultBackend on rule hosts, defaultBackend catch-all) in sync
/// (#397).
pub(super) fn resolve_host_builder<'b>(
    builder: &'b mut IngressRoutingTableBuilder,
    port: u16,
    host: Option<&str>,
    path_normalize: Option<NormalizeLevel>,
) -> &'b mut HostRouterBuilder {
    let host_builder = builder
        .for_port(port)
        .host_for(host, WildcardKind::SingleLabel);
    if let Some(level) = path_normalize {
        host_builder.set_path_normalize(level);
    }
    host_builder
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::fixtures::{
        empty_compression_store, empty_external_auth_store, empty_ip_access_store,
        empty_jwks_cache, empty_jwt_auth_store, empty_rate_limit_store, empty_retry_policy_store,
        empty_secret_store, empty_svc_store, make_ip_access_store, make_rate_limit_store,
        slice_store,
    };
    use coxswain_core::crd::{IpAccessControl, RateLimit};
    use coxswain_core::routing::RateLimitKey;

    // `IpAccessControlSpec` is `#[non_exhaustive]` — deserialize a CR instead.
    fn ip_access_cr(ns: &str, name: &str, allow: &[&str], deny: &[&str]) -> IpAccessControl {
        let fmt_list = |xs: &[&str]| xs.iter().map(|x| format!("\n  - {x}")).collect::<String>();
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: IpAccessControl\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  allow:{}\n  deny:{}\n",
            fmt_list(allow),
            fmt_list(deny),
        );
        serde_yaml::from_str(&yaml).expect("valid IpAccessControl")
    }

    // `RateLimitSpec` is `#[non_exhaustive]` — deserialize a CR instead.
    fn rate_limit_cr(ns: &str, name: &str, by_header: Option<&str>) -> RateLimit {
        let by_header_field = by_header
            .map(|h| format!("\n  byHeader: {h}"))
            .unwrap_or_default();
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: RateLimit\n\
             metadata:\n  name: {name}\n  namespace: {ns}\n\
             spec:\n  requestsPerSecond: 10{by_header_field}\n",
        );
        serde_yaml::from_str(&yaml).expect("valid RateLimit")
    }

    fn secret_ref(namespace: &str, name: &str) -> SecretRef {
        SecretRef {
            namespace: namespace.to_string(),
            name: name.to_string(),
        }
    }

    #[test]
    fn resolve_basic_auth_config_absent_annotation_is_none() {
        let store = empty_secret_store();
        let mut diag = vec![];
        assert!(
            resolve_basic_auth_config(None, &store, "default/ing", "default", &mut diag).is_none()
        );
    }

    #[test]
    fn resolve_basic_auth_config_missing_secret_fails_closed() {
        let r = secret_ref("default", "absent");
        let store = empty_secret_store();
        let mut diag = vec![];
        let resolved =
            resolve_basic_auth_config(Some(&r), &store, "default/ing", "default", &mut diag)
                .expect("missing Secret must still install a check (fail closed)");
        assert!(matches!(resolved, IngressAuthConfig::Unavailable));
    }

    #[test]
    fn resolve_ext_auth_config_absent_annotation_is_none() {
        let store = empty_external_auth_store();
        let svcs = empty_svc_store();
        let slices = slice_store(vec![]);
        let grants = crate::reference_grants::GrantSet::default();
        assert!(
            resolve_ext_auth_config(None, &store, &svcs, &slices, &grants, "default/ing").is_none()
        );
    }

    #[test]
    fn resolve_ext_auth_config_missing_cr_fails_closed() {
        // Every other Ingress auth annotation resolver in this file fails
        // closed on a missing referenced resource; `ext-auth` must match, not
        // silently disable the auth check an operator asked for.
        let r = secret_ref("default", "absent");
        let store = empty_external_auth_store();
        let svcs = empty_svc_store();
        let slices = slice_store(vec![]);
        let grants = crate::reference_grants::GrantSet::default();
        let resolved =
            resolve_ext_auth_config(Some(&r), &store, &svcs, &slices, &grants, "default/ing")
                .expect("missing CR must still install a check (fail closed)");
        assert!(matches!(resolved, IngressAuthConfig::Unavailable));
    }

    #[test]
    fn resolve_jwt_auth_config_absent_annotation_is_none() {
        let store = empty_jwt_auth_store();
        let cache = empty_jwks_cache();
        assert!(resolve_jwt_auth_config(None, &store, &cache, "default/ing").is_none());
    }

    #[test]
    fn resolve_jwt_auth_config_missing_cr_fails_closed() {
        // Every other Ingress auth annotation resolver in this file fails
        // closed on a missing referenced resource; `auth-jwt` must match, not
        // silently disable the auth check an operator asked for.
        let r = secret_ref("default", "absent");
        let store = empty_jwt_auth_store();
        let cache = empty_jwks_cache();
        let resolved = resolve_jwt_auth_config(Some(&r), &store, &cache, "default/ing")
            .expect("missing CR must still install a check (fail closed)");
        assert!(matches!(resolved, IngressAuthConfig::Unavailable));
    }

    #[test]
    fn resolve_compression_config_absent_annotation_is_none() {
        let store = empty_compression_store();
        assert!(resolve_compression_config(None, &store, "default/ing").is_none());
    }

    #[test]
    fn resolve_compression_config_missing_cr_fails_open() {
        // Unlike every auth resolver above, a missing Compression reference
        // must NOT install a fail-closed check — compression degrades to
        // "no compression", matching the HTTPRoute ExtensionRef path. The
        // "resolved" and "both-disabled" cases are covered by
        // `gateway_api::compression::resolve_spec`'s own test module, which
        // this function delegates to.
        let r = secret_ref("default", "absent");
        let store = empty_compression_store();
        assert!(resolve_compression_config(Some(&r), &store, "default/ing").is_none());
    }

    #[test]
    fn resolve_retry_config_absent_annotation_is_disabled_default() {
        let store = empty_retry_policy_store();
        assert!(resolve_retry_config(None, &store, "default/ing").is_disabled());
    }

    #[test]
    fn resolve_retry_config_missing_cr_fails_open() {
        // Unlike every auth resolver above, a missing RetryPolicy reference
        // must NOT install a fail-closed check — retries degrade to "disabled",
        // matching the HTTPRoute ExtensionRef path. The "resolved" case is
        // covered by `gateway_api::retry::resolve_spec`'s own test module,
        // which this function delegates to.
        let r = secret_ref("default", "absent");
        let store = empty_retry_policy_store();
        assert!(resolve_retry_config(Some(&r), &store, "default/ing").is_disabled());
    }

    #[test]
    fn resolve_rate_limit_config_absent_annotation_is_none() {
        let store = empty_rate_limit_store();
        let mut diag = vec![];
        assert!(resolve_rate_limit_config(None, &store, "default/ing", false, &mut diag).is_none());
        assert!(diag.is_empty());
    }

    #[test]
    fn resolve_rate_limit_config_missing_cr_fails_open() {
        // Unlike every auth resolver above, a missing RateLimit reference must
        // NOT install a fail-closed check — rate limiting degrades to "no
        // limit", matching the HTTPRoute/GRPCRoute ExtensionRef path. The
        // "resolved" case is covered by `gateway_api::rate_limit::resolve_spec`'s
        // own test module, which this function delegates to.
        let r = secret_ref("default", "absent");
        let store = empty_rate_limit_store();
        let mut diag = vec![];
        assert!(
            resolve_rate_limit_config(Some(&r), &store, "default/ing", false, &mut diag).is_none()
        );
        assert!(diag.is_empty());
    }

    #[test]
    fn resolve_rate_limit_config_header_without_auth_pushes_diag() {
        let r = secret_ref("default", "by-header");
        let store = make_rate_limit_store(vec![rate_limit_cr(
            "default",
            "by-header",
            Some("X-Api-Key"),
        )]);
        let mut diag = vec![];
        let cfg = resolve_rate_limit_config(Some(&r), &store, "default/ing", false, &mut diag)
            .expect("resolved");
        assert_eq!(cfg.key, RateLimitKey::Header(Arc::from("x-api-key")));
        assert_eq!(diag.len(), 1);
        assert_eq!(diag[0].annotation, traffic_policy::RATE_LIMIT);
    }

    #[test]
    fn resolve_rate_limit_config_header_with_auth_no_diag() {
        let r = secret_ref("default", "by-header");
        let store = make_rate_limit_store(vec![rate_limit_cr(
            "default",
            "by-header",
            Some("X-Api-Key"),
        )]);
        let mut diag = vec![];
        assert!(
            resolve_rate_limit_config(Some(&r), &store, "default/ing", true, &mut diag).is_some()
        );
        assert!(diag.is_empty());
    }

    #[test]
    fn resolve_rate_limit_config_ip_keyed_no_diag_regardless_of_auth() {
        let r = secret_ref("default", "ip-keyed");
        let store = make_rate_limit_store(vec![rate_limit_cr("default", "ip-keyed", None)]);
        let mut diag = vec![];
        assert!(
            resolve_rate_limit_config(Some(&r), &store, "default/ing", false, &mut diag).is_some()
        );
        assert!(diag.is_empty());
    }

    #[test]
    fn resolve_ip_access_control_config_absent_annotation_is_none() {
        let store = empty_ip_access_store();
        let (allow, deny) = resolve_ip_access_control_config(None, &store, "default/ing");
        assert!(allow.is_none());
        assert!(deny.is_none());
    }

    #[test]
    fn resolve_ip_access_control_config_missing_cr_fails_open() {
        // Unlike every auth resolver above, a missing IpAccessControl reference
        // must NOT install a fail-closed check — IP filtering degrades to "no
        // filtering", matching the HTTPRoute/GRPCRoute ExtensionRef path. The
        // "resolved" case is covered by
        // `gateway_api::ip_access_control::resolve_spec`'s own test module,
        // which this function delegates to.
        let r = secret_ref("default", "absent");
        let store = empty_ip_access_store();
        let (allow, deny) = resolve_ip_access_control_config(Some(&r), &store, "default/ing");
        assert!(allow.is_none());
        assert!(deny.is_none());
    }

    #[test]
    fn resolve_ip_access_control_config_present_cr_resolves_allow_and_deny() {
        let r = secret_ref("default", "policy");
        let store = make_ip_access_store(vec![ip_access_cr(
            "default",
            "policy",
            &["203.0.113.0/24"],
            &["10.0.0.0/8"],
        )]);
        let (allow, deny) = resolve_ip_access_control_config(Some(&r), &store, "default/ing");
        assert_eq!(
            *allow.expect("allow set"),
            vec!["203.0.113.0/24".parse::<ipnet::IpNet>().expect("valid")]
        );
        assert_eq!(
            *deny.expect("deny set"),
            vec!["10.0.0.0/8".parse::<ipnet::IpNet>().expect("valid")]
        );
    }
}
