//! Free helper functions extracted from [`super::reconcile`]: backend-group
//! construction, mirror-filter resolution, the auth-config resolution ladder,
//! the ssl-redirect filter prepend, and host-router builder resolution. Kept
//! beside the reconcile entry point but out of it to bound that file's size.

use super::annotations::AnnotationIssue;
use super::annotations::auth::{AuthAnnotation, ExtAuthProtocol, parse_htpasswd};
use crate::endpoints;
use coxswain_core::routing::{
    BackendGroup, BackendProtocol, BasicCredential, ExtAuthConfig, ExtAuthTransport, FilterAction,
    GrpcExtAuthConfig, HostRouterBuilder, HttpExtAuthConfig, IngressAuthConfig,
    IngressRoutingTableBuilder, NormalizeLevel, WildcardKind,
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
pub(super) fn build_ingress_backend_group(
    ns: &str,
    svc_name: &str,
    addrs: Vec<SocketAddr>,
    protocol: BackendProtocol,
    ann: &super::annotations::IngressAnnotations,
) -> BackendGroup {
    BackendGroup::new(format!("{ns}/{svc_name}"), addrs)
        .with_protocol(protocol)
        .with_retries(ann.retries)
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

/// Resolve an intermediate [`AuthAnnotation`] into a concrete
/// [`IngressAuthConfig`] using the label-scoped `auth_secrets` store.
///
/// - `External` → wrapped verbatim into `IngressAuthConfig::External`.
/// - `Basic(SecretRef)` → looked up in `auth_secrets` (the label-scoped
///   reflector); on success, the `"auth"` key is parsed with [`parse_htpasswd`].
///   Any failure (missing secret, missing key, no parseable entries) emits a
///   contextual `WARN` and returns `IngressAuthConfig::Unavailable` so the proxy
///   fails closed with 503 rather than silently bypassing auth.
/// - `None` annotation → returns `None` (no auth configured).
pub(super) fn resolve_auth_config(
    annotation: Option<&AuthAnnotation>,
    auth_secrets: &reflector::Store<Secret>,
    services: &reflector::Store<Service>,
    slices: &reflector::Store<EndpointSlice>,
    route_id: &str,
    ingress_ns: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<IngressAuthConfig> {
    let ann = annotation?;
    match ann {
        AuthAnnotation::External {
            backend,
            protocol,
            timeout,
            response_headers,
            always_set_cookie,
            fail_closed,
        } => {
            // Resolve the auth-service backendRef to pod endpoints, same as any
            // other backend. No ready endpoints → fail closed (503).
            let ns = backend.namespace.as_deref().unwrap_or(ingress_ns);
            let resolved =
                endpoints::resolve(ns, &backend.name, i32::from(backend.port), slices, services);
            if resolved.addrs.is_empty() {
                tracing::warn!(
                    ingress = %route_id,
                    auth_ns = %ns,
                    auth_svc = %backend.name,
                    auth_port = backend.port,
                    "ext-auth-backend resolved to no ready endpoints — failing closed (503)"
                );
                return Some(IngressAuthConfig::Unavailable);
            }
            let endpoints_arc: Arc<[SocketAddr]> = resolved.addrs.into();
            let resp_hdrs: Arc<[Box<str>]> = response_headers
                .iter()
                .map(|s| s.as_str().into())
                .collect::<Vec<Box<str>>>()
                .into();
            let transport = match protocol {
                ExtAuthProtocol::Http => {
                    ExtAuthTransport::Http(HttpExtAuthConfig::new(resp_hdrs, *always_set_cookie))
                }
                ExtAuthProtocol::Grpc => {
                    // Envoy `envoy.service.auth.v3.Authorization/Check` (#23 P4).
                    // `always_set_cookie` has no gRPC analogue (the auth service
                    // returns typed OK/Denied responses, not raw HTTP headers).
                    ExtAuthTransport::Grpc(GrpcExtAuthConfig::new(resp_hdrs))
                }
            };
            Some(IngressAuthConfig::External(ExtAuthConfig::new(
                *timeout,
                endpoints_arc,
                *fail_closed,
                transport,
            )))
        }
        AuthAnnotation::Basic(secret_ref) => {
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
    }
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
