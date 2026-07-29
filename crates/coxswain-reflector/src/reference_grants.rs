//! `ReferenceGrant` flattening consumed by the proxy reconciler.
//!
//! Centralising the flatten logic here ensures the shared-pool builder and
//! the dedicated-mode snapshot builder derive identical permitted-reference
//! sets from the same input, so the two code paths cannot drift.
//!
//! Every `flatten_*_grants` function returns a [`GrantSet`] parameterized by a
//! marker type below naming the `(from.group, from.kind, to.kind)` triple it
//! was flattened for. Two sets flattened for different triples are different
//! Rust types even though both wrap the same `HashSet<ReferenceGrantKey>`
//! shape — passing e.g. an `HTTPRoute`-flattened set where a `GRPCRoute`-flattened
//! one is expected is a compile error, not a silent value-level mistake (#691).

// The coxswain-proprietary CRD group (`BasicAuth`, `RateLimit`, … ExtensionRef CRDs);
// re-uses the single definition in `gateway_api` rather than a second local copy.
use crate::gateway_api::COXSWAIN_GROUP;
use crate::gw_types::v::referencegrants::ReferenceGrantSpec;
pub use coxswain_core::reference_grants::GrantSet;
use coxswain_core::reference_grants::ReferenceGrantKey;
use kube::core::{NotUsed, Object};
use std::sync::Arc;

/// A `ReferenceGrant` whose API version is negotiated at runtime rather than
/// fixed at compile time.
///
/// `ReferenceGrant` is the one Gateway API kind whose *served version* moves
/// across the versions Coxswain supports: v1.4 serves only `v1beta1`, v1.5+
/// serve both `v1` and `v1beta1`. The generated typed binding is pinned to
/// `v1`, so watching it against a v1.4 cluster 404s on every relist forever —
/// the capability gate cannot help, because the kind *is* present, just at a
/// different version.
///
/// [`kube::core::Object`] carries its [`kube::core::discovery::ApiResource`] as
/// runtime data, so the reflector watches whichever version discovery reported.
/// Only `spec.from` / `spec.to` are ever read and those are byte-identical
/// between the two versions, so nothing downstream needs to know which one it
/// got. `NotUsed` for the status: `ReferenceGrant` has none.
pub type DynamicReferenceGrant = Object<ReferenceGrantSpec, NotUsed>;

/// Marker for [`flatten_grants`]'s `backend_grants`: `HTTPRoute → Service`.
/// Also covers HTTPRoute's `RequestMirror` filter backend (a mirror target is
/// still an HTTPRoute-sourced ref).
pub struct HttpRouteBackend;

/// Marker for [`flatten_grpc_backend_grants`]: `GRPCRoute → Service`.
pub struct GrpcRouteBackend;

/// Marker for [`flatten_tls_backend_grants`]: `TLSRoute → Service`.
pub struct TlsRouteBackend;

/// Marker for [`flatten_tcp_backend_grants`]: `TCPRoute → Service`.
pub struct TcpRouteBackend;

/// Marker for [`flatten_udp_backend_grants`]: `UDPRoute → Service`.
pub struct UdpRouteBackend;

/// Marker for [`flatten_grants`]'s `cert_grants`: `Gateway → Secret`.
pub struct GatewayCert;

/// Marker for [`flatten_ls_cert_grants`]: `ListenerSet → Secret`.
pub struct ListenerSetCert;

/// Marker for [`flatten_ca_grants`]: `Gateway → ConfigMap`.
pub struct GatewayCa;

/// Marker for [`flatten_basic_auth_secret_grants`]: `BasicAuth → Secret`.
pub struct BasicAuthSecret;

/// Marker for [`flatten_external_auth_backend_grants`]: `CoxswainExternalAuth → Service`.
pub struct ExternalAuthBackend;

/// Flatten `ReferenceGrant` objects into the two O(1) sets [`GatewayApiReconciler`]
/// needs for cross-namespace reference checks:
///
/// - `backend_grants`: `HTTPRoute → Service` (used by the routing-table
///   builder when resolving HTTPRoute `backendRefs` across namespaces).
/// - `cert_grants`: `Gateway → Secret` (used by the TLS store builder when
///   resolving listener `certificateRefs` across namespaces).
///
/// The filter rules mirror the Gateway API spec: `from.group` must be
/// `gateway.networking.k8s.io` and `to.group` must be empty (the spec's only
/// core-API-group spelling). Coxswain additionally accepts the literal
/// `"core"` as a deliberate leniency, not a spec-sanctioned alias. A `to.name`
/// of `None` flattens to a wildcard
/// [`ReferenceGrantKey::wildcard`]; a `Some(name)` flattens to a
/// [`ReferenceGrantKey::specific`].
///
/// [`GatewayApiReconciler`]: crate::gateway_api::GatewayApiReconciler
#[must_use]
pub fn flatten_grants(
    grants: &[Arc<DynamicReferenceGrant>],
) -> (GrantSet<HttpRouteBackend>, GrantSet<GatewayCert>) {
    let backend_grants = flatten(grants, GATEWAY_API_GROUP, "HTTPRoute", "Service");
    let cert_grants = flatten(grants, GATEWAY_API_GROUP, "Gateway", "Secret");
    (backend_grants, cert_grants)
}

/// The upstream Gateway API `from.group` most cross-namespace refs originate from.
const GATEWAY_API_GROUP: &str = "gateway.networking.k8s.io";

/// Flatten the `BasicAuth → Secret` grants that authorize a `BasicAuth` CR to
/// reference its htpasswd `secretRef` in another namespace (#520).
///
/// The referrer is the `BasicAuth` CR itself, so the grant's `from.kind` is
/// `BasicAuth` in the proprietary `gateway.coxswain-labs.dev` group — mirroring how
/// Envoy Gateway's `SecurityPolicy` gates its secret refs by its own kind/group,
/// not by the route kind. Without a matching grant a cross-namespace `secretRef`
/// fails closed, so a tenant cannot bind another namespace's auth Secret.
#[must_use]
pub fn flatten_basic_auth_secret_grants(
    grants: &[Arc<DynamicReferenceGrant>],
) -> GrantSet<BasicAuthSecret> {
    flatten(grants, COXSWAIN_GROUP, "BasicAuth", "Secret")
}

/// Flatten the `CoxswainExternalAuth → Service` grants that authorize a
/// `CoxswainExternalAuth` CR to reference its auth-service `backendRef` in
/// another namespace (#691, matching `docs/src/gateway-api/route-extensions.md`).
///
/// The referrer is the `CoxswainExternalAuth` CR itself (its CRD `kind`, not
/// the `ExtensionRef`'s `kind: ExternalAuth` shorthand), so the grant's
/// `from.kind` is `CoxswainExternalAuth` in the proprietary
/// `gateway.coxswain-labs.dev` group — mirroring [`flatten_basic_auth_secret_grants`].
/// Consumed by all three ext-auth resolution surfaces: the Gateway-attached
/// `targetRefs` mandate, the route-level `ExtensionRef` filter, and the
/// Ingress `ext-auth` annotation.
#[must_use]
pub fn flatten_external_auth_backend_grants(
    grants: &[Arc<DynamicReferenceGrant>],
) -> GrantSet<ExternalAuthBackend> {
    flatten(grants, COXSWAIN_GROUP, "CoxswainExternalAuth", "Service")
}

/// Flatten the `Gateway → ConfigMap` grants used by GEP-91 frontend
/// client-certificate validation when a `caCertificateRefs` entry points at a
/// ConfigMap in another namespace (#86). Same filter rules as [`flatten_grants`].
#[must_use]
pub fn flatten_ca_grants(grants: &[Arc<DynamicReferenceGrant>]) -> GrantSet<GatewayCa> {
    flatten(grants, GATEWAY_API_GROUP, "Gateway", "ConfigMap")
}

/// Flatten the `ListenerSet → Secret` grants used when a `ListenerSet` HTTPS
/// listener's `certificateRefs` points at a Secret in another namespace
/// (GEP-1713, #93). A ListenerSet attaches its own listeners, so its
/// cross-namespace cert grant's `from.kind` is `ListenerSet` — not `Gateway`
/// (which [`flatten_grants`] handles for Gateway-owned listeners).
#[must_use]
pub fn flatten_ls_cert_grants(grants: &[Arc<DynamicReferenceGrant>]) -> GrantSet<ListenerSetCert> {
    flatten(grants, GATEWAY_API_GROUP, "ListenerSet", "Secret")
}

/// Flatten the `GRPCRoute → Service` grants used when a GRPCRoute `backendRef`
/// points at a Service in another namespace (#691). Kept separate from
/// [`flatten_grants`]'s `backend_grants` (`from.kind: HTTPRoute`) — see
/// [`flatten_tcp_backend_grants`]'s doc for why merging would be unsafe.
#[must_use]
pub fn flatten_grpc_backend_grants(
    grants: &[Arc<DynamicReferenceGrant>],
) -> GrantSet<GrpcRouteBackend> {
    flatten(grants, GATEWAY_API_GROUP, "GRPCRoute", "Service")
}

/// Flatten the `TLSRoute → Service` grants used when a TLSRoute `backendRef`
/// (passthrough or terminate) points at a Service in another namespace (#691).
/// Kept separate from [`flatten_grants`]'s `backend_grants` (`from.kind:
/// HTTPRoute`) — see [`flatten_tcp_backend_grants`]'s doc for why merging
/// would be unsafe.
#[must_use]
pub fn flatten_tls_backend_grants(
    grants: &[Arc<DynamicReferenceGrant>],
) -> GrantSet<TlsRouteBackend> {
    flatten(grants, GATEWAY_API_GROUP, "TLSRoute", "Service")
}

/// Flatten the `TCPRoute → Service` grants used when a TCPRoute `backendRef`
/// points at a Service in another namespace (GEP-1901, #505). Kept separate
/// from [`flatten_grants`]'s `backend_grants` (`from.kind: HTTPRoute`) rather
/// than folding into the same set: [`ReferenceGrantKey`] carries no
/// `from.kind`, so merging would let an HTTPRoute-scoped grant silently also
/// permit a TCPRoute's backendRef between the same namespace pair — the same
/// per-kind isolation [`flatten_ls_cert_grants`] applies to `ListenerSet`.
#[must_use]
pub fn flatten_tcp_backend_grants(
    grants: &[Arc<DynamicReferenceGrant>],
) -> GrantSet<TcpRouteBackend> {
    flatten(grants, GATEWAY_API_GROUP, "TCPRoute", "Service")
}

/// Flatten the `UDPRoute → Service` grants used when a UDPRoute `backendRef`
/// points at a Service in another namespace (GEP-2645, #506). Kept separate
/// from [`flatten_grants`]'s `backend_grants` (`from.kind: HTTPRoute`) and from
/// [`flatten_tcp_backend_grants`] for the same reason: [`ReferenceGrantKey`]
/// carries no `from.kind`, so merging would let an HTTPRoute- or TCPRoute-scoped
/// grant silently also permit a UDPRoute's backendRef between the same
/// namespace pair.
#[must_use]
pub fn flatten_udp_backend_grants(
    grants: &[Arc<DynamicReferenceGrant>],
) -> GrantSet<UdpRouteBackend> {
    flatten(grants, GATEWAY_API_GROUP, "UDPRoute", "Service")
}

fn flatten<K>(
    grants: &[Arc<DynamicReferenceGrant>],
    from_group: &str,
    from_kind: &str,
    to_kind: &str,
) -> GrantSet<K> {
    grants
        .iter()
        .filter_map(|grant| {
            let to_ns = grant.metadata.namespace.clone()?;
            Some((grant, to_ns))
        })
        .flat_map(|(grant, to_ns)| {
            let from_entries: Vec<_> = grant
                .spec
                .from
                .iter()
                .filter(|f| f.group == from_group && f.kind == from_kind)
                .map(|f| f.namespace.clone())
                .collect();
            let to_entries: Vec<_> = grant
                .spec
                .to
                .iter()
                .filter(|t| (t.group.is_empty() || t.group == "core") && t.kind == to_kind)
                .map(|t| t.name.clone())
                .collect();
            from_entries.into_iter().flat_map(move |from_ns| {
                let to_ns = to_ns.clone();
                to_entries
                    .clone()
                    .into_iter()
                    .map(move |to_name| match to_name {
                        Some(name) => {
                            ReferenceGrantKey::specific(from_ns.clone(), to_ns.clone(), name)
                        }
                        None => ReferenceGrantKey::wildcard(from_ns.clone(), to_ns.clone()),
                    })
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::gw_types::v::referencegrants::{
        ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo,
    };
    use crate::reference_grants::{DynamicReferenceGrant, flatten_grants};
    use coxswain_core::gateway_api_capability::{GATEWAY_API_GROUP, GatewayApiKind};
    use coxswain_core::reference_grants::ReferenceGrantKey;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::core::TypeMeta;
    use std::sync::Arc;

    fn grant(
        ns: &str,
        from: Vec<(&str, &str, Option<&str>)>,
        to: Vec<(&str, &str, Option<&str>)>,
    ) -> Arc<DynamicReferenceGrant> {
        Arc::new(DynamicReferenceGrant {
            types: Some(TypeMeta {
                api_version: format!("{GATEWAY_API_GROUP}/v1"),
                kind: GatewayApiKind::ReferenceGrant.as_str().to_string(),
            }),
            status: None,
            metadata: ObjectMeta {
                namespace: Some(ns.to_string()),
                name: Some("grant".to_string()),
                ..ObjectMeta::default()
            },
            spec: ReferenceGrantSpec {
                from: from
                    .into_iter()
                    .map(|(g, k, ns)| ReferenceGrantFrom {
                        group: g.to_string(),
                        kind: k.to_string(),
                        namespace: ns.unwrap_or_default().to_string(),
                    })
                    .collect(),
                to: to
                    .into_iter()
                    .map(|(g, k, name)| ReferenceGrantTo {
                        group: g.to_string(),
                        kind: k.to_string(),
                        name: name.map(str::to_string),
                    })
                    .collect(),
            },
        })
    }

    #[test]
    fn backend_and_cert_grants_partition_by_kind() {
        let grants = vec![
            // HTTPRoute(ns=routes) → Service(svc-a) in ns=backends
            grant(
                "backends",
                vec![("gateway.networking.k8s.io", "HTTPRoute", Some("routes"))],
                vec![("", "Service", Some("svc-a"))],
            ),
            // Gateway(ns=gw) → Secret(*) in ns=certs (wildcard)
            grant(
                "certs",
                vec![("gateway.networking.k8s.io", "Gateway", Some("gw"))],
                vec![("", "Secret", None)],
            ),
        ];

        let (backend, cert) = flatten_grants(&grants);

        assert!(backend.contains(&ReferenceGrantKey::specific("routes", "backends", "svc-a")));
        assert_eq!(backend.len(), 1);
        assert!(cert.contains(&ReferenceGrantKey::wildcard("gw", "certs")));
        assert_eq!(cert.len(), 1);
    }

    #[test]
    fn from_group_other_than_gateway_api_is_ignored() {
        let grants = vec![grant(
            "backends",
            vec![("example.com", "HTTPRoute", Some("routes"))],
            vec![("", "Service", Some("svc-a"))],
        )];

        let (backend, cert) = flatten_grants(&grants);

        assert!(backend.is_empty());
        assert!(cert.is_empty());
    }

    #[test]
    fn to_group_core_alias_matches_empty_group() {
        let grants = vec![grant(
            "backends",
            vec![("gateway.networking.k8s.io", "HTTPRoute", Some("routes"))],
            vec![("core", "Service", Some("svc-a"))],
        )];

        let (backend, _cert) = flatten_grants(&grants);

        assert!(backend.contains(&ReferenceGrantKey::specific("routes", "backends", "svc-a")));
    }

    #[test]
    fn grant_without_namespace_is_dropped() {
        let mut g = grant(
            "placeholder",
            vec![("gateway.networking.k8s.io", "HTTPRoute", Some("routes"))],
            vec![("", "Service", Some("svc-a"))],
        );
        Arc::get_mut(&mut g).unwrap().metadata.namespace = None;

        let (backend, cert) = flatten_grants(&[g]);

        assert!(backend.is_empty());
        assert!(cert.is_empty());
    }

    #[test]
    fn cross_product_yields_all_from_to_pairs() {
        let grants = vec![grant(
            "backends",
            vec![
                ("gateway.networking.k8s.io", "HTTPRoute", Some("ns-a")),
                ("gateway.networking.k8s.io", "HTTPRoute", Some("ns-b")),
            ],
            vec![
                ("", "Service", Some("svc-x")),
                ("", "Service", Some("svc-y")),
            ],
        )];

        let (backend, _cert) = flatten_grants(&grants);

        assert_eq!(backend.len(), 4);
        assert!(backend.contains(&ReferenceGrantKey::specific("ns-a", "backends", "svc-x")));
        assert!(backend.contains(&ReferenceGrantKey::specific("ns-a", "backends", "svc-y")));
        assert!(backend.contains(&ReferenceGrantKey::specific("ns-b", "backends", "svc-x")));
        assert!(backend.contains(&ReferenceGrantKey::specific("ns-b", "backends", "svc-y")));
    }

    #[test]
    fn grpc_and_tls_and_external_auth_grants_are_kind_scoped() {
        use crate::reference_grants::{
            flatten_external_auth_backend_grants, flatten_grpc_backend_grants,
            flatten_tls_backend_grants,
        };

        let grants = vec![
            grant(
                "backends",
                vec![("gateway.networking.k8s.io", "GRPCRoute", Some("routes"))],
                vec![("", "Service", Some("grpc-svc"))],
            ),
            grant(
                "backends2",
                vec![("gateway.networking.k8s.io", "TLSRoute", Some("routes"))],
                vec![("", "Service", Some("tls-svc"))],
            ),
            grant(
                "backends3",
                vec![(
                    "gateway.coxswain-labs.dev",
                    "CoxswainExternalAuth",
                    Some("routes"),
                )],
                vec![("", "Service", Some("auth-svc"))],
            ),
            // An HTTPRoute-from grant to the same namespaces must not leak
            // into any of the three kind-scoped sets above (#691's core bug).
            grant(
                "backends",
                vec![("gateway.networking.k8s.io", "HTTPRoute", Some("routes"))],
                vec![("", "Service", Some("grpc-svc"))],
            ),
        ];

        let grpc = flatten_grpc_backend_grants(&grants);
        let tls = flatten_tls_backend_grants(&grants);
        let ext_auth = flatten_external_auth_backend_grants(&grants);

        assert!(grpc.contains(&ReferenceGrantKey::specific(
            "routes", "backends", "grpc-svc"
        )));
        assert_eq!(
            grpc.len(),
            1,
            "HTTPRoute-from grant must not leak into the GRPCRoute set"
        );
        assert!(tls.contains(&ReferenceGrantKey::specific(
            "routes",
            "backends2",
            "tls-svc"
        )));
        assert_eq!(tls.len(), 1);
        assert!(ext_auth.contains(&ReferenceGrantKey::specific(
            "routes",
            "backends3",
            "auth-svc"
        )));
        assert_eq!(ext_auth.len(), 1);
    }
}
