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

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

/// Maximum nesting depth for `Mirror` backends in `from_wire`.
///
/// Prevents unbounded recursion through untrusted proto bytes where a Mirror
/// backend itself carries a per-backend filter that embeds another Mirror, etc.
/// Trees only in practice; this guard is a safety net for malformed input.
pub const MAX_MIRROR_DEPTH: usize = 4;

mod decode;
mod encode;

// `protocol_from_wire` is reused by `wire::endpoints`. `build_route_table` plus
// the L4 decoders are the per-cell compile seams the client's partitioned apply
// (`crate::apply`, #383) reuses to recompile only dirty resources.
pub(crate) use decode::{
    build_route_table, passthrough_from_wire, protocol_from_wire, tcp_table_from_wire,
    udp_table_from_wire,
};
// Backend/rate-limit/tls decoders and the whole-world `decode_world` oracle are
// exercised directly by unit tests; production decode now goes partition- and
// cell-wise through `crate::apply`.
#[cfg(test)]
pub(crate) use decode::{bg_from_wire, decode_world, rate_limit_from_wire, upstream_tls_from_wire};
// Per-resource emitters + the endpoint collector: the server's materialize path
// walks the tables once and folds these into the view.
#[cfg(test)]
pub(crate) use encode::upstream_tls_to_wire;
pub(crate) use encode::{
    EndpointCollector, gateway_route_resources, ingress_route_resources, passthrough_resources,
    tcp_resources, udp_resources,
};

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use std::time::Duration;

    use coxswain_core::routing::{
        BackendClientCert, BackendGroup, CompressionConfig, FilterAction, MatchPredicates,
        NormalizeLevel, PathModifier, RateLimitConfig, RateLimitKey, RouteEntry, RouteTimeouts,
        SubjectAltName, UpstreamCa, UpstreamTls, WildcardKind,
    };

    use super::{
        EndpointCollector, MAX_MIRROR_DEPTH, bg_from_wire, decode_world, gateway_route_resources,
        ingress_route_resources, rate_limit_from_wire, upstream_tls_from_wire,
        upstream_tls_to_wire,
    };
    use crate::error::WireError;
    use crate::proto::v1 as p;
    use crate::wire::tests::*;
    use coxswain_core::endpoints::EndpointPool;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Encode a routing table to its resource set (routes + any referenced
    /// endpoints), the shape the server ships and the client applies (#383).
    pub(super) fn ingress_resources(
        t: &coxswain_core::routing::IngressRoutingTable,
    ) -> Vec<p::Resource> {
        let mut coll = EndpointCollector::new();
        let mut resources = ingress_route_resources(t, &mut coll);
        resources.extend(coll.into_resources());
        resources
    }

    pub(super) fn gateway_resources(
        t: &coxswain_core::routing::GatewayRoutingTable,
    ) -> Vec<p::Resource> {
        let mut coll = EndpointCollector::new();
        let mut resources = gateway_route_resources(t, &mut coll);
        resources.extend(coll.into_resources());
        resources
    }

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
        let resources = ingress_resources(&t);
        decode_world(&resources).expect("decode_world").ingress
    }

    pub(super) fn rt_gateway(
        builder: GatewayRoutingTableBuilder,
    ) -> coxswain_core::routing::GatewayRoutingTable {
        let t = builder.build().expect("build");
        let resources = gateway_resources(&t);
        decode_world(&resources).expect("decode_world").gateway
    }

    // ── #383 endpoint refs + status provenance ────────────────────────────────

    /// An Ingress route-host resource whose single backend references an endpoint
    /// resource by `(ns, svc, svc_port)` — no inline addrs. Optionally bakes a
    /// server-side `error_status` (the endpoint-independent path).
    fn keyed_route_resource(
        host: &str,
        ns: &str,
        svc: &str,
        svc_port: u32,
        baked: Option<u32>,
    ) -> p::Resource {
        let bg = p::BackendGroup {
            name: format!("{ns}/{svc}"),
            weighted: vec![p::WeightedBackend {
                addrs: Vec::new(),
                weight: 1,
                endpoint_ref: Some(p::EndpointRef {
                    namespace: ns.to_owned(),
                    service: svc.to_owned(),
                    port: svc_port,
                }),
            }],
            load_balance: Some(p::LoadBalance {
                algorithm: Some(p::load_balance::Algorithm::RoundRobin(true)),
            }),
            ..Default::default()
        };
        let route = p::RouteEntry {
            kind: p::RouteKind::Prefix as i32,
            path: "/".to_owned(),
            backend_group: Some(bg),
            error_status: baked,
            ..Default::default()
        };
        p::Resource {
            payload: Some(p::resource::Payload::RouteHost(p::RouteHostResource {
                table: p::RouteTableKind::Ingress as i32,
                port: 80,
                host: Some(p::HostEntry {
                    pattern: Some(p::host_entry::Pattern::Exact(host.to_owned())),
                    normalize_level: 0,
                    routes: vec![route],
                }),
            })),
            ..Default::default()
        }
    }

    fn endpoint_resource(
        ns: &str,
        svc: &str,
        port: u32,
        exists: bool,
        addrs: &[&str],
    ) -> p::Resource {
        p::Resource {
            payload: Some(p::resource::Payload::Endpoints(p::EndpointResource {
                namespace: ns.to_owned(),
                service: svc.to_owned(),
                port,
                app_protocol: 0,
                service_exists: exists,
                addrs: addrs.iter().map(|s| (*s).to_owned()).collect(),
            })),
            ..Default::default()
        }
    }

    /// A keyed backend that resolves to real endpoints routes normally — the
    /// client resolves the ref against the message pool (no inline addrs).
    #[test]
    fn keyed_ref_resolves_from_pool() {
        let resources = vec![
            keyed_route_resource("api.example.com", "default", "svc", 80, None),
            endpoint_resource("default", "svc", 80, true, &["10.0.0.1:8080"]),
        ];
        let world = decode_world(&resources).expect("decode_world");
        let bg = world
            .ingress
            .route(80, "api.example.com", "/", &ctx())
            .expect("route resolves via endpoint ref");
        assert_eq!(bg.endpoints(), &["10.0.0.1:8080".parse().unwrap()]);
    }

    /// A dangling ref (no matching endpoint resource) is a hard protocol error.
    #[test]
    fn dangling_ref_errors() {
        let resources = vec![keyed_route_resource(
            "api.example.com",
            "default",
            "svc",
            80,
            None,
        )];
        // DecodedWorld is not Debug (routing tables aren't), so match rather than unwrap_err.
        let err = match decode_world(&resources) {
            Ok(_) => panic!("expected a dangling-ref error, got a decoded world"),
            Err(e) => e,
        };
        assert!(
            matches!(err, WireError::UnknownEndpointRef { .. }),
            "expected UnknownEndpointRef, got {err:?}"
        );
    }

    /// Status parity trio (#383): the client re-derives the endpoint-derived
    /// status the server omitted, and a server-baked status wins.

    #[test]
    fn valid_empty_installs_503() {
        // Present Service, zero ready endpoints → 503 (endpoint-derived).
        let resources = vec![
            keyed_route_resource("api.example.com", "default", "svc", 80, None),
            endpoint_resource("default", "svc", 80, true, &[]),
        ];
        let world = decode_world(&resources).expect("decode_world");
        assert!(
            matches!(
                world.ingress.find(80, "api.example.com", "/", &ctx()),
                RouteOutcome::Error(503)
            ),
            "valid-but-empty Service must re-derive 503"
        );
    }

    #[test]
    fn missing_service_installs_500() {
        // Missing Service (service_exists=false), zero addrs → 500.
        let resources = vec![
            keyed_route_resource("api.example.com", "default", "svc", 80, None),
            endpoint_resource("default", "svc", 80, false, &[]),
        ];
        let world = decode_world(&resources).expect("decode_world");
        assert!(
            matches!(
                world.ingress.find(80, "api.example.com", "/", &ctx()),
                RouteOutcome::Error(500)
            ),
            "missing Service must re-derive 500"
        );
    }

    #[test]
    fn server_baked_502_wins() {
        // A baked 502 (endpoint-independent) overrides the client's 503 derivation.
        let resources = vec![
            keyed_route_resource("api.example.com", "default", "svc", 80, Some(502)),
            endpoint_resource("default", "svc", 80, true, &[]),
        ];
        let world = decode_world(&resources).expect("decode_world");
        assert!(
            matches!(
                world.ingress.find(80, "api.example.com", "/", &ctx()),
                RouteOutcome::Error(502)
            ),
            "server-baked 502 must win over the endpoint-derived 503"
        );
    }

    // ── #383 per-backend filter / spec-index alignment ────────────────────────

    /// `per_backend_filters` is keyed by SPEC index — index-aligned with the wire
    /// `weighted` list, which retains drained keyed-empty refs the hot-path pools
    /// drop. A group whose spec is `[keyed-empty(drained), live-A(A), live-B(B)]`
    /// must round-trip so filter A lands on the first surviving backend and B on
    /// the second. Emitting the pool position instead would shift every filter
    /// past the drained slot — A would decode onto no backend and B onto A.
    #[test]
    fn per_backend_filters_realign_across_drained_ref() {
        use coxswain_core::endpoints::{EndpointKey, ResolvedEndpoints};
        use coxswain_core::routing::{BackendGroup, BackendProtocol, HeaderMod};

        let a = addr("10.0.0.1:80");
        let b = addr("10.0.0.2:80");
        let filter_a = FilterAction::RequestHeaderModifier(
            HeaderMod::parse(&[("x-backend", "a")], &[], &[]).expect("hm a"),
        );
        let filter_b = FilterAction::RequestHeaderModifier(
            HeaderMod::parse(&[("x-backend", "b")], &[], &[]).expect("hm b"),
        );

        // Spec order [drained@0, live-A@1, live-B@2]; pools/backends are [A, B].
        let drained = Arc::new(ResolvedEndpoints::new(
            Vec::new(),
            BackendProtocol::default(),
            true,
        ));
        let live_a = Arc::new(ResolvedEndpoints::new(
            vec![a],
            BackendProtocol::default(),
            true,
        ));
        let live_b = Arc::new(ResolvedEndpoints::new(
            vec![b],
            BackendProtocol::default(),
            true,
        ));
        let bg = Arc::new(
            BackendGroup::weighted_with_endpoints(
                "default/svc".to_string(),
                vec![
                    (
                        drained,
                        Some(EndpointKey::new("default", "svc-drained", 80)),
                        1,
                    ),
                    (live_a, Some(EndpointKey::new("default", "svc-a", 80)), 1),
                    (live_b, Some(EndpointKey::new("default", "svc-b", 80)), 1),
                ],
            )
            .with_per_backend_filters(vec![vec![filter_a], vec![filter_b]]),
        );
        let entry = Arc::new(RouteEntry::path_only(bg, "ns/r".to_string(), None));
        let mut builder = IngressRoutingTableBuilder::new();
        builder
            .for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);
        let rt = builder.build().expect("build");

        // Encode → decode via the full resource path (routes + referenced endpoints).
        let world = decode_world(&ingress_resources(&rt)).expect("decode_world");
        let group = world
            .ingress
            .route(80, "example.com", "/", &ctx())
            .expect("route resolves");

        // Round-robin over the two surviving backends; each must carry ITS filter.
        let mut saw_a = false;
        let mut saw_b = false;
        for _ in 0..8 {
            let (picked, filters) = group.next_endpoint_with_filters().expect("endpoint");
            let filters = filters.expect("surviving backend keeps its per-backend filter");
            let expected = if picked == a { "a" } else { "b" };
            match &filters[0] {
                FilterAction::RequestHeaderModifier(hm) => {
                    let hdr = hm
                        .add
                        .iter()
                        .find(|(name, _)| name == "x-backend")
                        .expect("x-backend header");
                    assert_eq!(hdr.1, expected, "each filter must ride its own backend");
                }
                other => panic!("unexpected filter action: {other:?}"),
            }
            saw_a |= picked == a;
            saw_b |= picked == b;
        }
        assert!(saw_a && saw_b, "both surviving backends were selected");
    }

    /// Two-entry case `[drained, live(F)]`: the single filter must survive on the
    /// live backend even though a drained keyed-empty ref precedes it in the spec.
    #[test]
    fn per_backend_filter_survives_single_drained_prefix() {
        use coxswain_core::endpoints::{EndpointKey, ResolvedEndpoints};
        use coxswain_core::routing::{BackendGroup, BackendProtocol, HeaderMod};

        let live = addr("10.0.0.9:80");
        let filter = FilterAction::RequestHeaderModifier(
            HeaderMod::parse(&[("x-backend", "f")], &[], &[]).expect("hm f"),
        );
        let drained = Arc::new(ResolvedEndpoints::new(
            Vec::new(),
            BackendProtocol::default(),
            true,
        ));
        let live_ep = Arc::new(ResolvedEndpoints::new(
            vec![live],
            BackendProtocol::default(),
            true,
        ));
        let bg = Arc::new(
            BackendGroup::weighted_with_endpoints(
                "default/svc".to_string(),
                vec![
                    (
                        drained,
                        Some(EndpointKey::new("default", "svc-drained", 80)),
                        1,
                    ),
                    (
                        live_ep,
                        Some(EndpointKey::new("default", "svc-live", 80)),
                        1,
                    ),
                ],
            )
            .with_per_backend_filters(vec![vec![filter]]),
        );
        let entry = Arc::new(RouteEntry::path_only(bg, "ns/r".to_string(), None));
        let mut builder = IngressRoutingTableBuilder::new();
        builder
            .for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);
        let rt = builder.build().expect("build");

        let world = decode_world(&ingress_resources(&rt)).expect("decode_world");
        let group = world
            .ingress
            .route(80, "example.com", "/", &ctx())
            .expect("route resolves");

        let (picked, filters) = group.next_endpoint_with_filters().expect("endpoint");
        assert_eq!(picked, live, "only the live backend routes");
        let filters = filters.expect("the live backend keeps filter F past the drained prefix");
        match &filters[0] {
            FilterAction::RequestHeaderModifier(hm) => {
                let hdr = hm
                    .add
                    .iter()
                    .find(|(name, _)| name == "x-backend")
                    .expect("x-backend header");
                assert_eq!(hdr.1, "f", "filter F must survive on the live backend");
            }
            other => panic!("unexpected filter action: {other:?}"),
        }
    }

    // ── UpstreamTls client cert (GEP-3155) ────────────────────────────────────

    #[test]
    fn upstream_tls_client_cert_round_trips() {
        let tls = UpstreamTls::new(Arc::from("backend.example.com"), UpstreamCa::System, 0x1234)
            .with_client_cert(Arc::new(BackendClientCert::new(
                Arc::from(&b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"[..]),
                Arc::from(&b"-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----"[..]),
                Arc::from("ns/client-cert"),
            )));
        // with_client_cert re-mixed group_key away from the base 0x1234.
        let mixed_key = tls.group_key;
        assert_ne!(mixed_key, 0x1234, "client cert must perturb group_key");

        let back = upstream_tls_from_wire(&upstream_tls_to_wire(&tls)).expect("from_wire");
        let cc = back.client_cert().expect("client cert survives round-trip");
        assert_eq!(&*cc.cert_pem, &*tls.client_cert().unwrap().cert_pem);
        assert_eq!(&*cc.key_pem, &*tls.client_cert().unwrap().key_pem);
        assert_eq!(&*cc.source, "ns/client-cert");
        assert_eq!(
            back.group_key, mixed_key,
            "from_wire must preserve the sender's group_key, not re-mix it"
        );
    }

    #[test]
    fn upstream_tls_without_client_cert_round_trips() {
        let tls = UpstreamTls::new(Arc::from("backend.example.com"), UpstreamCa::System, 0x99);
        let back = upstream_tls_from_wire(&upstream_tls_to_wire(&tls)).expect("from_wire");
        assert!(
            back.client_cert().is_none(),
            "absent client cert must stay absent (empty source)"
        );
        assert_eq!(back.group_key, 0x99);
    }

    // ── UpstreamTls subject-alt-names (GEP-1897) ──────────────────────────────

    #[test]
    fn upstream_tls_subject_alt_names_round_trips() {
        let sans: Arc<[SubjectAltName]> = Arc::from([
            SubjectAltName::Uri(Arc::from("spiffe://cluster.local/ns/default/sa/svc")),
            SubjectAltName::Hostname(Arc::from("svc.default.svc.cluster.local")),
        ]);
        // Apply SANs before client_cert (canonical reflector order).
        let base_key: u64 = 0xABCD;
        let tls = UpstreamTls::new(Arc::from("svc.example.com"), UpstreamCa::System, base_key)
            .with_subject_alt_names(sans.clone());
        let san_mixed_key = tls.group_key;
        assert_ne!(san_mixed_key, base_key, "SAN list must perturb group_key");

        let back = upstream_tls_from_wire(&upstream_tls_to_wire(&tls)).expect("from_wire");
        assert_eq!(
            back.subject_alt_names(),
            sans.as_ref(),
            "SAN entries must survive round-trip"
        );
        // Critical: from_wire must preserve the sender's group_key verbatim —
        // using with_subject_alt_names() in from_wire would re-fold and diverge.
        assert_eq!(
            back.group_key, san_mixed_key,
            "from_wire must preserve group_key, not re-mix it with SANs"
        );
    }

    #[test]
    fn upstream_tls_empty_subject_alt_names_round_trips() {
        let tls = UpstreamTls::new(Arc::from("svc.example.com"), UpstreamCa::System, 0x42);
        let back = upstream_tls_from_wire(&upstream_tls_to_wire(&tls)).expect("from_wire");
        assert!(
            back.subject_alt_names().is_empty(),
            "absent SANs must round-trip as empty"
        );
        assert_eq!(back.group_key, 0x42);
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

    // ── ext_authz transport (#23) ─────────────────────────────────────────────

    /// A route whose auth chain carries a gRPC-transport ext_authz check must
    /// survive the wire round-trip. Regression for the old encode `unreachable!`
    /// on the transport wildcard and the decode `MissingRequiredField("http")`:
    /// a Grpc entry now encodes the `grpc` field and decodes cleanly (a decode
    /// error would fail `rt_ingress`'s `expect`).
    #[test]
    fn ext_auth_grpc_transport_round_trips() {
        use coxswain_core::routing::{
            ExtAuthConfig, ExtAuthTransport, GrpcExtAuthConfig, IngressAuthConfig,
        };

        let auth = Arc::new(IngressAuthConfig::External(ExtAuthConfig::new(
            Duration::from_millis(750),
            Arc::from([addr("10.1.2.3:9000"), addr("10.1.2.4:9000")]),
            true,
            ExtAuthTransport::Grpc(GrpcExtAuthConfig::new(Arc::from([Box::from(
                "x-auth-user",
            )]))),
        )));
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:8080")]);
        let entry = Arc::new(simple_entry(bg).with_auth_chain(Arc::from([auth])));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("grpc.example.com")
            .add_exact_route("/", entry);

        let rt = rt_ingress(b);
        assert!(
            rt.route(80, "grpc.example.com", "/", &ctx()).is_some(),
            "gRPC ext_authz route must survive the wire round-trip"
        );
    }

    // ── JWT auth (#441) ────────────────────────────────────────────────────────

    /// A route whose auth chain carries a resolved `JwtAuth` check must survive
    /// the wire round-trip with every field intact: issuer, audiences, the
    /// resolved JWKS text, header-extraction locations, the payload-forwarding
    /// header, claim-to-header pairs, and the forward-token flag.
    #[test]
    fn jwt_auth_config_round_trips() {
        use coxswain_core::routing::{IngressAuthConfig, JwtConfig, JwtHeaderLoc};

        let auth = Arc::new(IngressAuthConfig::Jwt(JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([Box::from("my-api"), Box::from("my-other-api")]),
            Arc::from(r#"{"keys":[{"kty":"RSA","kid":"1"}]}"#),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            Some(Box::from("x-jwt-payload")),
            Arc::from([(Box::from("sub"), Box::from("x-user-id"))]),
            true,
        )));
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:8080")]);
        let entry = Arc::new(simple_entry(bg).with_auth_chain(Arc::from([auth])));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);

        let rt = rt_ingress(b);
        let RouteOutcome::Found(m) = rt.find(80, "example.com", "/", &ctx()) else {
            panic!("JWT-auth route must survive the wire round-trip");
        };
        assert_eq!(m.auth.len(), 1, "auth chain must carry exactly one entry");
        let IngressAuthConfig::Jwt(jwt) = m.auth[0].as_ref() else {
            panic!("expected IngressAuthConfig::Jwt, got {:?}", m.auth[0]);
        };
        assert_eq!(&*jwt.issuer, "https://issuer.example.com");
        assert_eq!(jwt.audiences.len(), 2);
        assert_eq!(&*jwt.audiences[0], "my-api");
        assert_eq!(&*jwt.jwks, r#"{"keys":[{"kty":"RSA","kid":"1"}]}"#);
        assert_eq!(jwt.from_headers.len(), 1);
        assert_eq!(&*jwt.from_headers[0].name, "Authorization");
        assert_eq!(&*jwt.from_headers[0].value_prefix, "Bearer ");
        assert_eq!(jwt.forward_payload_header.as_deref(), Some("x-jwt-payload"));
        assert_eq!(jwt.claim_to_headers.len(), 1);
        assert_eq!(&*jwt.claim_to_headers[0].0, "sub");
        assert_eq!(&*jwt.claim_to_headers[0].1, "x-user-id");
        assert!(jwt.forward_token);
    }

    /// An unresolved JWKS (empty `jwks` string — the controller hasn't fetched
    /// the remote `jwksUri` yet) must decode to `Unavailable` (fail-closed),
    /// never a `Jwt` config with an empty key set.
    #[test]
    fn jwt_auth_config_with_empty_jwks_decodes_unavailable() {
        use coxswain_core::routing::{IngressAuthConfig, JwtConfig, JwtHeaderLoc};

        let auth = Arc::new(IngressAuthConfig::Jwt(JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            Arc::from(""),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            None,
            Arc::from([]),
            false,
        )));
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:8080")]);
        let entry = Arc::new(simple_entry(bg).with_auth_chain(Arc::from([auth])));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);

        let rt = rt_ingress(b);
        let RouteOutcome::Found(m) = rt.find(80, "example.com", "/", &ctx()) else {
            panic!("route must survive the wire round-trip even with an unresolved JWKS");
        };
        assert!(
            matches!(m.auth[0].as_ref(), IngressAuthConfig::Unavailable),
            "empty JWKS must decode to Unavailable (fail-closed), got {:?}",
            m.auth[0]
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
        assert_eq!(
            spec.weighted[0].weight, 4,
            "first group weight = 4 (pre-GCD)"
        );
        assert_eq!(
            spec.weighted[1].weight, 2,
            "second group weight = 2 (pre-GCD)"
        );
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
    fn retry_policy_round_trips() {
        use coxswain_core::routing::RetryPolicyConfig;
        let retry = RetryPolicyConfig::for_grpc(
            2,
            Some(std::time::Duration::from_millis(100)),
            Some(vec![503, 500]),
            Some(vec![14]),
        );
        let bg = Arc::new(
            BackendGroup::new("ns/svc".to_string(), vec![addr("10.0.0.1:80")]).with_retries(retry),
        );
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/", entry);
        let table = rt_ingress(b);

        let group = table
            .route(80, "example.com", "/", &ctx())
            .expect("route present after round-trip");
        let p = group.retry_policy();
        assert_eq!(p.attempts, 2);
        assert_eq!(p.backoff, Some(std::time::Duration::from_millis(100)));
        assert_eq!(&*p.http_codes, &[500, 503]);
        assert_eq!(&*p.grpc_codes, &[14]);
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
                .with_allow_source_range(Some(Arc::from(vec!["10.0.0.0/8".parse().unwrap()])))
                .with_deny_source_range(Some(Arc::from(vec!["10.1.0.0/16".parse().unwrap()]))),
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

    #[test]
    fn backend_timeouts_round_trip() {
        let a = addr("10.0.0.1:80");
        let bg = Arc::new(
            BackendGroup::new("ns/svc".to_string(), vec![a])
                .with_connect_timeout(Some(Duration::from_millis(500)))
                .with_keepalive_timeout(Some(Duration::from_secs(60))),
        );
        let entry = Arc::new(simple_entry(bg));

        let mut b = IngressRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("example.com")
            .add_exact_route("/api", entry);

        let rt = rt_ingress(b);
        let bg2 = rt.route(80, "example.com", "/api", &ctx()).expect("hit");
        assert_eq!(
            bg2.connect_timeout(),
            Some(Duration::from_millis(500)),
            "connect timeout must survive the wire round-trip (#354)"
        );
        assert_eq!(
            bg2.keepalive_timeout(),
            Some(Duration::from_secs(60)),
            "keepalive (idle) timeout must survive the wire round-trip"
        );
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
            fraction: None,
        };
        let outer_bg = Arc::new(
            BackendGroup::new("outer".to_string(), vec![addr("10.0.0.1:80")])
                .with_per_backend_filters(vec![vec![inner_filter]]),
        );
        let entry = Arc::new(RouteEntry::with_filters(
            outer_bg,
            MatchPredicates::default(),
            vec![FilterAction::Mirror {
                backend: mirror_bg,
                fraction: None,
            }],
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
                endpoint_ref: None,
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
                    action: Some(p::filter_action::Action::Mirror(p::MirrorFilter {
                        backend: Some(nested_bg(depth - 1)),
                        fraction: None,
                    })),
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
        let err = bg_from_wire(&dto, &EndpointPool::new(), 0).unwrap_err();
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
        let resources = ingress_resources(&t);
        // Find the single route-host resource and assert its normalize level rode
        // the wire, then confirm the full resource set decodes.
        let host = resources
            .iter()
            .find_map(|r| match r.payload.as_ref() {
                Some(p::resource::Payload::RouteHost(rh)) => rh.host.as_ref(),
                _ => None,
            })
            .expect("route-host resource");
        assert_ne!(host.normalize_level, 0, "normalize level serialised");

        decode_world(&resources).expect("decode_world round-trip");
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
        // Literal-addr routes carry no endpoint resources, so the per-resource
        // emitter is fully deterministic: repeated encodes must be byte-identical.
        let r1: Vec<Vec<u8>> = ingress_resources(&t)
            .iter()
            .map(|r| r.encode_to_vec())
            .collect();
        let r2: Vec<Vec<u8>> = ingress_resources(&t)
            .iter()
            .map(|r| r.encode_to_vec())
            .collect();
        assert_eq!(
            r1, r2,
            "repeated resource emission must produce identical bytes"
        );
    }

    // ── CORS filter round-trip ────────────────────────────────────────────────

    #[test]
    fn cors_filter_round_trips() {
        use coxswain_core::routing::{CorsConfig, CorsOrigin};
        use http::HeaderValue;

        let cfg = CorsConfig::new(
            vec![
                CorsOrigin::Exact("https://allowed.example".to_string()),
                CorsOrigin::Wildcard {
                    prefix: "https://".into(),
                    suffix: ".trusted.example".into(),
                },
            ],
            false, // allow_all_origins
            true,  // allow_credentials
            Some(HeaderValue::from_static("GET, POST")),
            Some(HeaderValue::from_static("Content-Type")),
            Some(HeaderValue::from_static("X-Custom-Header")),
            HeaderValue::from_static("3600"),
        );
        let filter = FilterAction::Cors(Arc::new(cfg));
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(RouteEntry::with_filters(
            bg,
            MatchPredicates::default(),
            vec![filter],
            RouteTimeouts::default(),
            "cors-route".to_string(),
            None,
        ));

        let mut b = GatewayRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("api.example.com")
            .add_exact_route("/", entry);

        let rt = rt_gateway(b);
        let RouteOutcome::Found(m) = rt.find(80, "api.example.com", "/", &ctx()) else {
            panic!("expected Found")
        };
        let FilterAction::Cors(cfg) = &m.filters[0] else {
            panic!("expected FilterAction::Cors")
        };

        // Origins preserved
        assert_eq!(cfg.allow_origins.len(), 2);
        assert!(cfg.allow_origins[0].matches("https://allowed.example"));
        assert!(!cfg.allow_origins[0].matches("https://other.example"));
        assert!(cfg.allow_origins[1].matches("https://foo.trusted.example"));
        assert!(!cfg.allow_origins[1].matches("https://foo.other.example"));
        assert!(!cfg.allow_all_origins);
        assert!(cfg.allow_credentials);

        // Pre-rendered header values preserved
        assert_eq!(cfg.allow_methods.as_ref().expect("methods"), "GET, POST");
        assert_eq!(cfg.allow_headers.as_ref().expect("headers"), "Content-Type");
        assert_eq!(
            cfg.expose_headers.as_ref().expect("expose"),
            "X-Custom-Header"
        );
        assert_eq!(cfg.max_age, "3600");

        // Echo-origin logic works end-to-end
        let hv = cfg
            .resolve_origin("https://allowed.example")
            .expect("should match");
        assert_eq!(hv, "https://allowed.example");
        assert!(cfg.resolve_origin("https://evil.example").is_none());
    }

    #[test]
    fn cors_filter_allow_all_origins_round_trips() {
        use coxswain_core::routing::CorsConfig;
        use http::HeaderValue;

        let cfg = CorsConfig::new(
            vec![],
            true,  // allow_all_origins (bare '*')
            false, // allow_credentials
            None,
            None,
            None,
            HeaderValue::from_static("5"),
        );
        let filter = FilterAction::Cors(Arc::new(cfg));
        let bg = simple_bg("ns/svc", &[addr("10.0.0.1:80")]);
        let entry = Arc::new(RouteEntry::with_filters(
            bg,
            MatchPredicates::default(),
            vec![filter],
            RouteTimeouts::default(),
            "cors-wildcard-route".to_string(),
            None,
        ));

        let mut b = GatewayRoutingTableBuilder::new();
        b.for_port(80)
            .exact_host("api.example.com")
            .add_exact_route("/", entry);

        let rt = rt_gateway(b);
        let RouteOutcome::Found(m) = rt.find(80, "api.example.com", "/", &ctx()) else {
            panic!("expected Found")
        };
        let FilterAction::Cors(cfg) = &m.filters[0] else {
            panic!("expected FilterAction::Cors")
        };
        assert!(cfg.allow_all_origins);
        assert!(cfg.allow_origins.is_empty());
        assert!(!cfg.allow_credentials);
        let hv = cfg
            .resolve_origin("https://any.example")
            .expect("allow_all_origins should match anything");
        assert_eq!(hv, "https://any.example");
    }
}
