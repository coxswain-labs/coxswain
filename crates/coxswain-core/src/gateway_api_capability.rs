//! Closed vocabulary for Gateway API capability detection.
//!
//! Gateway API CRDs are cluster-scoped singletons, so a cluster may have any
//! subset of the kinds Coxswain knows how to watch — an older release, or a
//! co-resident implementation pinning a lower version. Coxswain adapts by
//! *detecting* what is installed and treating the result as data, never by
//! comparing version numbers.
//!
//! This module owns only the vocabulary: which kinds and fields exist, and how
//! to find each one on the API server. It deliberately holds no behaviour and
//! talks to nothing.
//!
//! - `coxswain-reflector` performs detection against a live API server and
//!   produces the capability set.
//! - `coxswain-controller` projects that set onto its readiness checks and its
//!   GEP-2162 `supportedFeatures` advertisement.
//!
//! Both consumers key off the enums here, so a kind or field that gains a new
//! variant fails to compile at every site that must handle it. That guarantee
//! is why these are closed enums and not strings: a mistyped `"listenerset"`
//! would be a silent runtime capability gap, whereas a mistyped
//! [`GatewayApiKind`] variant is a build error.
//!
//! The enums and their lookup tables are generated from a single macro
//! invocation each. A variant therefore *cannot* exist without an `ALL` entry
//! and a value in every table — the alternative, hand-maintaining a parallel
//! `ALL` slice, compiles and passes tests when the slice is stale, leaving the
//! new kind silently un-probed on every cluster.

/// The API group every kind in [`GatewayApiKind`] belongs to.
///
/// Detection resolves the whole group in one discovery query, so this is the
/// single string the reflector needs; individual kinds are identified by their
/// [`plural`](GatewayApiKind::plural) name within it. Consumers must import this
/// rather than respelling the group — two copies that disagree resolve nothing.
pub const GATEWAY_API_GROUP: &str = "gateway.networking.k8s.io";

// ── kinds ─────────────────────────────────────────────────────────────────────

/// Declares [`GatewayApiKind`] together with every table keyed on it.
///
/// Generating the variant list and the lookup tables from one source is what
/// makes [`GatewayApiKind::ALL`] trustworthy: completeness is structural, not
/// something a test has to re-check.
macro_rules! gateway_api_kinds {
    ($(
        $(#[$attr:meta])*
        $variant:ident => plural: $plural:literal, versions: $versions:expr, kind: $kind_name:literal;
    )+) => {
        /// A Gateway API kind whose presence Coxswain detects rather than assumes.
        ///
        /// Coxswain's declared floor is Gateway API v1.4.0, where four of these
        /// kinds do not exist at all (`ListenerSet`, `TLSRoute`, `TCPRoute`,
        /// `UDPRoute`) and `ReferenceGrant` serves only `v1beta1`. Spawning a
        /// reflector for an absent kind would 404 on every relist forever, so
        /// each kind is resolved through discovery first and skipped when absent.
        ///
        /// `Copy` + `Hash` + `Eq` because the reflector's re-probe loop keys a
        /// `HashSet` on these to track which kinds already have a live reflector.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum GatewayApiKind {
            $($(#[$attr])* $variant,)+
        }

        impl GatewayApiKind {
            /// Every kind, in declaration order.
            ///
            /// Detection, the capability gauge, and the startup capability log
            /// all walk this rather than repeating the list. It is generated
            /// alongside the enum, so it cannot fall behind a new variant.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The lower-case plural resource name, as it appears in API discovery.
            ///
            /// Discovery matches on this rather than the Rust type name, which
            /// differs in case and in the `Http`/`HTTP` acronym convention.
            #[must_use]
            pub const fn plural(self) -> &'static str {
                match self { $(Self::$variant => $plural,)+ }
            }

            /// Served API versions to try, most-preferred first.
            ///
            /// Detection takes the first entry the cluster actually serves, so a
            /// kind that gained `v1` in a later release is watched at `v1` where
            /// available and at its older version otherwise — without any version
            /// comparison.
            ///
            /// Only [`ReferenceGrant`](Self::ReferenceGrant) exercises the
            /// fallback in practice: it serves `v1beta1` alone until Gateway API
            /// v1.5. The `v1beta1` entries on `GatewayClass`, `Gateway` and
            /// `HttpRoute` reflect what those CRDs genuinely serve and cost
            /// nothing, but are never reached at the current v1.4.0 floor because
            /// `v1` is always present too.
            ///
            /// Versions the CRD declares but marks `served: false` (several kinds
            /// carry a legacy `v1alpha2`/`v1alpha3`) are deliberately omitted —
            /// discovery would never return them.
            #[must_use]
            pub const fn versions(self) -> &'static [&'static str] {
                match self { $(Self::$variant => $versions,)+ }
            }

            /// Stable identifier for metric labels and structured log fields.
            ///
            /// Matches the Kubernetes kind name so an operator reading
            /// `coxswain_gateway_api_capability{kind="ListenerSet"}` sees the same
            /// spelling they would `kubectl get`.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $kind_name,)+ }
            }
        }
    };
}

gateway_api_kinds! {
    /// Cluster-scoped; carries the `supportedFeatures` advertisement.
    GatewayClass => plural: "gatewayclasses", versions: &["v1", "v1beta1"], kind: "GatewayClass";

    /// The listener/address surface every route attaches to.
    Gateway => plural: "gateways", versions: &["v1", "v1beta1"], kind: "Gateway";

    /// HTTP routing; present and `v1` on every supported version, as is
    /// [`GrpcRoute`](GatewayApiKind::GrpcRoute).
    HttpRoute => plural: "httproutes", versions: &["v1", "v1beta1"], kind: "HTTPRoute";

    /// gRPC routing; present and `v1` on every supported version.
    GrpcRoute => plural: "grpcroutes", versions: &["v1"], kind: "GRPCRoute";

    /// Cross-namespace reference permission. The one kind with version skew:
    /// `v1beta1` only until Gateway API v1.5, both `v1` and `v1beta1` after.
    ReferenceGrant => plural: "referencegrants", versions: &["v1", "v1beta1"], kind: "ReferenceGrant";

    /// Upstream TLS policy; standard channel from Gateway API v1.4.
    BackendTlsPolicy => plural: "backendtlspolicies", versions: &["v1"], kind: "BackendTLSPolicy";

    /// GEP-1713 listener composition; absent before Gateway API v1.5.
    ListenerSet => plural: "listenersets", versions: &["v1"], kind: "ListenerSet";

    /// TLS passthrough/terminate routing; absent before Gateway API v1.5.
    TlsRoute => plural: "tlsroutes", versions: &["v1"], kind: "TLSRoute";

    /// TCP routing; absent before Gateway API v1.6.
    TcpRoute => plural: "tcproutes", versions: &["v1"], kind: "TCPRoute";

    /// UDP routing; absent before Gateway API v1.6.
    UdpRoute => plural: "udproutes", versions: &["v1"], kind: "UDPRoute";
}

// ── fields ────────────────────────────────────────────────────────────────────

/// Declares [`GatewayApiField`] together with every table keyed on it.
///
/// Same rationale as [`gateway_api_kinds`]: `ALL` is generated, so it cannot go
/// stale when a field is added.
macro_rules! gateway_api_fields {
    ($(
        $(#[$attr:meta])*
        $variant:ident => crd: $crd:literal, path: $path:expr, name: $name:literal;
    )+) => {
        /// A Gateway API field whose presence must be detected separately from its kind.
        ///
        /// Some capabilities were added to an existing kind rather than as a new
        /// one, so the CRD is installed but the field is missing from its schema.
        /// Kind-level discovery cannot see that, so these are resolved by reading
        /// the CRD's `openAPIV3Schema` directly.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum GatewayApiField {
            $($(#[$attr])* $variant,)+
        }

        impl GatewayApiField {
            /// Every field, in declaration order.
            ///
            /// Detection groups these by [`crd`](Self::crd) so each CRD is
            /// fetched once regardless of how many fields it carries.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// Fully-qualified name of the CRD whose schema declares this field.
            #[must_use]
            pub const fn crd(self) -> &'static str {
                match self { $(Self::$variant => $crd,)+ }
            }

            /// Property names to descend, from the schema root to the field itself.
            ///
            /// These are property names only. Array-valued nodes along the way
            /// (`rules` and `filters` on `HTTPRoute`) are *not* listed — the
            /// resolver descends through an array's `items` automatically when the
            /// next name is not a direct property. Encoding the array hops here
            /// would duplicate schema shape that upstream is free to change, and
            /// would silently mis-resolve if a field were ever promoted out of a
            /// list.
            ///
            /// A name that fails to resolve at *any* depth means the capability is
            /// absent, not that the schema is malformed. This matters at the
            /// declared floor: on Gateway API v1.4.x
            /// [`GatewayFrontendTls`](GatewayApiField::GatewayFrontendTls) fails at
            /// the intermediate `tls` node, not at the `frontend` leaf, and that
            /// must be reported as "unavailable" rather than logged as a broken
            /// schema on every startup.
            #[must_use]
            pub const fn schema_path(self) -> &'static [&'static str] {
                match self { $(Self::$variant => $path,)+ }
            }

            /// Stable identifier for structured log fields.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $name,)+ }
            }
        }
    };
}

gateway_api_fields! {
    /// `HTTPRoute` CORS filter — added in Gateway API v1.5.
    HttpRouteCors
        => crd: "httproutes.gateway.networking.k8s.io",
           path: &["spec", "rules", "filters", "cors"],
           name: "HTTPRouteCORS";

    /// `Gateway` frontend client-certificate validation (GEP-91) — added in
    /// Gateway API v1.5. Absent at the floor as a whole `tls` subtree, not just
    /// a missing leaf.
    GatewayFrontendTls
        => crd: "gateways.gateway.networking.k8s.io",
           path: &["spec", "tls", "frontend"],
           name: "GatewayFrontendTLS";

    /// `GatewayClass.status.supportedFeatures` (GEP-2162) — added in Gateway
    /// API v1.4, and therefore present on every version Coxswain declares
    /// support for.
    ///
    /// It is detected anyway because Coxswain degrades rather than refusing to
    /// start, so it still runs on sub-floor clusters. There the API server
    /// silently prunes a write to this field, so
    /// `gateway_class_needs_status_patch` would compare its desired list against
    /// a permanently-empty current one and re-patch on every reconcile. Detecting
    /// the field lets the controller patch `conditions` alone instead of
    /// hot-looping against the API server.
    GatewayClassSupportedFeatures
        => crd: "gatewayclasses.gateway.networking.k8s.io",
           path: &["status", "supportedFeatures"],
           name: "GatewayClassSupportedFeatures";
}

// ── requirements ──────────────────────────────────────────────────────────────

/// What a named thing needs from the cluster in order to be available.
///
/// The controller keeps two tables of `(name, Requirement)` — one for readiness
/// checks, one for GEP-2162 feature advertisement — and resolves both through a
/// single predicate against the detected capability set. Without this shared
/// shape each table would grow its own ad-hoc encoding of "optional, and gated
/// on what", which is how the two drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Requirement {
    /// Available on every supported Gateway API version.
    Always,
    /// Available only when the CRD for this kind is installed.
    Kind(GatewayApiKind),
    /// Available only when this field is present in its CRD's schema.
    Field(GatewayApiField),
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // `ALL` completeness is guaranteed by construction — the macro emits the
    // enum and the slice from one variant list — so there is no test for it.
    // The tests below cover what the macro cannot: that the *values* supplied
    // for each variant are internally consistent and usable by detection.

    #[test]
    fn plurals_are_unique_and_lowercase() {
        let plurals: HashSet<&str> = GatewayApiKind::ALL.iter().map(|k| k.plural()).collect();
        assert_eq!(
            plurals.len(),
            GatewayApiKind::ALL.len(),
            "two kinds share a plural name; discovery would resolve one to the other"
        );
        for kind in GatewayApiKind::ALL {
            let plural = kind.plural();
            assert!(
                plural.chars().all(|c| c.is_ascii_lowercase()),
                "{plural} must be lower-case to match API discovery"
            );
        }
    }

    #[test]
    fn kind_names_are_unique() {
        let names: HashSet<&str> = GatewayApiKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            names.len(),
            GatewayApiKind::ALL.len(),
            "two kinds share a display name; the capability gauge would collapse \
             them onto one time series"
        );
    }

    #[test]
    fn every_kind_offers_at_least_one_version() {
        for kind in GatewayApiKind::ALL {
            let versions = kind.versions();
            assert!(
                !versions.is_empty(),
                "{} has no candidate version, so detection could never resolve it",
                kind.as_str()
            );
            let unique: HashSet<&&str> = versions.iter().collect();
            assert_eq!(
                unique.len(),
                versions.len(),
                "{} lists a duplicate version; the second is unreachable",
                kind.as_str()
            );
        }
    }

    #[test]
    fn reference_grant_prefers_v1_over_v1beta1() {
        // The skew that motivates version negotiation: Gateway API v1.4 serves
        // only v1beta1, v1.5+ serves both. Preferring v1 keeps newer clusters
        // on the GA version while older ones still resolve.
        assert_eq!(
            GatewayApiKind::ReferenceGrant.versions(),
            &["v1", "v1beta1"],
            "ReferenceGrant must try v1 first and fall back to v1beta1"
        );
    }

    #[test]
    fn field_crds_name_a_kind_detection_already_covers() {
        for field in GatewayApiField::ALL {
            let crd = field.crd();
            assert!(
                crd.ends_with(GATEWAY_API_GROUP),
                "{crd} must be a {GATEWAY_API_GROUP} CRD"
            );
            let plural = crd
                .trim_end_matches(GATEWAY_API_GROUP)
                .trim_end_matches('.');
            assert!(
                GatewayApiKind::ALL.iter().any(|k| k.plural() == plural),
                "{crd} names a resource no GatewayApiKind covers, so its CRD \
                 would never be fetched alongside a detected kind"
            );
        }
    }

    #[test]
    fn schema_paths_are_rooted_at_a_top_level_property() {
        for field in GatewayApiField::ALL {
            let path = field.schema_path();
            assert!(
                path.len() >= 2,
                "{} needs at least a root property and a leaf",
                field.as_str()
            );
            assert!(
                matches!(path[0], "spec" | "status"),
                "{} must descend from spec or status, got {:?}",
                field.as_str(),
                path[0]
            );
        }
    }

    #[test]
    fn field_names_are_unique() {
        let names: HashSet<&str> = GatewayApiField::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(
            names.len(),
            GatewayApiField::ALL.len(),
            "two fields share a display name; capability logs would be ambiguous"
        );
    }
}
