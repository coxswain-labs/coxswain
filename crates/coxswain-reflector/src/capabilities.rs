//! Gateway API capability detection against a live API server.
//!
//! Gateway API CRDs are cluster-scoped singletons, so Coxswain may find any
//! subset of the kinds it knows how to watch — an older Gateway API release, or
//! a co-resident implementation pinning a lower version. Spawning a reflector
//! for an absent kind 404s on every relist forever and wedges its readiness
//! check, so the controller resolves what is actually installed first and
//! degrades to the intersection.
//!
//! This module is the *only* place that asks the API server what exists. It
//! answers questions about the result ([`GatewayApiCapabilities::kind`],
//! [`satisfies`](GatewayApiCapabilities::satisfies)) but holds no opinion about
//! what any capability is *for* — readiness-check names and GEP-2162 feature
//! names are the controller's vocabulary and live there, as tables keyed on
//! [`Requirement`].
//!
//! Detection is a single attempt by design. Retrying belongs to the caller: at
//! startup a failure should back off and retry before giving up, while the
//! periodic re-probe loop already *is* a retry and must not compound its own.

use std::collections::{BTreeMap, BTreeSet};

use coxswain_core::gateway_api_capability::{
    GATEWAY_API_GROUP, GatewayApiField, GatewayApiKind, Requirement,
};
use coxswain_core::shared::Shared;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::{
    CustomResourceDefinition, JSONSchemaProps, JSONSchemaPropsOrArray,
};
use kube::{Api, Client, core::discovery::ApiResource, discovery};
use thiserror::Error;

/// Why capability detection could not produce a trustworthy answer.
///
/// Note what is deliberately *not* an error: a cluster with no Gateway API CRDs
/// at all. That is Ingress-only mode, a supported configuration, and it yields
/// an empty capability set. Only a cluster we failed to *interrogate* is an
/// error — under the previous bare-boolean probe a wrong guess cost one wedged
/// surface, but a wrong guess here would mis-declare the entire feature set, so
/// "assume present" is no longer a safe fallback.
#[derive(Debug, Error)]
pub enum CapabilityDetectError {
    /// The API group could not be listed for a reason other than its absence.
    #[error("Gateway API discovery failed")]
    Discovery(#[source] kube::Error),

    /// A CRD naming a detected field could not be read. Most often RBAC: the
    /// controller ClusterRole needs `get` on `customresourcedefinitions`.
    #[error("reading CRD {crd} failed")]
    CrdRead {
        /// Fully-qualified CRD name that could not be fetched.
        crd: &'static str,
        /// Underlying client error.
        #[source]
        source: kube::Error,
    },
}

/// What this cluster's Gateway API installation actually provides.
///
/// Produced once by [`CapabilitySource::detect`] and then consumed as data —
/// the reflector gates reflector spawns on it, and the controller projects it
/// onto readiness checks and its advertised `supportedFeatures`. No consumer
/// compares version numbers.
#[derive(Debug, Clone, Default)]
pub struct GatewayApiCapabilities {
    /// Negotiated resource per present kind. The [`ApiResource`] is retained
    /// rather than a bare `bool` because the dynamic `ReferenceGrant` watch
    /// needs the exact served version, and re-deriving it later would mean a
    /// second negotiation that could disagree with this one.
    kinds: BTreeMap<GatewayApiKind, ApiResource>,
    /// Fields found present in their CRD's schema.
    fields: BTreeSet<GatewayApiField>,
}

impl GatewayApiCapabilities {
    /// The capability set of a cluster with no Gateway API installed.
    ///
    /// This is a legitimate outcome, not a failure: the controller runs in
    /// Ingress-only mode and the periodic re-probe activates Gateway API later
    /// if the CRDs are installed.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The negotiated resource for `kind`, or `None` when its CRD is absent.
    ///
    /// Callers spawn a reflector only when this is `Some`, and pass the returned
    /// [`ApiResource`] to dynamically-typed watches so the store and the watch
    /// agree on the served version.
    #[must_use]
    pub fn kind(&self, kind: GatewayApiKind) -> Option<&ApiResource> {
        self.kinds.get(&kind)
    }

    /// Whether `field` is present in its CRD's schema.
    #[must_use]
    pub fn has_field(&self, field: GatewayApiField) -> bool {
        self.fields.contains(&field)
    }

    /// Whether this cluster satisfies `req`.
    ///
    /// The single predicate behind both controller tables. Keeping one shape for
    /// "optional, and gated on what" is what stops the readiness-check table and
    /// the feature table from drifting into two different encodings.
    #[must_use]
    pub fn satisfies(&self, req: Requirement) -> bool {
        match req {
            Requirement::Always => true,
            Requirement::Kind(kind) => self.kind(kind).is_some(),
            Requirement::Field(field) => self.has_field(field),
        }
    }

    /// Whether any Gateway API kind resolved at all.
    ///
    /// Backs the coarse `gateway_api_crds` readiness check, whose meaning is
    /// unchanged from the probe it replaces: false puts the controller in
    /// Ingress-only mode with `/readyz` failing until the CRDs appear. Per-kind
    /// absence is reported by the per-kind checks instead, which degrade rather
    /// than block.
    #[must_use]
    pub fn group_present(&self) -> bool {
        !self.kinds.is_empty()
    }

    /// Kinds that resolved, for the startup capability log.
    pub fn present_kinds(&self) -> impl Iterator<Item = GatewayApiKind> + '_ {
        self.kinds.keys().copied()
    }

    /// Build a capability set from an explicit kind/field list, synthesizing
    /// each [`ApiResource`] from the vocabulary rather than from discovery.
    ///
    /// For callers that need to describe a hypothetical cluster shape — chiefly
    /// tests of the projections in other crates, which cannot reach a live API
    /// server. The synthesized resource uses each kind's *most preferred*
    /// version, so it must not stand in for a real detection where the
    /// negotiated version matters (`ReferenceGrant` resolves to `v1beta1` on a
    /// Gateway API v1.4 cluster, which this constructor cannot express).
    #[must_use]
    pub fn from_vocabulary(
        kinds: impl IntoIterator<Item = GatewayApiKind>,
        fields: impl IntoIterator<Item = GatewayApiField>,
    ) -> Self {
        let kinds = kinds
            .into_iter()
            .map(|kind| {
                let version = kind.versions().first().copied().unwrap_or("v1");
                let resource = ApiResource {
                    group: GATEWAY_API_GROUP.to_string(),
                    version: version.to_string(),
                    api_version: format!("{GATEWAY_API_GROUP}/{version}"),
                    kind: kind.as_str().to_string(),
                    plural: kind.plural().to_string(),
                };
                (kind, resource)
            })
            .collect();
        Self {
            kinds,
            fields: fields.into_iter().collect(),
        }
    }
}

/// Lock-free handle to the most recently detected capabilities.
///
/// The reflector detects; the controller's `GatewayClass` status writer reads,
/// so it advertises only features the installed CRDs can actually express. A
/// [`Shared`] rather than a one-shot value because the re-probe can widen the
/// set at runtime when a CRD is installed under a live controller.
///
/// Starts empty. An empty set is also what a *failed* detection leaves in
/// place, which is why the status writer must treat "no kinds at all" as
/// "not yet known" and decline to patch, rather than publishing an empty
/// feature list over a correct one.
pub type SharedGatewayApiCapabilities = Shared<GatewayApiCapabilities>;

/// Where a [`GatewayApiCapabilities`] comes from.
///
/// A trait rather than a bare function so the re-probe loop can be driven by a
/// scripted capability sequence under unit test. That loop's failure mode —
/// reverting to one-shot, so a CRD installed later never activates — is
/// structural and needs to be testable without a live API server.
#[async_trait::async_trait]
pub trait CapabilitySource: Send + Sync {
    /// Resolve the cluster's Gateway API capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityDetectError`] when the API server could not be
    /// interrogated. An *absent* Gateway API installation is not an error — it
    /// yields an empty set.
    async fn detect(&self) -> Result<GatewayApiCapabilities, CapabilityDetectError>;
}

/// Detects capabilities by querying a real Kubernetes API server.
#[derive(Clone)]
pub struct ApiServerCapabilities {
    client: Client,
}

impl ApiServerCapabilities {
    /// Bind a detector to a client.
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl CapabilitySource for ApiServerCapabilities {
    async fn detect(&self) -> Result<GatewayApiCapabilities, CapabilityDetectError> {
        let kinds = match discovery::group(&self.client, GATEWAY_API_GROUP).await {
            Ok(group) => resolve_kinds(|version| {
                group
                    .versioned_resources(version)
                    .into_iter()
                    .map(|(ar, _)| ar)
                    .collect()
            }),
            // The group being absent is Ingress-only mode, not a failure.
            Err(e) if is_group_absent(&e) => {
                tracing::info!(
                    "Gateway API CRDs not found; running in Ingress-only mode — \
                     the CRDs are re-probed periodically, so installing them \
                     activates Gateway API without a restart"
                );
                return Ok(GatewayApiCapabilities::empty());
            }
            Err(e) => return Err(CapabilityDetectError::Discovery(e)),
        };

        // On a cluster without Gateway API there is nothing to read at all; a
        // partially-installed group is handled per-CRD by the absent arm below.
        let fields = self.resolve_fields(&kinds).await?;

        Ok(GatewayApiCapabilities { kinds, fields })
    }
}

impl ApiServerCapabilities {
    /// Read each distinct CRD named by a [`GatewayApiField`] once, and record
    /// which fields its schema declares.
    async fn resolve_fields(
        &self,
        kinds: &BTreeMap<GatewayApiKind, ApiResource>,
    ) -> Result<BTreeSet<GatewayApiField>, CapabilityDetectError> {
        let mut present = BTreeSet::new();
        if kinds.is_empty() {
            return Ok(present);
        }

        let api: Api<CustomResourceDefinition> = Api::all(self.client.clone());
        // One fetch per CRD regardless of how many fields it carries.
        let crds: BTreeSet<&'static str> = GatewayApiField::ALL.iter().map(|f| f.crd()).collect();

        for crd_name in crds {
            let crd = match api.get(crd_name).await {
                Ok(crd) => crd,
                // A CRD that isn't installed simply has none of its fields.
                // Shares the predicate with group detection so both sites keep
                // the same notion of "absent" and one set of tests constrains it.
                Err(e) if is_group_absent(&e) => continue,
                Err(source) => {
                    return Err(CapabilityDetectError::CrdRead {
                        crd: crd_name,
                        source,
                    });
                }
            };

            for field in GatewayApiField::ALL.iter().filter(|f| f.crd() == crd_name) {
                if crd_declares_field(&crd, field.schema_path()) {
                    present.insert(*field);
                }
            }
        }

        Ok(present)
    }
}

/// Whether a discovery failure means "this group is not installed" as opposed to
/// "we could not reach the API server".
///
/// This distinction is the whole reason detection can be strict about other
/// errors: without it, an Ingress-only cluster would be indistinguishable from
/// an unreachable one and either Ingress-only mode breaks or a transient blip
/// silently mis-declares the feature set.
fn is_group_absent(error: &kube::Error) -> bool {
    match error {
        kube::Error::Discovery(kube::error::DiscoveryError::MissingApiGroup(_)) => true,
        kube::Error::Api(status) => status.code == 404,
        _ => false,
    }
}

/// Pick each kind's served version, most-preferred first.
///
/// Matching is on the plural resource name because that is what discovery
/// reports; the Rust type name differs in acronym casing.
///
/// Takes a version lookup rather than a [`discovery::ApiGroup`] because that
/// type has private fields and no public constructor, so a test could not
/// otherwise reach the preference ordering — which is the behaviour that
/// decides `v1` over `v1beta1` for `ReferenceGrant` above the v1.4 floor.
fn resolve_kinds(
    versioned: impl Fn(&str) -> Vec<ApiResource>,
) -> BTreeMap<GatewayApiKind, ApiResource> {
    let mut resolved = BTreeMap::new();
    for kind in GatewayApiKind::ALL {
        for version in kind.versions() {
            let found = versioned(version)
                .into_iter()
                .find(|ar| ar.plural == kind.plural());
            if let Some(ar) = found {
                resolved.insert(*kind, ar);
                break;
            }
        }
    }
    resolved
}

/// Whether `path` resolves to a node in any served version of `crd`'s schema.
///
/// Served versions are checked in the order the CRD declares them and the first
/// hit wins — a field present in *some* served version is usable, and the watch
/// itself negotiates which version it talks.
fn crd_declares_field(crd: &CustomResourceDefinition, path: &[&str]) -> bool {
    crd.spec
        .versions
        .iter()
        .filter(|v| v.served)
        .filter_map(|v| v.schema.as_ref()?.open_api_v3_schema.as_ref())
        .any(|schema| resolve_schema_path(schema, path))
}

/// Walk `path` from a schema root, descending through array `items` implicitly.
///
/// A name that fails to resolve at *any* depth means the capability is absent —
/// not that the schema is malformed. That matters at the declared floor: on
/// Gateway API v1.4.x `spec.tls.frontend` fails at the intermediate `tls` node
/// rather than the `frontend` leaf, and treating a missing intermediate as an
/// error would log a schema failure on every startup of a perfectly healthy
/// v1.4 cluster.
fn resolve_schema_path(root: &JSONSchemaProps, path: &[&str]) -> bool {
    let mut node = root;
    for name in path {
        match descend(node, name) {
            Some(child) => node = child,
            None => return false,
        }
    }
    true
}

/// One step of [`resolve_schema_path`].
///
/// Property names are matched directly; when the current node is an array (as
/// `rules` and `filters` are on `HTTPRoute`) the step is retried against the
/// item schema. Encoding those array hops in the path table instead would
/// duplicate schema shape upstream is free to change.
fn descend<'a>(node: &'a JSONSchemaProps, name: &str) -> Option<&'a JSONSchemaProps> {
    if let Some(child) = node.properties.as_ref().and_then(|props| props.get(name)) {
        return Some(child);
    }
    match node.items.as_ref()? {
        JSONSchemaPropsOrArray::Schema(item) => descend(item, name),
        JSONSchemaPropsOrArray::Schemas(items) => items.iter().find_map(|i| descend(i, name)),
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::{
        CustomResourceDefinitionNames, CustomResourceDefinitionSpec,
        CustomResourceDefinitionVersion, CustomResourceValidation,
    };

    /// Build an object schema node from `(name, child)` pairs.
    fn object(properties: &[(&str, JSONSchemaProps)]) -> JSONSchemaProps {
        JSONSchemaProps {
            properties: Some(
                properties
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), v.clone()))
                    .collect(),
            ),
            ..JSONSchemaProps::default()
        }
    }

    /// Build an array node whose items are `item`.
    fn array(item: JSONSchemaProps) -> JSONSchemaProps {
        JSONSchemaProps {
            items: Some(JSONSchemaPropsOrArray::Schema(Box::new(item))),
            ..JSONSchemaProps::default()
        }
    }

    fn leaf() -> JSONSchemaProps {
        JSONSchemaProps::default()
    }

    /// The real shape of `HTTPRoute.spec.rules[].filters[].cors` — two array
    /// hops the path table deliberately does not encode.
    fn httproute_schema_with_cors() -> JSONSchemaProps {
        object(&[(
            "spec",
            object(&[(
                "rules",
                array(object(&[("filters", array(object(&[("cors", leaf())])))])),
            )]),
        )])
    }

    fn crd_with_schema(schema: JSONSchemaProps, served: bool) -> CustomResourceDefinition {
        CustomResourceDefinition {
            spec: CustomResourceDefinitionSpec {
                group: GATEWAY_API_GROUP.to_string(),
                names: CustomResourceDefinitionNames::default(),
                scope: "Namespaced".to_string(),
                versions: vec![CustomResourceDefinitionVersion {
                    name: "v1".to_string(),
                    served,
                    storage: true,
                    schema: Some(CustomResourceValidation {
                        open_api_v3_schema: Some(schema),
                    }),
                    ..CustomResourceDefinitionVersion::default()
                }],
                ..CustomResourceDefinitionSpec::default()
            },
            ..CustomResourceDefinition::default()
        }
    }

    #[test]
    fn resolves_a_path_through_two_array_hops() {
        // The v1.5+ shape: cors is nested under two lists, so a resolver that
        // only walked `properties` would report it absent on every version.
        assert!(resolve_schema_path(
            &httproute_schema_with_cors(),
            GatewayApiField::HttpRouteCors.schema_path()
        ));
    }

    #[test]
    fn missing_leaf_resolves_to_absent() {
        // v1.4.x HTTPRoute: same nesting, no cors filter.
        let schema = object(&[(
            "spec",
            object(&[("rules", array(object(&[("filters", array(object(&[])))])))]),
        )]);
        assert!(!resolve_schema_path(
            &schema,
            GatewayApiField::HttpRouteCors.schema_path()
        ));
    }

    #[test]
    fn missing_intermediate_resolves_to_absent_not_error() {
        // v1.4.x Gateway: the whole `tls` subtree is absent, so the walk fails
        // at an intermediate node. This must read as "capability unavailable",
        // which is what lets a healthy v1.4 cluster start without a schema
        // error on every boot.
        let schema = object(&[("spec", object(&[("listeners", array(leaf()))]))]);
        assert!(!resolve_schema_path(
            &schema,
            GatewayApiField::GatewayFrontendTls.schema_path()
        ));
    }

    #[test]
    fn resolves_a_status_rooted_path() {
        let schema = object(&[("status", object(&[("supportedFeatures", array(leaf()))]))]);
        assert!(resolve_schema_path(
            &schema,
            GatewayApiField::GatewayClassSupportedFeatures.schema_path()
        ));
    }

    #[test]
    fn unserved_versions_are_ignored() {
        // A CRD may declare a legacy version with `served: false`; its schema
        // must not contribute, or a field removed from every served version
        // would still read as present.
        let crd = crd_with_schema(httproute_schema_with_cors(), false);
        assert!(!crd_declares_field(
            &crd,
            GatewayApiField::HttpRouteCors.schema_path()
        ));

        let crd = crd_with_schema(httproute_schema_with_cors(), true);
        assert!(crd_declares_field(
            &crd,
            GatewayApiField::HttpRouteCors.schema_path()
        ));
    }

    #[test]
    fn missing_api_group_is_classified_as_absent() {
        // Ingress-only mode depends on this discrimination: without it an
        // uninstalled Gateway API is indistinguishable from an unreachable
        // API server.
        let absent = kube::Error::Discovery(kube::error::DiscoveryError::MissingApiGroup(
            GATEWAY_API_GROUP.to_string(),
        ));
        assert!(is_group_absent(&absent));
    }

    #[test]
    fn api_404_is_classified_as_absent() {
        // Not every API server reports an uninstalled group as
        // `MissingApiGroup`; a bare 404 on the group endpoint means the same
        // thing and must reach Ingress-only mode, not a startup failure.
        let not_found = kube::Error::Api(Box::new(kube::core::Status {
            code: 404,
            reason: "NotFound".to_string(),
            ..kube::core::Status::default()
        }));
        assert!(is_group_absent(&not_found));
    }

    #[test]
    fn transient_failures_are_not_classified_as_absent() {
        // A 403 must NOT read as "no Gateway API" — that would silently
        // advertise an empty feature set on a cluster that has the CRDs but
        // denied us discovery.
        let forbidden = kube::Error::Api(Box::new(kube::core::Status {
            code: 403,
            reason: "Forbidden".to_string(),
            ..kube::core::Status::default()
        }));
        assert!(!is_group_absent(&forbidden));
    }

    #[test]
    fn transport_failures_are_not_classified_as_absent() {
        // Constrains the catch-all arm specifically: an unreachable API server
        // must not read as "no Gateway API", or a blip would put a fully
        // provisioned cluster into Ingress-only mode with an empty feature set.
        let down = kube::Error::Service(Box::new(std::io::Error::other("connection refused")));
        assert!(!is_group_absent(&down));
    }

    fn api_resource(plural: &str, version: &str) -> ApiResource {
        ApiResource {
            group: GATEWAY_API_GROUP.to_string(),
            version: version.to_string(),
            api_version: format!("{GATEWAY_API_GROUP}/{version}"),
            kind: plural.to_string(),
            plural: plural.to_string(),
        }
    }

    #[test]
    fn kind_resolution_prefers_the_first_listed_version() {
        // ReferenceGrant is served as both v1 and v1beta1 from Gateway API
        // v1.5; the vocabulary lists v1 first and that order must decide.
        let resolved = resolve_kinds(|version| {
            vec![api_resource(
                GatewayApiKind::ReferenceGrant.plural(),
                version,
            )]
        });

        let grant = resolved
            .get(&GatewayApiKind::ReferenceGrant)
            .expect("ReferenceGrant resolves when every version serves it");
        assert_eq!(grant.version, "v1");
    }

    #[test]
    fn kind_resolution_falls_back_to_the_older_version() {
        // At the v1.4 floor only v1beta1 exists; resolution must degrade to it
        // rather than leaving ReferenceGrant unresolved.
        let resolved = resolve_kinds(|version| {
            if version == "v1beta1" {
                vec![api_resource(
                    GatewayApiKind::ReferenceGrant.plural(),
                    version,
                )]
            } else {
                Vec::new()
            }
        });

        let grant = resolved
            .get(&GatewayApiKind::ReferenceGrant)
            .expect("ReferenceGrant resolves from its v1beta1-only serving");
        assert_eq!(grant.version, "v1beta1");
    }

    #[test]
    fn kinds_absent_from_discovery_do_not_resolve() {
        // The v1.4 shape: no ListenerSet at any version.
        let resolved = resolve_kinds(|_| Vec::new());
        assert!(resolved.is_empty());
    }

    #[test]
    fn empty_capabilities_report_group_absent_and_satisfy_only_always() {
        let caps = GatewayApiCapabilities::empty();
        assert!(!caps.group_present());
        assert!(caps.satisfies(Requirement::Always));
        assert!(!caps.satisfies(Requirement::Kind(GatewayApiKind::ListenerSet)));
        assert!(!caps.satisfies(Requirement::Field(GatewayApiField::HttpRouteCors)));
        assert_eq!(caps.present_kinds().count(), 0);
    }

    #[test]
    fn satisfies_reflects_detected_kinds_and_fields() {
        let mut kinds = BTreeMap::new();
        kinds.insert(
            GatewayApiKind::HttpRoute,
            ApiResource {
                group: GATEWAY_API_GROUP.to_string(),
                version: "v1".to_string(),
                api_version: format!("{GATEWAY_API_GROUP}/v1"),
                kind: "HTTPRoute".to_string(),
                plural: "httproutes".to_string(),
            },
        );
        let caps = GatewayApiCapabilities {
            kinds,
            fields: [GatewayApiField::HttpRouteCors].into_iter().collect(),
        };

        assert!(caps.group_present());
        assert!(caps.satisfies(Requirement::Kind(GatewayApiKind::HttpRoute)));
        assert!(!caps.satisfies(Requirement::Kind(GatewayApiKind::TcpRoute)));
        assert!(caps.satisfies(Requirement::Field(GatewayApiField::HttpRouteCors)));
        assert!(!caps.satisfies(Requirement::Field(GatewayApiField::GatewayFrontendTls)));

        // The negotiated version must survive detection — the dynamic
        // ReferenceGrant watch reads it back rather than re-negotiating.
        assert_eq!(
            caps.kind(GatewayApiKind::HttpRoute)
                .map(|ar| ar.version.as_str()),
            Some("v1")
        );
    }
}
