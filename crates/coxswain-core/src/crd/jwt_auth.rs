//! `JwtAuth` CRD — per-route JWT (JWKS bearer-token) validation for Gateway-API
//! `HTTPRoute`s and `GRPCRoute`s.
//!
//! Attached to a route rule via an `ExtensionRef` filter (group
//! `gateway.coxswain-labs.dev`, kind `JwtAuth`), or to an Ingress via the
//! `ingress.coxswain-labs.dev/auth-jwt: "namespace/name"` annotation — both
//! surfaces resolve the same CR to the same runtime
//! [`JwtConfig`](crate::routing::JwtConfig). Follow-up to #77.
//!
//! Unlike `BasicAuth` (an HTTP/browser idiom, deliberately excluded from
//! `GRPCRoute`), bearer/JWT auth is a common gRPC pattern, so `JwtAuth` is
//! wired on both route kinds.
//!
//! Modeled on Envoy's `envoy.filters.http.jwt_authn` `JwtProvider` / Istio
//! `RequestAuthentication.jwtRules` — a first-class Envoy concept. No Gateway
//! API standard exists for in-proxy JWT validation (GEP-1494 covers *delegated*
//! ext_authz, a different model); this is net-new capability.
//!
//! **JWKS resolution happens in the control plane** (the Istio model, not
//! Envoy's default proxy-side fetch): a remote [`RemoteJwks::uri`] is fetched
//! and refreshed by the reflector, never by the proxy, so the read-only data
//! plane never egresses to an identity provider. Inline JWKS
//! ([`InlineJwks::jwks`]) and a resolved remote JWKS both collapse to the same
//! resolved-JWK-set representation on the wire.
//!
//! Source of truth is the Rust type below; the on-disk CRD YAML
//! (`deploy/manifests/crds/jwtauths.yaml` and `charts/coxswain/crds/jwtauths.yaml`)
//! is generated from it by `examples/crdgen.rs` and pinned by a snapshot test.

use kube::CustomResource;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

/// JWT (JWKS bearer-token) validation policy for a route rule.
///
/// Reference this CR from a rule's `filters` entry with `type: ExtensionRef`
/// pointing at `group: gateway.coxswain-labs.dev`, `kind: JwtAuth`, or from an
/// Ingress via `ingress.coxswain-labs.dev/auth-jwt: "namespace/name"`. The
/// proxy validates the bearer token's signature against the resolved JWKS,
/// `iss` against [`issuer`](Self::issuer), and `aud` against
/// [`audiences`](Self::audiences) (when non-empty); a missing/invalid token
/// responds `401` with `WWW-Authenticate: Bearer`. An unresolved JWKS (broken
/// `jwksUri`) fails closed with `503`. Only asymmetric signing algorithms are
/// supported (RS/PS/ES/EdDSA) — JWKS is inherently asymmetric.
#[derive(CustomResource, Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.coxswain-labs.dev",
    version = "v1alpha1",
    kind = "JwtAuth",
    plural = "jwtauths",
    namespaced
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct JwtAuthSpec {
    /// Expected token `iss` (issuer) claim. Required — Envoy `JwtProvider.issuer`.
    pub issuer: String,

    /// Expected token `aud` (audience) claims. A token is accepted if any of its
    /// audiences matches any entry here. Empty (the default) skips the audience
    /// check entirely — Envoy `JwtProvider.audiences`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<String>,

    /// Where the verification keys come from — a remote JWKS endpoint (resolved
    /// and cached by the controller) or an inline key set.
    pub jwks: JwksSource,

    /// Request locations to extract the token from. Absent (the default) looks
    /// for `Authorization: Bearer <token>` — Envoy `JwtProvider.from_headers`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_headers: Vec<JwtHeaderLocation>,

    /// When set, the base64url-encoded verified claims payload is forwarded to
    /// the upstream in this header — Envoy `JwtProvider.forward_payload_header`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_payload_header: Option<String>,

    /// Verified claims copied onto upstream request headers. A named claim that
    /// is absent or non-scalar on the token is skipped (no header written).
    /// Envoy `JwtProvider.claim_to_headers`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claim_to_headers: Vec<ClaimToHeader>,

    /// Whether to keep the original token header(s) on the upstream request
    /// after verification. Absent or `false` (the default and Envoy's default)
    /// strips it — Envoy `JwtProvider.forward`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward: Option<bool>,
}

/// Source of a [`JwtAuth`]'s verification keys — exactly one of
/// [`remote`](Self::remote) / [`inline`](Self::inline) must be set.
///
/// A Rust sum type (`enum`) would be the natural shape, but `kube`'s CRD
/// structural-schema generation rejects internally-tagged enums whose variants
/// don't share an identical schema for the tag field (a K8s apiserver
/// structural-schema constraint, not a schemars limitation). This mirrors the
/// existing [`ForwardBodyConfig`](super::ForwardBodyConfig) pattern instead:
/// both fields are schema-optional, and "neither set" / "both set" is caught
/// at reconcile time (WARN + [`IngressAuthConfig::Unavailable`][crate::routing::IngressAuthConfig::Unavailable],
/// fail-closed) rather than by the apiserver.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct JwksSource {
    /// Fetch the JWKS from a remote HTTPS endpoint. Resolved and refreshed by
    /// the controller (never the proxy) — the proxy only ever verifies against
    /// keys already pushed to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteJwks>,
    /// A JWKS provided directly in the spec — no controller-side fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline: Option<InlineJwks>,
}

/// A remote JWKS endpoint, refreshed by the controller.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemoteJwks {
    /// HTTPS URL serving a JSON Web Key Set (RFC 7517 `{"keys": [...]}`).
    pub uri: String,
    /// How often to refetch, as a Gateway API Duration (e.g. `"5m"`). Absent or
    /// unparseable → **5 minutes** (WARN + default at the reflector, never an
    /// apiserver rejection). The response's `Cache-Control` header is not
    /// consulted — this is the only refresh signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<String>,
}

/// A JWKS supplied inline in the spec.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InlineJwks {
    /// A JSON Web Key Set object (RFC 7517 `{"keys": [...]}`), verbatim.
    /// Schema-free (any JSON) — an unparseable or empty key set is caught at
    /// reconcile time and fails the route closed, never an apiserver rejection.
    #[schemars(schema_with = "preserve_unknown_fields_schema")]
    pub jwks: serde_json::Value,
}

fn preserve_unknown_fields_schema(_: &mut SchemaGenerator) -> Schema {
    serde_json::from_value(serde_json::json!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true,
    }))
    .unwrap_or_else(|e| panic!("invariant: preserve-unknown-fields schema is a valid Schema: {e}"))
}

/// One request location to look for the bearer token in — Envoy
/// `JwtProvider.from_headers` entry.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct JwtHeaderLocation {
    /// Header name to read the token from.
    pub name: String,
    /// Prefix stripped from the header value before parsing the token (e.g.
    /// `"Bearer "`). Absent means the header value *is* the token verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_prefix: Option<String>,
}

/// Copies one verified claim onto an upstream request header — Envoy
/// `JwtProvider.claim_to_headers` entry.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClaimToHeader {
    /// Top-level claim name to read from the verified token payload.
    pub claim: String,
    /// Upstream request header name to write the claim value to.
    pub header: String,
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::CustomResourceExt;

    const MANIFEST_CRD_YAML: &str = include_str!("../../../../deploy/manifests/crds/jwtauths.yaml");
    const CHART_CRD_YAML: &str = include_str!("../../../../charts/coxswain/crds/jwtauths.yaml");

    fn parse_cr(spec_fragment: &str) -> JwtAuth {
        let indented = spec_fragment.replace('\n', "\n  ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: JwtAuth\n\
             metadata:\n  name: t\n\
             spec:\n  {indented}\n",
        );
        serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("parse failed: {e}\n--- yaml ---\n{yaml}"))
    }

    #[test]
    fn committed_manifest_crd_matches_generator() {
        let on_disk: CustomResourceDefinition = serde_yaml::from_str(MANIFEST_CRD_YAML)
            .unwrap_or_else(|e| panic!("committed CRD YAML must deserialize: {e}"));
        let generated = JwtAuth::crd();
        assert_eq!(
            on_disk, generated,
            "deploy/manifests/crds/jwtauths.yaml drifted from the Rust type. \
             Regenerate: cargo run -p coxswain-core --example crdgen -- JwtAuth \
             > deploy/manifests/crds/jwtauths.yaml \
             && cp deploy/manifests/crds/jwtauths.yaml \
             charts/coxswain/crds/jwtauths.yaml",
        );
    }

    #[test]
    fn chart_crd_is_byte_identical_to_manifest_crd() {
        assert_eq!(
            MANIFEST_CRD_YAML, CHART_CRD_YAML,
            "deploy/manifests/crds and charts/coxswain/crds CRDs diverged; \
             copy the manifest CRD over the chart CRD",
        );
    }

    #[test]
    fn minimal_inline_spec_deserializes() {
        let cr = parse_cr(concat!(
            "issuer: https://issuer.example.com\n",
            "jwks:\n",
            "  inline:\n",
            "    jwks:\n",
            "      keys: []",
        ));
        assert_eq!(cr.spec.issuer, "https://issuer.example.com");
        assert!(cr.spec.audiences.is_empty());
        assert!(cr.spec.jwks.remote.is_none());
        assert!(cr.spec.jwks.inline.is_some());
        assert!(cr.spec.from_headers.is_empty());
        assert!(cr.spec.claim_to_headers.is_empty());
        assert!(cr.spec.forward.is_none());
        assert!(cr.spec.forward_payload_header.is_none());
    }

    #[test]
    fn full_remote_spec_round_trips() {
        let cr = parse_cr(concat!(
            "issuer: https://issuer.example.com\n",
            "audiences: [my-api, my-other-api]\n",
            "jwks:\n",
            "  remote:\n",
            "    uri: https://issuer.example.com/.well-known/jwks.json\n",
            "    refreshInterval: 5m\n",
            "fromHeaders:\n",
            "- name: Authorization\n",
            "  valuePrefix: \"Bearer \"\n",
            "forwardPayloadHeader: x-jwt-payload\n",
            "claimToHeaders:\n",
            "- claim: sub\n",
            "  header: x-user-id\n",
            "forward: true",
        ));
        assert_eq!(cr.spec.audiences, vec!["my-api", "my-other-api"]);
        let remote = cr.spec.jwks.remote.as_ref().expect("remote JWKS source");
        assert_eq!(
            remote.uri,
            "https://issuer.example.com/.well-known/jwks.json"
        );
        assert_eq!(remote.refresh_interval.as_deref(), Some("5m"));
        assert!(cr.spec.jwks.inline.is_none());
        assert_eq!(cr.spec.from_headers.len(), 1);
        assert_eq!(cr.spec.from_headers[0].name, "Authorization");
        assert_eq!(
            cr.spec.from_headers[0].value_prefix.as_deref(),
            Some("Bearer ")
        );
        assert_eq!(
            cr.spec.forward_payload_header.as_deref(),
            Some("x-jwt-payload")
        );
        assert_eq!(cr.spec.claim_to_headers.len(), 1);
        assert_eq!(cr.spec.claim_to_headers[0].claim, "sub");
        assert_eq!(cr.spec.claim_to_headers[0].header, "x-user-id");
        assert_eq!(cr.spec.forward, Some(true));
    }

    #[test]
    fn missing_issuer_is_rejected() {
        let yaml = "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
                    kind: JwtAuth\n\
                    metadata:\n  name: bad\n\
                    spec:\n  jwks:\n    inline:\n      jwks: {}\n";
        serde_yaml::from_str::<JwtAuth>(yaml).expect_err("missing issuer must be rejected");
    }

    #[test]
    fn missing_jwks_is_rejected() {
        let yaml = "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
                    kind: JwtAuth\n\
                    metadata:\n  name: bad\n\
                    spec:\n  issuer: https://issuer.example.com\n";
        serde_yaml::from_str::<JwtAuth>(yaml).expect_err("missing jwks must be rejected");
    }

    /// `JwksSource` has no schema-level oneOf (see the type's doc comment for
    /// why) — an empty `jwks: {}` is schema-valid and must be caught at
    /// reconcile time (`Unavailable`, fail-closed), not here.
    #[test]
    fn jwks_with_neither_remote_nor_inline_is_schema_valid() {
        let cr = parse_cr("issuer: https://issuer.example.com\njwks: {}");
        assert!(cr.spec.jwks.remote.is_none());
        assert!(cr.spec.jwks.inline.is_none());
    }
}
