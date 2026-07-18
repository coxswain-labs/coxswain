//! `JwtAuth` resolution (#441): spec → runtime [`IngressAuthConfig`] translation
//! shared by the route-level `ExtensionRef` filter (in [`super::filters`]) and
//! the Ingress `auth-jwt` annotation (`crate::ingress`).
//!
//! Unlike [`super::external_auth`], there is no `backendRef` to resolve to
//! endpoints — the only external dependency is a remote JWKS, and that is
//! resolved by the controller-side [`crate::jwks::JwksCacheHandle`] background
//! fetcher, never inline here. `resolve_spec` only ever does synchronous,
//! infallible-I/O work: look up the cache, or read the CRD's inline JWKS.

use coxswain_core::crd::JwtAuthSpec;
use coxswain_core::routing::{IngressAuthConfig, JwtConfig, JwtHeaderLoc};
use std::sync::Arc;

/// Resolve a `JwtAuth` spec into the runtime [`IngressAuthConfig`] the proxy
/// enforces.
///
/// Returns [`IngressAuthConfig::Unavailable`] (fail-closed 503) when: neither
/// `jwks.remote` nor `jwks.inline` is set (misconfigured CR — the schema
/// allows this, see [`coxswain_core::crd::JwksSource`]'s doc comment), or a
/// configured remote JWKS hasn't been fetched yet or is currently failing. An
/// operator who attached this filter expects enforcement, so an unresolved
/// JWKS must never silently open the route.
///
/// `jwks_cache` is looked up **read-only** and synchronously — the fetch
/// itself runs in [`crate::jwks::run`], entirely decoupled from reconcile.
///
/// `pub(crate)` (not `pub(super)` like its Gateway API siblings) — reused
/// directly by [`crate::ingress::reconcile_helpers`] so the Ingress `auth-jwt`
/// annotation resolves to the identical [`IngressAuthConfig`] the HTTPRoute
/// `ExtensionRef` filter produces (Gateway API parity, #441).
#[must_use]
pub(crate) fn resolve_spec(
    spec: &JwtAuthSpec,
    jwks_cache: &crate::jwks::JwksCacheHandle,
    route_id: &str,
) -> IngressAuthConfig {
    let jwks = match (&spec.jwks.remote, &spec.jwks.inline) {
        (Some(remote), None) => {
            let Some(text) = jwks_cache.get(&remote.uri) else {
                tracing::warn!(
                    route = route_id,
                    jwks_uri = %remote.uri,
                    "JwtAuth remote JWKS not yet resolved — failing closed (503)"
                );
                return IngressAuthConfig::Unavailable;
            };
            text
        }
        (None, Some(inline)) => match serde_json::to_string(&inline.jwks) {
            Ok(text) => Arc::from(text),
            Err(e) => {
                // `inline.jwks` is `serde_json::Value`, already deserialized —
                // re-serializing it cannot fail in practice. Fail closed anyway
                // rather than `unwrap`, matching the module's crypto-free /
                // reconcile-never-panics-on-CRD-input posture.
                tracing::warn!(
                    route = route_id,
                    error = %e,
                    "JwtAuth inline JWKS could not be re-serialized — failing closed (503)"
                );
                return IngressAuthConfig::Unavailable;
            }
        },
        (None, None) => {
            tracing::warn!(
                route = route_id,
                "JwtAuth has neither jwks.remote nor jwks.inline set — failing closed (503)"
            );
            return IngressAuthConfig::Unavailable;
        }
        (Some(_), Some(_)) => {
            tracing::warn!(
                route = route_id,
                "JwtAuth sets both jwks.remote and jwks.inline — mutually exclusive, failing closed (503)"
            );
            return IngressAuthConfig::Unavailable;
        }
    };

    // Absent `fromHeaders` defaults to the GEP-1494/Envoy convention: a bearer
    // token in the standard `Authorization` header.
    let from_headers: Arc<[JwtHeaderLoc]> = if spec.from_headers.is_empty() {
        Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")])
    } else {
        spec.from_headers
            .iter()
            .map(|h| JwtHeaderLoc::new(h.name.as_str(), h.value_prefix.as_deref().unwrap_or("")))
            .collect()
    };

    IngressAuthConfig::Jwt(JwtConfig::new(
        Arc::from(spec.issuer.as_str()),
        spec.audiences
            .iter()
            .map(|a| Box::from(a.as_str()))
            .collect(),
        jwks,
        from_headers,
        spec.forward_payload_header.as_deref().map(Box::from),
        spec.claim_to_headers
            .iter()
            .map(|c| (Box::from(c.claim.as_str()), Box::from(c.header.as_str())))
            .collect(),
        spec.forward.unwrap_or(false),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(missing_docs)]

    use super::*;
    use crate::jwks::JwksCacheHandle;

    /// Build a `JwtAuthSpec` from a `jwks:` YAML fragment. `JwksSource` and its
    /// nested types are `#[non_exhaustive]` and defined in `coxswain-core` — a
    /// different crate — so cross-crate struct literals are unavailable here;
    /// deserializing from YAML is the only construction path, mirroring the
    /// CRD's own test convention (`crd::jwt_auth::tests::parse_cr`).
    fn spec_with(jwks_yaml: &str) -> JwtAuthSpec {
        let indented = jwks_yaml.replace('\n', "\n    ");
        let yaml = format!(
            "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n\
             kind: JwtAuth\n\
             metadata:\n  name: t\n\
             spec:\n  issuer: https://issuer.example.com\n  jwks:\n    {indented}\n",
        );
        serde_yaml::from_str::<coxswain_core::crd::JwtAuth>(&yaml)
            .unwrap_or_else(|e| panic!("bad yaml: {e}\n---\n{yaml}"))
            .spec
    }

    #[test]
    fn neither_remote_nor_inline_fails_closed() {
        let spec = spec_with("{}");
        let cache = JwksCacheHandle::new();
        assert!(matches!(
            resolve_spec(&spec, &cache, "ns/route"),
            IngressAuthConfig::Unavailable
        ));
    }

    #[test]
    fn unresolved_remote_jwks_fails_closed() {
        let spec = spec_with("remote:\n  uri: https://issuer.example.com/jwks.json");
        let cache = JwksCacheHandle::new(); // never populated
        assert!(matches!(
            resolve_spec(&spec, &cache, "ns/route"),
            IngressAuthConfig::Unavailable
        ));
    }

    #[test]
    fn inline_jwks_resolves() {
        let spec = spec_with("inline:\n  jwks:\n    keys: []");
        let cache = JwksCacheHandle::new();
        let IngressAuthConfig::Jwt(cfg) = resolve_spec(&spec, &cache, "ns/route") else {
            panic!("expected Jwt config");
        };
        assert_eq!(&*cfg.issuer, "https://issuer.example.com");
        assert_eq!(&*cfg.jwks, r#"{"keys":[]}"#);
        // Default from_headers: Authorization / "Bearer ".
        assert_eq!(cfg.from_headers.len(), 1);
        assert_eq!(&*cfg.from_headers[0].name, "Authorization");
        assert_eq!(&*cfg.from_headers[0].value_prefix, "Bearer ");
        assert!(!cfg.forward_token);
    }

    #[test]
    fn both_remote_and_inline_fails_closed() {
        let spec = spec_with(
            "remote:\n  uri: https://issuer.example.com/jwks.json\ninline:\n  jwks:\n    keys: []",
        );
        let cache = JwksCacheHandle::new();
        assert!(matches!(
            resolve_spec(&spec, &cache, "ns/route"),
            IngressAuthConfig::Unavailable
        ));
    }
}
