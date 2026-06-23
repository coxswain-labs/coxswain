//! `KubeTokenAuthenticator` — validates Kubernetes ServiceAccount tokens via
//! the TokenReview API and maps them to SPIFFE identities.
//!
//! Implements [`coxswain_core::TokenAuthenticator`]: given a projected SA token,
//! it calls the Kubernetes `authentication.k8s.io/v1` TokenReview endpoint and
//! derives a [`SpiffeId`] from the authenticated
//! `system:serviceaccount:<ns>:<sa>` username.
//!
//! [`SpiffeId`]: coxswain_core::SpiffeId

use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec, TokenReviewStatus};
use kube::api::PostParams;
use kube::{Api, Client};

use coxswain_core::identity::{AuthnError, SpiffeId, TokenAuthenticator};

// ── KubeTokenAuthenticator ────────────────────────────────────────────────────

/// Authenticates Kubernetes ServiceAccount tokens via the TokenReview API.
///
/// Requires a `kube::Client` with permission to `create` `tokenreviews` in the
/// `authentication.k8s.io` API group (ClusterRole — TokenReviews are cluster-scoped).
#[non_exhaustive]
pub struct KubeTokenAuthenticator {
    client: Client,
    /// Expected token audience; passed as `spec.audiences` to the TokenReview.
    /// The API server only authenticates tokens issued for this audience.
    audience: String,
    /// SPIFFE trust domain; used to build the returned [`SpiffeId`].
    trust_domain: String,
}

impl KubeTokenAuthenticator {
    /// Create a new authenticator.
    ///
    /// `audience` must match the audience configured on the proxy's projected
    /// SA-token volume (e.g. `"coxswain-discovery"`).  `trust_domain` is the
    /// SPIFFE trust domain (typically `"cluster.local"`).
    #[must_use]
    pub fn new(
        client: Client,
        audience: impl Into<String>,
        trust_domain: impl Into<String>,
    ) -> Self {
        Self {
            client,
            audience: audience.into(),
            trust_domain: trust_domain.into(),
        }
    }
}

impl TokenAuthenticator for KubeTokenAuthenticator {
    async fn authenticate(&self, token: &str) -> Result<SpiffeId, AuthnError> {
        let api: Api<TokenReview> = Api::all(self.client.clone());

        let tr = TokenReview {
            spec: TokenReviewSpec {
                token: Some(token.to_owned()),
                audiences: Some(vec![self.audience.clone()]),
            },
            ..Default::default()
        };

        let result = api
            .create(&PostParams::default(), &tr)
            .await
            .map_err(|e| AuthnError::ApiError(e.to_string()))?;

        parse_token_review_status(result.status.as_ref(), &self.trust_domain)
    }
}

/// Parse a [`TokenReviewStatus`] into a [`SpiffeId`].
///
/// Returns `Err(AuthnError::Unauthenticated)` when the API server rejected
/// the token, `Err(AuthnError::InvalidPrincipal)` when the username does not
/// have the expected `system:serviceaccount:<ns>:<sa>` form.
fn parse_token_review_status(
    status: Option<&TokenReviewStatus>,
    trust_domain: &str,
) -> Result<SpiffeId, AuthnError> {
    let status =
        status.ok_or_else(|| AuthnError::ApiError("TokenReview response has no status".into()))?;

    // The API server reports a non-empty error string when the token is invalid
    // even if `authenticated` is false.
    if let Some(err) = &status.error
        && !err.is_empty()
    {
        return Err(AuthnError::Unauthenticated(err.clone()));
    }

    if !status.authenticated.unwrap_or(false) {
        return Err(AuthnError::Unauthenticated(
            "token not authenticated".into(),
        ));
    }

    let username = status
        .user
        .as_ref()
        .and_then(|u| u.username.as_deref())
        .unwrap_or("");

    sa_username_to_spiffe_id(username, trust_domain)
}

/// Convert a `system:serviceaccount:<ns>:<sa>` username to a [`SpiffeId`].
fn sa_username_to_spiffe_id(username: &str, trust_domain: &str) -> Result<SpiffeId, AuthnError> {
    const PREFIX: &str = "system:serviceaccount:";
    let rest = username.strip_prefix(PREFIX).ok_or_else(|| {
        AuthnError::InvalidPrincipal(format!("expected {PREFIX}<ns>:<sa>, got: {username}"))
    })?;

    let (ns, sa) = rest.split_once(':').ok_or_else(|| {
        AuthnError::InvalidPrincipal(format!(
            "expected {PREFIX}<ns>:<sa>, missing ':' in: {rest}"
        ))
    })?;

    if ns.is_empty() || sa.is_empty() {
        return Err(AuthnError::InvalidPrincipal(format!(
            "namespace and service account must not be empty: {username}"
        )));
    }

    Ok(SpiffeId::from_parts(trust_domain, ns, sa))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use k8s_openapi::api::authentication::v1::UserInfo;

    fn ok_status(username: &str) -> TokenReviewStatus {
        TokenReviewStatus {
            authenticated: Some(true),
            user: Some(UserInfo {
                username: Some(username.to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn reject_status(msg: &str) -> TokenReviewStatus {
        TokenReviewStatus {
            authenticated: Some(false),
            error: Some(msg.to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn valid_token_maps_to_spiffe_id() {
        let status = ok_status("system:serviceaccount:coxswain-system:coxswain-proxy");
        let id = parse_token_review_status(Some(&status), "cluster.local").expect("should parse");
        assert_eq!(id.trust_domain(), "cluster.local");
        assert_eq!(id.namespace(), "coxswain-system");
        assert_eq!(id.service_account(), "coxswain-proxy");
    }

    #[test]
    fn rejected_token_returns_unauthenticated() {
        let status = reject_status("token has expired");
        let err =
            parse_token_review_status(Some(&status), "cluster.local").expect_err("should reject");
        assert!(
            matches!(err, AuthnError::Unauthenticated(_)),
            "expected Unauthenticated, got: {err}"
        );
    }

    #[test]
    fn unauthenticated_without_error_string() {
        let status = TokenReviewStatus {
            authenticated: Some(false),
            ..Default::default()
        };
        let err =
            parse_token_review_status(Some(&status), "cluster.local").expect_err("should reject");
        assert!(matches!(err, AuthnError::Unauthenticated(_)));
    }

    #[test]
    fn missing_status_returns_api_error() {
        let err = parse_token_review_status(None, "cluster.local").expect_err("should fail");
        assert!(matches!(err, AuthnError::ApiError(_)));
    }

    #[test]
    fn non_sa_username_returns_invalid_principal() {
        let status = ok_status("admin");
        let err =
            parse_token_review_status(Some(&status), "cluster.local").expect_err("should fail");
        assert!(matches!(err, AuthnError::InvalidPrincipal(_)));
    }

    #[test]
    fn sa_username_parsing_roundtrips() {
        let cases = [
            ("system:serviceaccount:default:my-app", "default", "my-app"),
            (
                "system:serviceaccount:kube-system:coredns",
                "kube-system",
                "coredns",
            ),
        ];
        for (username, ns, sa) in cases {
            let id = sa_username_to_spiffe_id(username, "cluster.local")
                .unwrap_or_else(|e| panic!("parse {username}: {e}"));
            assert_eq!(id.namespace(), ns, "ns for {username}");
            assert_eq!(id.service_account(), sa, "sa for {username}");
        }
    }

    #[test]
    fn empty_namespace_or_sa_is_rejected() {
        assert!(sa_username_to_spiffe_id("system:serviceaccount::sa", "cluster.local").is_err());
        assert!(sa_username_to_spiffe_id("system:serviceaccount:ns:", "cluster.local").is_err());
    }
}
