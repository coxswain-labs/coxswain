//! Per-host client-certificate mTLS annotation parsing (`auth-tls-*`, #267).
//!
//! Reuses [`super::auth::SecretRef`] / [`super::auth::parse_secret_ref`] for the
//! `auth-tls-secret` reference.

use super::auth::{SecretRef, parse_secret_ref};

// ── Client-certificate mTLS annotations (#267) ───────────────────────────────

/// Reference to a Kubernetes Secret in `namespace/name` form that holds PEM
/// CA certificate(s) under the `ca.crt` key.  Used to verify client certificates
/// at TLS handshake time.  The Secret **must** carry the label
/// `ingress.coxswain-labs.dev/auth-tls: "true"` so only opt-in Secrets are
/// cached by the data-plane reflector (read-only-proxy invariant).
///
/// A missing Secret, an unlabeled Secret, or one without a parseable `ca.crt`
/// key causes the proxy to abort every TLS handshake to this host until the
/// Secret is corrected (fail-closed, matching Istio `tls.mode: MUTUAL`).
pub const AUTH_TLS_SECRET: &str = "ingress.coxswain-labs.dev/auth-tls-secret";

/// Maximum client-certificate chain verification depth.  Must be a positive
/// integer.  When absent or invalid a `WARN` is emitted and the default of `1`
/// (leaf certificate only) is used, matching Istio's default for mutual TLS.
pub const AUTH_TLS_VERIFY_DEPTH: &str = "ingress.coxswain-labs.dev/auth-tls-verify-depth";

/// When `"true"`, the verified client certificate is forwarded to the upstream
/// backend as the `X-SSL-Client-Cert` request header (URL-encoded PEM).
/// When absent or `"false"`, the header is not injected.
pub const AUTH_TLS_PASS_CERT_TO_UPSTREAM: &str =
    "ingress.coxswain-labs.dev/auth-tls-pass-certificate-to-upstream";

// ── Intermediate annotation representation ───────────────────────────────────

/// Intermediate, pre-reconcile client-cert mTLS configuration parsed from the
/// `auth-tls-*` annotations.  The Secret reference is resolved to CA PEM bytes
/// by `IngressReconciler::reconcile_client_certs`; only then does this become a
/// [`ClientCertConfigState`][coxswain_core::tls::ClientCertConfigState].
pub(crate) struct ClientCertAnnotation {
    /// Reference to the CA Secret in `namespace/name` form.
    pub secret: SecretRef,
    /// Maximum chain verification depth (default `1`).
    pub verify_depth: u32,
    /// Whether to forward the verified cert as `X-SSL-Client-Cert`.
    pub pass_to_upstream: bool,
}

// ── Parse helper ─────────────────────────────────────────────────────────────

/// Parse the `auth-tls-*` annotation cluster into a [`ClientCertAnnotation`].
///
/// Returns `None` when `auth-tls-secret` is absent (mTLS disabled for the
/// route).  Invalid values for the optional knobs emit a `WARN` and fall back
/// to safe defaults; the whole block is still produced so long as the Secret
/// reference is valid.
#[must_use]
pub(crate) fn parse_client_cert(
    annotations: &std::collections::BTreeMap<String, String>,
    route_id: &str,
) -> Option<ClientCertAnnotation> {
    use super::get;

    let ref_str = get(annotations, AUTH_TLS_SECRET)?;
    let secret = match parse_secret_ref(ref_str) {
        Some(r) => r,
        None => {
            tracing::warn!(
                ingress = %route_id,
                annotation = AUTH_TLS_SECRET,
                value = ref_str,
                "invalid auth-tls-secret — expected \"namespace/name\" format; mTLS disabled"
            );
            return None;
        }
    };

    let verify_depth = get(annotations, AUTH_TLS_VERIFY_DEPTH)
        .and_then(|v| match v.trim().parse::<u32>() {
            Ok(n) if n >= 1 => Some(n),
            _ => {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = AUTH_TLS_VERIFY_DEPTH,
                    value = v,
                    "invalid auth-tls-verify-depth — expected a positive integer; using default 1"
                );
                None
            }
        })
        .unwrap_or(1);

    let pass_to_upstream = get(annotations, AUTH_TLS_PASS_CERT_TO_UPSTREAM)
        .and_then(|v| {
            let b = super::parse_bool(v);
            if b.is_none() {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = AUTH_TLS_PASS_CERT_TO_UPSTREAM,
                    value = v,
                    "invalid auth-tls-pass-certificate-to-upstream — expected \"true\" or \"false\"; treating as false"
                );
            }
            b
        })
        .unwrap_or(false);

    Some(ClientCertAnnotation {
        secret,
        verify_depth,
        pass_to_upstream,
    })
}

#[cfg(test)]
mod client_cert_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn ann(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ── Annotation const references (satisfies check-annotation-coverage.sh) ─

    #[test]
    fn auth_tls_secret_const_referenced() {
        let _ = AUTH_TLS_SECRET;
    }

    #[test]
    fn auth_tls_verify_depth_const_referenced() {
        let _ = AUTH_TLS_VERIFY_DEPTH;
    }

    #[test]
    fn auth_tls_pass_cert_to_upstream_const_referenced() {
        let _ = AUTH_TLS_PASS_CERT_TO_UPSTREAM;
    }

    // ── parse_client_cert ─────────────────────────────────────────────────────

    #[test]
    fn parse_client_cert_absent_is_none() {
        assert!(parse_client_cert(&ann(&[]), "ns/test").is_none());
    }

    #[test]
    fn parse_client_cert_valid_ref_defaults() {
        let m = ann(&[(AUTH_TLS_SECRET, "default/my-ca")]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert_eq!(cc.secret.namespace, "default");
        assert_eq!(cc.secret.name, "my-ca");
        assert_eq!(cc.verify_depth, 1);
        assert!(!cc.pass_to_upstream);
    }

    #[test]
    fn parse_client_cert_custom_depth() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_VERIFY_DEPTH, "3"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert_eq!(cc.verify_depth, 3);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_client_cert_invalid_depth_warns_and_defaults() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_VERIFY_DEPTH, "bad"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert_eq!(cc.verify_depth, 1);
        assert!(logs_contain("invalid auth-tls-verify-depth"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_client_cert_zero_depth_warns_and_defaults() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_VERIFY_DEPTH, "0"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert_eq!(cc.verify_depth, 1);
        assert!(logs_contain("invalid auth-tls-verify-depth"));
    }

    #[test]
    fn parse_client_cert_pass_to_upstream_true() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_PASS_CERT_TO_UPSTREAM, "true"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert!(cc.pass_to_upstream);
    }

    #[test]
    fn parse_client_cert_pass_to_upstream_false() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_PASS_CERT_TO_UPSTREAM, "false"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert!(!cc.pass_to_upstream);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_client_cert_invalid_pass_to_upstream_warns_and_defaults_false() {
        let m = ann(&[
            (AUTH_TLS_SECRET, "default/my-ca"),
            (AUTH_TLS_PASS_CERT_TO_UPSTREAM, "yes"),
        ]);
        let cc = parse_client_cert(&m, "ns/test").expect("Some");
        assert!(!cc.pass_to_upstream);
        assert!(logs_contain(
            "invalid auth-tls-pass-certificate-to-upstream"
        ));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_client_cert_invalid_secret_ref_warns_and_is_none() {
        let m = ann(&[(AUTH_TLS_SECRET, "no-slash-here")]);
        assert!(parse_client_cert(&m, "ns/test").is_none());
        assert!(logs_contain("invalid auth-tls-secret"));
    }
}
