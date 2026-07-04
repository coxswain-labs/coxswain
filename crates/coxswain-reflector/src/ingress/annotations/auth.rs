//! Request-authentication annotation parsing (`auth-*`, #24): external
//! (`ext_authz`-HTTP) and basic auth, plus the htpasswd / Secret-ref helpers.
//! `SecretRef` and `parse_secret_ref` are reused by the sibling client-cert
//! mTLS module ([`super::client_cert`]).

use super::AnnotationIssue;

// ── Auth annotations (#24) ───────────────────────────────────────────────────

/// Full URL of the external auth endpoint, e.g.
/// `"http://oauth2-proxy.auth.svc/oauth2/auth"`.  When present, the proxy
/// sends a sub-request (Envoy `ext_authz`-HTTP semantics); 2xx allows and the
/// original request continues; any other status code is returned to the client.
/// Mutually exclusive with `auth-basic-secret` — when both are present a `WARN`
/// is emitted and `auth-url` takes precedence.
pub const AUTH_URL: &str = "ingress.coxswain-labs.dev/auth-url";

/// Maximum time to wait for the auth service to respond before failing the
/// request with 503.  Format is a duration string (`"500ms"`, `"2s"`, etc.).
/// When absent or invalid the default of **2 s** is used.
pub const AUTH_TIMEOUT: &str = "ingress.coxswain-labs.dev/auth-timeout";

/// Comma-separated list of header names to copy from the auth *response* onto
/// the upstream *request* when the auth service returns 2xx.  Mirrors Envoy's
/// `allowed_upstream_headers` / Istio's `headersToUpstreamOnAllow`.
pub const AUTH_RESPONSE_HEADERS: &str = "ingress.coxswain-labs.dev/auth-response-headers";

/// When `"true"`, copy the `Set-Cookie` header from the auth *response* onto
/// the downstream *response* when the auth service denies the request.  Mirrors
/// Envoy's `allowed_client_headers` / Istio's `headersToDownstreamOnDeny`.
/// Enables IdP login-redirect flows (`302 + Set-Cookie`) without leaking other
/// auth-response headers to the client.
pub const AUTH_ALWAYS_SET_COOKIE: &str = "ingress.coxswain-labs.dev/auth-always-set-cookie";

/// Reference to an htpasswd [`Secret`] in `namespace/name` form, e.g.
/// `"default/my-htpasswd"`.  The Secret **must** carry the label
/// `ingress.coxswain-labs.dev/auth-basic: "true"` and store the htpasswd file
/// under the key `auth` (nginx convention).  A missing Secret, an unlabeled
/// Secret, or one without a parseable `auth` key causes the proxy to respond
/// with 503 (fail-closed) and emit a loud `WARN` naming the issue.
///
/// Mutually exclusive with `auth-url`.
pub const AUTH_BASIC_SECRET: &str = "ingress.coxswain-labs.dev/auth-basic-secret";

// ── Intermediate annotation representation (pre-reconcile) ──────────────────

/// A reference to a Kubernetes Secret in `namespace/name` form.
pub(crate) struct SecretRef {
    pub namespace: String,
    pub name: String,
}

/// Intermediate, pre-reconcile auth configuration parsed from the `auth-*`
/// annotations.  Secret references are resolved to credentials by
/// `IngressReconciler::reconcile`; only then does this become an
/// [`IngressAuthConfig`][coxswain_core::routing::IngressAuthConfig].
pub(crate) enum AuthAnnotation {
    /// Delegate auth to an external service (ext_authz HTTP).
    External {
        url: String,
        timeout: std::time::Duration,
        response_headers: Vec<String>,
        always_set_cookie: bool,
    },
    /// Validate `Authorization: Basic` against an htpasswd Secret.
    Basic(SecretRef),
}

// ── Parse helpers ────────────────────────────────────────────────────────────

/// Parse the `auth-*` annotation cluster into an [`AuthAnnotation`].
///
/// Returns `None` when neither `auth-url` nor `auth-basic-secret` is present.
/// When both are present, a `WARN` is emitted and `auth-url` wins.  Invalid
/// values for the optional knobs (`auth-timeout`, `auth-response-headers`,
/// `auth-always-set-cookie`) emit a `WARN` and fall back to safe defaults; the
/// whole auth block is still produced.
#[must_use]
pub(crate) fn parse_auth(
    annotations: &std::collections::BTreeMap<String, String>,
    route_id: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Option<AuthAnnotation> {
    use super::get;

    let url = get(annotations, AUTH_URL);
    let basic = get(annotations, AUTH_BASIC_SECRET);

    if url.is_some() && basic.is_some() {
        tracing::warn!(
            ingress = %route_id,
            "auth-url and auth-basic-secret are mutually exclusive — using auth-url"
        );
        diag.push(AnnotationIssue {
            annotation: AUTH_URL,
            message: "auth-url and auth-basic-secret are mutually exclusive — using auth-url"
                .into(),
        });
    }

    if let Some(u) = url {
        let timeout = get(annotations, AUTH_TIMEOUT)
            .and_then(|v| {
                let d = super::parse_duration(v);
                if d.is_none() {
                    tracing::warn!(
                        ingress = %route_id,
                        annotation = AUTH_TIMEOUT,
                        value = v,
                        "invalid auth-timeout — using default 2s"
                    );
                    diag.push(AnnotationIssue {
                        annotation: AUTH_TIMEOUT,
                        message: "invalid auth-timeout — using default 2s".into(),
                    });
                }
                d
            })
            .unwrap_or_else(|| std::time::Duration::from_secs(2));

        let response_headers = get(annotations, AUTH_RESPONSE_HEADERS)
            .map(parse_auth_response_headers)
            .unwrap_or_default();

        let always_set_cookie = get(annotations, AUTH_ALWAYS_SET_COOKIE)
            .and_then(|v| {
                let b = super::parse_bool(v);
                if b.is_none() {
                    tracing::warn!(
                        ingress = %route_id,
                        annotation = AUTH_ALWAYS_SET_COOKIE,
                        value = v,
                        "invalid auth-always-set-cookie — treating as false"
                    );
                    diag.push(AnnotationIssue {
                        annotation: AUTH_ALWAYS_SET_COOKIE,
                        message: "invalid auth-always-set-cookie — treating as false".into(),
                    });
                }
                b
            })
            .unwrap_or(false);

        return Some(AuthAnnotation::External {
            url: u.to_string(),
            timeout,
            response_headers,
            always_set_cookie,
        });
    }

    if let Some(ref_str) = basic {
        match parse_secret_ref(ref_str) {
            Some(secret_ref) => return Some(AuthAnnotation::Basic(secret_ref)),
            None => {
                tracing::warn!(
                    ingress = %route_id,
                    annotation = AUTH_BASIC_SECRET,
                    value = ref_str,
                    "invalid auth-basic-secret — expected \"namespace/name\" format; auth disabled"
                );
                diag.push(AnnotationIssue {
                    annotation: AUTH_BASIC_SECRET,
                    message: format!(
                        "invalid auth-basic-secret '{ref_str}' — expected \"namespace/name\" format; auth disabled"
                    ),
                });
            }
        }
    }

    None
}

/// Parse a comma-separated list of response-header names to forward upstream.
///
/// Empty tokens are silently filtered. Header names are lower-cased for
/// case-insensitive comparison later.
fn parse_auth_response_headers(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

/// Parse a `namespace/name` reference.  Returns `None` when the value does not
/// contain exactly one `/` with non-empty parts on both sides.
pub(super) fn parse_secret_ref(s: &str) -> Option<SecretRef> {
    let (ns, name) = s.split_once('/')?;
    let ns = ns.trim();
    let name = name.trim();
    if ns.is_empty() || name.is_empty() {
        return None;
    }
    Some(SecretRef {
        namespace: ns.to_string(),
        name: name.to_string(),
    })
}

/// Parse an htpasswd file from raw bytes into a list of [`BasicCredential`]s.
///
/// Lines starting with `#` and blank lines are skipped.  Each non-empty,
/// non-comment line must be `username:hash`.  Unsupported hash algorithms (MD5,
/// SHA-256, crypt, …) emit a `WARN` and are skipped — the remaining entries
/// still apply.  An empty or fully-unparseable file produces an empty `Vec`;
/// the caller (reconciler) maps that to [`IngressAuthConfig::Unavailable`] so
/// the proxy fails closed.
///
/// # Supported formats
///
/// - bcrypt: hash prefix `$2a$`, `$2b$`, or `$2y$`
/// - Apache SHA1: hash prefix `{SHA}` (base64-encoded SHA1 of the password); accepted for
///   compatibility but emits a `WARN` log and an `AnnotationIssue` per affected entry —
///   SHA1 is unsalted and unsuitable for password storage; regenerate with `htpasswd -B`.
#[must_use]
pub(crate) fn parse_htpasswd(
    data: &[u8],
    route_id: &str,
    diag: &mut Vec<AnnotationIssue>,
) -> Vec<coxswain_core::routing::BasicCredential> {
    use coxswain_core::routing::{BasicCredential, PasswordHash};

    let Ok(text) = std::str::from_utf8(data) else {
        tracing::warn!("htpasswd Secret data is not valid UTF-8 — no credentials loaded");
        return Vec::new();
    };

    text.lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            // Log the 1-based line number, never the line content: an htpasswd line
            // is `user:hash`, so emitting it would leak the password hash into logs.
            let line_number = idx + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let Some((username, hash)) = line.split_once(':') else {
                tracing::warn!(line_number, "htpasswd line has no ':' separator — skipping");
                return None;
            };
            let username = username.trim();
            let hash = hash.trim();
            if username.is_empty() || hash.is_empty() {
                tracing::warn!(
                    line_number,
                    "htpasswd line has empty username or hash — skipping"
                );
                return None;
            }

            let password_hash = if hash.starts_with("$2a$")
                || hash.starts_with("$2b$")
                || hash.starts_with("$2y$")
            {
                PasswordHash::Bcrypt(hash.into())
            } else if hash.starts_with("{SHA}") {
                tracing::warn!(
                    ingress = %route_id,
                    user = username,
                    "htpasswd entry uses SHA1 which is not suitable for password storage; \
                     regenerate with bcrypt (htpasswd -B)"
                );
                diag.push(AnnotationIssue {
                    annotation: AUTH_BASIC_SECRET,
                    message: format!(
                        "htpasswd entry for user '{username}' uses SHA1 which is not suitable \
                         for password storage; regenerate with bcrypt (htpasswd -B)"
                    ),
                });
                PasswordHash::Sha1(hash.into())
            } else {
                tracing::warn!(
                    username = username,
                    hash_prefix = &hash[..hash.len().min(6)],
                    "unsupported htpasswd hash algorithm — skipping entry (supported: bcrypt, SHA1)"
                );
                return None;
            };

            Some(BasicCredential::new(username, password_hash))
        })
        .collect()
}

#[cfg(test)]
mod auth_tests {
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
    fn auth_url_const_referenced() {
        let _ = AUTH_URL;
    }

    #[test]
    fn auth_timeout_const_referenced() {
        let _ = AUTH_TIMEOUT;
    }

    #[test]
    fn auth_response_headers_const_referenced() {
        let _ = AUTH_RESPONSE_HEADERS;
    }

    #[test]
    fn auth_always_set_cookie_const_referenced() {
        let _ = AUTH_ALWAYS_SET_COOKIE;
    }

    #[test]
    fn auth_basic_secret_const_referenced() {
        let _ = AUTH_BASIC_SECRET;
    }

    // ── parse_auth: ext_authz ─────────────────────────────────────────────────

    #[test]
    fn parse_auth_absent_is_none() {
        let m = ann(&[]);
        assert!(parse_auth(&m, "ns/test", &mut vec![]).is_none());
    }

    #[test]
    fn parse_auth_url_produces_external() {
        let m = ann(&[(AUTH_URL, "http://authsvc/check")]);
        match parse_auth(&m, "ns/test", &mut vec![]) {
            Some(AuthAnnotation::External { url, timeout, .. }) => {
                assert_eq!(url, "http://authsvc/check");
                assert_eq!(timeout, std::time::Duration::from_secs(2));
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    fn parse_auth_timeout_custom() {
        let m = ann(&[(AUTH_URL, "http://svc/"), (AUTH_TIMEOUT, "500ms")]);
        match parse_auth(&m, "ns/test", &mut vec![]) {
            Some(AuthAnnotation::External { timeout, .. }) => {
                assert_eq!(timeout, std::time::Duration::from_millis(500));
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_auth_invalid_timeout_warns_and_defaults_2s() {
        let m = ann(&[(AUTH_URL, "http://svc/"), (AUTH_TIMEOUT, "bad")]);
        match parse_auth(&m, "ns/test", &mut vec![]) {
            Some(AuthAnnotation::External { timeout, .. }) => {
                assert_eq!(timeout, std::time::Duration::from_secs(2));
                assert!(logs_contain("invalid auth-timeout"));
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    fn parse_auth_response_headers_list() {
        let m = ann(&[
            (AUTH_URL, "http://svc/"),
            (AUTH_RESPONSE_HEADERS, "X-User, X-Role ,x-tenant"),
        ]);
        match parse_auth(&m, "ns/test", &mut vec![]) {
            Some(AuthAnnotation::External {
                response_headers, ..
            }) => {
                assert_eq!(response_headers, vec!["x-user", "x-role", "x-tenant"]);
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    fn parse_auth_always_set_cookie_true() {
        let m = ann(&[(AUTH_URL, "http://svc/"), (AUTH_ALWAYS_SET_COOKIE, "true")]);
        match parse_auth(&m, "ns/test", &mut vec![]) {
            Some(AuthAnnotation::External {
                always_set_cookie, ..
            }) => assert!(always_set_cookie),
            _ => panic!("expected External"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_auth_invalid_always_set_cookie_warns_and_defaults_false() {
        let m = ann(&[(AUTH_URL, "http://svc/"), (AUTH_ALWAYS_SET_COOKIE, "yes")]);
        match parse_auth(&m, "ns/test", &mut vec![]) {
            Some(AuthAnnotation::External {
                always_set_cookie, ..
            }) => {
                assert!(!always_set_cookie);
                assert!(logs_contain("invalid auth-always-set-cookie"));
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_auth_both_url_and_basic_prefers_url_and_warns() {
        let m = ann(&[
            (AUTH_URL, "http://svc/"),
            (AUTH_BASIC_SECRET, "default/my-htpasswd"),
        ]);
        match parse_auth(&m, "ns/test", &mut vec![]) {
            Some(AuthAnnotation::External { .. }) => {
                assert!(logs_contain("mutually exclusive"));
            }
            _ => panic!("expected External when both present"),
        }
    }

    // ── parse_auth: basic auth ────────────────────────────────────────────────

    #[test]
    fn parse_auth_basic_valid_ref() {
        let m = ann(&[(AUTH_BASIC_SECRET, "default/my-htpasswd")]);
        match parse_auth(&m, "ns/test", &mut vec![]) {
            Some(AuthAnnotation::Basic(ref_)) => {
                assert_eq!(ref_.namespace, "default");
                assert_eq!(ref_.name, "my-htpasswd");
            }
            _ => panic!("expected Basic"),
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_auth_basic_invalid_ref_warns_and_is_none() {
        let m = ann(&[(AUTH_BASIC_SECRET, "just-a-name-no-slash")]);
        assert!(parse_auth(&m, "ns/test", &mut vec![]).is_none());
        assert!(logs_contain("invalid auth-basic-secret"));
    }

    // ── parse_htpasswd ────────────────────────────────────────────────────────

    #[test]
    fn parse_htpasswd_bcrypt_entry() {
        let data = b"alice:$2y$12$abcdefghijklmnopqrstuuVGKkqzuSFPb0h.d.XRjRijkFvxONxfy\n";
        let creds = parse_htpasswd(data, "ns/test", &mut vec![]);
        assert_eq!(creds.len(), 1);
    }

    #[test]
    fn parse_htpasswd_sha1_entry() {
        // {SHA} + base64-encoded SHA1 of "password"; accepted but emits a diag.
        let data = b"bob:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n";
        let creds = parse_htpasswd(data, "ns/test", &mut vec![]);
        assert_eq!(creds.len(), 1);
    }

    #[test]
    fn parse_htpasswd_skips_comments_and_blank_lines() {
        let data = b"# comment\nalice:$2y$12$abc\n\n# another\n";
        let creds = parse_htpasswd(data, "ns/test", &mut vec![]);
        assert_eq!(creds.len(), 1);
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_htpasswd_unsupported_algorithm_warns_and_skips() {
        let data = b"alice:$apr1$salt$hash\n";
        let creds = parse_htpasswd(data, "ns/test", &mut vec![]);
        assert!(creds.is_empty());
        assert!(logs_contain("unsupported htpasswd hash algorithm"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_htpasswd_malformed_line_warns_and_skips() {
        let data = b"no-colon-here\n";
        let creds = parse_htpasswd(data, "ns/test", &mut vec![]);
        assert!(creds.is_empty());
        assert!(logs_contain("no ':' separator"));
    }

    #[test]
    fn parse_htpasswd_empty_input_is_empty() {
        assert!(parse_htpasswd(b"", "ns/test", &mut vec![]).is_empty());
        assert!(parse_htpasswd(b"# only comments\n", "ns/test", &mut vec![]).is_empty());
    }

    #[test]
    #[tracing_test::traced_test]
    fn parse_htpasswd_sha1_entry_warns() {
        let data = b"bob:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\nalice:$2y$12$abcdefghijklmnopqrstuuVGKkqzuSFPb0h.d.XRjRijkFvxONxfy\n";
        let mut diag = vec![];
        let creds = parse_htpasswd(data, "ns/test", &mut diag);
        assert_eq!(creds.len(), 2);
        assert_eq!(diag.len(), 1);
        assert_eq!(diag[0].annotation, AUTH_BASIC_SECRET);
        assert!(diag[0].message.contains("bob"));
        assert!(diag[0].message.contains("SHA1"));
        assert!(logs_contain("SHA1 which is not suitable"));
    }

    #[test]
    fn parse_htpasswd_bcrypt_only_no_diag() {
        let data = b"alice:$2y$12$abcdefghijklmnopqrstuuVGKkqzuSFPb0h.d.XRjRijkFvxONxfy\n";
        let mut diag = vec![];
        let creds = parse_htpasswd(data, "ns/test", &mut diag);
        assert_eq!(creds.len(), 1);
        assert!(diag.is_empty());
    }
}
