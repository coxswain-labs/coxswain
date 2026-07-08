//! Request-authentication annotation parsing (`auth-*`, #24, #441, #549):
//! external (`CoxswainExternalAuth` CR reference), basic (htpasswd Secret),
//! and JWT (`JwtAuth` CR reference) auth — all three independently additive,
//! plus the shared `namespace/name` / htpasswd parse helpers. `SecretRef` and
//! `parse_secret_ref` are reused by the sibling client-cert mTLS module
//! ([`super::client_cert`]).

use super::AnnotationIssue;

// ── External-auth annotation (#549) ───────────────────────────────────────────

/// Reference to a `CoxswainExternalAuth` CR in `namespace/name` form, e.g.
/// `"default/my-extauth"` (#549). Independent of (additive with)
/// `auth-basic-secret` / `auth-jwt` — a route can require external auth
/// alongside basic and/or JWT auth; every check in the chain must pass.
/// Resolves to the same
/// [`IngressAuthConfig::External`][coxswain_core::routing::IngressAuthConfig::External]
/// the HTTPRoute `ExtensionRef` filter produces (Gateway API parity).
/// Replaces the former inline `ext-auth-backend` / `ext-auth-protocol` /
/// `ext-auth-timeout` / `ext-auth-response-headers` /
/// `ext-auth-always-set-cookie` / `ext-auth-fail-closed` annotation cluster,
/// whose knobs now live on the `CoxswainExternalAuth` CRD spec. A missing CR
/// fails **closed** (503) — matching `auth-basic-secret`/`auth-jwt`.
pub const EXT_AUTH: &str = "ingress.coxswain-labs.dev/ext-auth";

/// Reference to an htpasswd [`Secret`] in `namespace/name` form, e.g.
/// `"default/my-htpasswd"`.  The Secret **must** carry the label
/// `ingress.coxswain-labs.dev/auth-basic: "true"` and store the htpasswd file
/// under the key `auth`.  A missing Secret, an unlabeled Secret, or one without
/// a parseable `auth` key causes the proxy to respond with 503 (fail-closed)
/// and emit a loud `WARN` naming the issue.
///
/// Independent of (additive with) `ext-auth` / `auth-jwt` — every configured
/// check must pass.
pub const AUTH_BASIC_SECRET: &str = "ingress.coxswain-labs.dev/auth-basic-secret";

/// Reference to a `JwtAuth` CR in `namespace/name` form, e.g. `"default/my-jwt"`
/// (#441). Independent of (additive with) `ext-auth` / `auth-basic-secret`
/// — a route can require JWT auth alongside external or basic auth; every check
/// in the chain must pass. Resolves to the same
/// [`IngressAuthConfig::Jwt`][coxswain_core::routing::IngressAuthConfig::Jwt]
/// the HTTPRoute `ExtensionRef` filter produces (Gateway API parity). A missing
/// CR fails open (WARN, no JWT check); a present-but-unresolved JWKS fails
/// closed (503).
pub const AUTH_JWT: &str = "ingress.coxswain-labs.dev/auth-jwt";

// ── Intermediate annotation representation (pre-reconcile) ──────────────────

/// A reference to a Kubernetes object in `namespace/name` form. Reused for any
/// coordinate of that shape: [`AUTH_BASIC_SECRET`] parses to this to reference
/// a `Secret`, [`AUTH_JWT`] a `JwtAuth` CR, and [`EXT_AUTH`] a
/// `CoxswainExternalAuth` CR.
pub(crate) struct SecretRef {
    pub namespace: String,
    pub name: String,
}

// ── Parse helpers ────────────────────────────────────────────────────────────

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

    // ── Annotation const references (satisfies check-annotation-coverage.sh) ─

    #[test]
    fn ext_auth_const_referenced() {
        let _ = EXT_AUTH;
    }

    #[test]
    fn auth_basic_secret_const_referenced() {
        let _ = AUTH_BASIC_SECRET;
    }

    // ── parse_secret_ref ──────────────────────────────────────────────────────

    #[test]
    fn parse_secret_ref_valid() {
        let r = parse_secret_ref("default/my-extauth").expect("valid");
        assert_eq!(r.namespace, "default");
        assert_eq!(r.name, "my-extauth");
    }

    #[test]
    fn parse_secret_ref_rejects_malformed() {
        assert!(parse_secret_ref("no-slash").is_none());
        assert!(parse_secret_ref("/name").is_none()); // empty namespace
        assert!(parse_secret_ref("ns/").is_none()); // empty name
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
