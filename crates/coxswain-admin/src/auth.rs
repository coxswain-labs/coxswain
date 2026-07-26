//! Optional HTTP Basic authentication for the admin surface (#670).
//!
//! The admin API has no authentication of its own, and on the controller role it
//! serves verbatim Kubernetes manifests (including Pod `spec.containers[].env`)
//! and coxswain pod logs. The `NetworkPolicy` fence is the primary control; this
//! is the second factor for operators who want one — notably anyone who has to
//! open the port beyond the install namespace.
//!
//! ## Where the credential comes from
//!
//! An operator-managed `Secret`, named by `--admin-basic-auth-secret`, holding
//! one htpasswd line under key `auth`:
//!
//! ```text
//! htpasswd -nbB admin 's3cret'   # -> admin:$2y$05$...
//! ```
//!
//! The controller reads it with the `kube::Client` and cluster-wide `secrets`
//! read it already holds — no new RBAC — and re-reads on a poll so rotating the
//! Secret takes effect without restarting the pod. Only the bcrypt hash is ever
//! held in memory; the plaintext never reaches the controller's config, flags,
//! or environment.
//!
//! ## Why only bcrypt, and only one credential
//!
//! The per-route `BasicAuth` CRD accepts a full multi-user htpasswd file and
//! tolerates Apache SHA1 for compatibility with pre-existing tenant files. This
//! is a different problem: nobody has a legacy admin-port credential to migrate,
//! and an unsalted SHA1 guarding cluster-wide manifest reads would be worse than
//! the fence alone. So the parser accepts exactly one bcrypt entry and rejects
//! everything else at load time, when the operator can still see the error —
//! rather than at request time, when a rejected line would silently read as an
//! empty credential set.

use std::sync::Arc;

use base64::Engine as _;
use coxswain_core::routing::{BasicCredential, PasswordHash};
use http::{Response, StatusCode, header};
use zeroize::Zeroizing;

/// Why an admin Basic-auth credential could not be loaded.
///
/// Each variant names a concrete operator mistake, because this is surfaced in a
/// startup/poll log line that has to be actionable without reading source.
#[derive(Debug, thiserror::Error)]
pub enum AdminAuthError {
    /// The Secret has no `auth` key.
    #[error("Secret has no '{AUTH_SECRET_KEY}' key (expected one htpasswd line)")]
    MissingKey,
    /// The `auth` value is not UTF-8.
    #[error("the '{AUTH_SECRET_KEY}' value is not valid UTF-8")]
    NotUtf8,
    /// No `user:hash` line was found.
    #[error("no credential found (expected one '<user>:<bcrypt-hash>' line)")]
    Empty,
    /// More than one credential line was present.
    #[error(
        "found {0} credential lines; the admin surface takes exactly one \
         (use a per-route BasicAuth policy for multi-user auth)"
    )]
    NotSingular(usize),
    /// A line was not `user:hash`, or either half was blank.
    #[error("malformed credential line (expected '<user>:<bcrypt-hash>')")]
    Malformed,
    /// The hash is not bcrypt.
    #[error(
        "credential for user '{0}' is not a bcrypt hash; regenerate it with \
         `htpasswd -nbB <user> <password>`"
    )]
    NotBcrypt(String),
}

/// The `Secret` data key holding the htpasswd line.
pub const AUTH_SECRET_KEY: &str = "auth";

/// Parse the single bcrypt credential out of an htpasswd `Secret` value.
///
/// Blank lines and `#` comments are skipped, matching htpasswd conventions;
/// anything else must be exactly one `user:$2[aby]$...` line.
///
/// # Errors
///
/// Returns the [`AdminAuthError`] naming the specific defect — no key, not
/// UTF-8, no line, several lines, a malformed line, or a non-bcrypt hash. The
/// caller fails the admin surface closed rather than serving it unauthenticated.
pub fn parse_admin_credential(data: &[u8]) -> Result<BasicCredential, AdminAuthError> {
    let text = std::str::from_utf8(data).map_err(|_| AdminAuthError::NotUtf8)?;

    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let line = match lines.as_slice() {
        [] => return Err(AdminAuthError::Empty),
        [single] => *single,
        many => return Err(AdminAuthError::NotSingular(many.len())),
    };

    let (username, hash) = line.split_once(':').ok_or(AdminAuthError::Malformed)?;
    let (username, hash) = (username.trim(), hash.trim());
    if username.is_empty() || hash.is_empty() {
        return Err(AdminAuthError::Malformed);
    }

    // `$2a$` / `$2b$` / `$2y$` are the bcrypt variants htpasswd -B emits; the
    // per-route auth path accepts the same set.
    if !(hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")) {
        return Err(AdminAuthError::NotBcrypt(username.to_string()));
    }

    Ok(BasicCredential::new(
        username,
        PasswordHash::Bcrypt(hash.into()),
    ))
}

/// The credential the admin surface currently enforces.
///
/// `None` means the credential could not be loaded — a missing, malformed, or
/// not-yet-created Secret. That is deliberately **not** the same as "auth
/// disabled": auth is disabled by not configuring a Secret name at all, which
/// leaves the whole [`AdminAuth`] absent. Once configured, an unreadable Secret
/// fails closed, so a typo in the Secret name can never silently reopen the
/// surface.
pub type AdminCredentialCell = coxswain_core::Shared<Option<Arc<BasicCredential>>>;

/// Basic-auth enforcement state for [`crate::AdminServer`].
#[derive(Clone)]
pub struct AdminAuth {
    /// The active credential, swapped in place by the controller's Secret poll.
    credential: AdminCredentialCell,
    /// `WWW-Authenticate` realm returned with a 401.
    realm: Arc<str>,
}

impl AdminAuth {
    /// Enforce `realm` against the credential published in `credential`.
    #[must_use]
    pub fn new(credential: AdminCredentialCell, realm: impl Into<Arc<str>>) -> Self {
        Self {
            credential,
            realm: realm.into(),
        }
    }
}

/// What [`AdminAuth::check`] decided about a request.
pub(crate) enum AuthOutcome {
    /// Credentials verified; serve the request.
    Allow,
    /// Absent or wrong credentials — return 401 with a challenge.
    Challenge,
    /// No credential is loaded; the surface is closed (503).
    Unavailable,
}

impl AdminAuth {
    /// Verify the request's `Authorization: Basic` header.
    ///
    /// bcrypt verification is deliberate, expensive work, so it runs on
    /// `spawn_blocking` rather than the async executor — the same rule the
    /// per-route Basic auth path follows. Unlike that path this needs no
    /// timing-equalisation dummy hash: there is exactly one credential and the
    /// verify runs on every request that carries a parseable header, so a
    /// username miss and a password miss cost the same by construction.
    pub(crate) async fn check(&self, header_value: Option<&str>) -> AuthOutcome {
        let Some(credential) = self.credential.load().as_ref().clone() else {
            return AuthOutcome::Unavailable;
        };

        let Some(encoded) = header_value.and_then(|v| v.strip_prefix("Basic ")) else {
            return AuthOutcome::Challenge;
        };

        // Hold the decoded `user:pass` in a Zeroizing buffer so the plaintext is
        // scrubbed when this scope ends, on every path.
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return AuthOutcome::Challenge;
        };
        let decoded = Zeroizing::new(decoded);

        let Some(colon) = decoded.iter().position(|&b| b == b':') else {
            return AuthOutcome::Challenge;
        };
        let Ok(username) = std::str::from_utf8(&decoded[..colon]) else {
            return AuthOutcome::Challenge;
        };
        let username_matches = username == credential.username.as_ref();
        let password: Zeroizing<Vec<u8>> = Zeroizing::new(decoded[colon + 1..].to_vec());

        let PasswordHash::Bcrypt(hash) = &credential.hash else {
            // Unreachable via `parse_admin_credential`, which rejects every
            // non-bcrypt hash at load. Degrade to a challenge rather than
            // panicking on a request path.
            return AuthOutcome::Challenge;
        };
        let hash = hash.clone();

        let verified = tokio::task::spawn_blocking(move || {
            let candidate = std::str::from_utf8(&password).unwrap_or("");
            bcrypt::verify(candidate, &hash).unwrap_or(false)
        })
        .await
        .unwrap_or(false);

        if username_matches && verified {
            AuthOutcome::Allow
        } else {
            AuthOutcome::Challenge
        }
    }

    /// The `401` challenge response.
    pub(crate) fn challenge(&self) -> Response<Vec<u8>> {
        let mut r = Response::new(Vec::new());
        *r.status_mut() = StatusCode::UNAUTHORIZED;
        if let Ok(v) = http::HeaderValue::from_str(&format!(r#"Basic realm="{}""#, self.realm)) {
            r.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
        r
    }

    /// The `503` returned while no credential is loaded.
    pub(crate) fn unavailable() -> Response<Vec<u8>> {
        let mut r = Response::new(Vec::new());
        *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        r
    }
}

/// How often the credential Secret is re-read.
///
/// Matches the trust-bundle publisher's CA-rotation poll: rotating an admin
/// credential is a rare, operator-initiated act, and a Secret watch would cost a
/// cluster-wide `secrets` watch to observe one object.
const CREDENTIAL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Pingora background service that keeps the admin credential in sync with its
/// `Secret`.
///
/// The cell it publishes into starts empty, and empty means **closed** (503), so
/// the admin surface is never briefly unauthenticated during the window between
/// the listener binding and the first successful read. Each later poll refreshes
/// the credential, clears it when the apiserver definitively reports the Secret
/// gone or unreadable (so deleting it closes the surface rather than reopening
/// it), and retains the last-good value across transport failures.
pub struct AdminCredentialWatcher {
    /// Cell shared with the [`AdminAuth`] the admin server enforces.
    cell: AdminCredentialCell,
    /// Secret name, in [`Self::namespace`].
    secret_name: String,
    /// Namespace holding the Secret — the install namespace.
    namespace: String,
}

impl AdminCredentialWatcher {
    /// Build a watcher for `secret_name` in `namespace`.
    #[must_use]
    pub fn new(secret_name: String, namespace: String) -> Self {
        Self {
            cell: coxswain_core::Shared::from_value(None),
            secret_name,
            namespace,
        }
    }

    /// The cell to hand [`AdminAuth::new`]. Cheap to clone; the watcher keeps
    /// its own handle to the same underlying value.
    #[must_use]
    pub fn credential(&self) -> AdminCredentialCell {
        self.cell.clone()
    }
}

#[async_trait::async_trait]
impl pingora_core::services::background::BackgroundService for AdminCredentialWatcher {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        // Built here rather than passed in: `run_controller` is synchronous, and
        // `Client::try_default` needs a runtime.
        let mut client = None;
        loop {
            // Retried on the poll cadence rather than returning: giving up would
            // wedge the admin surface closed for the pod's whole life, and the
            // pod would stay Ready (health is a separate listener), so nothing
            // would restart it.
            if client.is_none() {
                match kube::Client::try_default().await {
                    Ok(c) => client = Some(c),
                    Err(e) => tracing::error!(
                        error = %e,
                        "admin auth: no Kubernetes client yet; \
                         admin surface stays closed, retrying"
                    ),
                }
            }
            if let Some(client) = client.as_ref() {
                refresh_credential(client, &self.secret_name, &self.namespace, &self.cell).await;
            }
            tokio::select! {
                _ = shutdown.changed() => return,
                () = tokio::time::sleep(CREDENTIAL_POLL_INTERVAL) => {}
            }
        }
    }
}

/// Whether `e` is the apiserver definitively saying the Secret is unavailable —
/// as opposed to the controller failing to ask.
///
/// `404` (deleted), `403` (RBAC revoked), and `401` are answers; a timeout, a
/// connection reset, a `503`, or a `429` are not, and must not be allowed to
/// revoke a credential that is still perfectly valid.
fn is_definitive_secret_failure(e: &kube::Error) -> bool {
    matches!(e, kube::Error::Api(api) if matches!(api.code, 401 | 403 | 404))
}

/// Read the Secret once and publish (or clear) the credential.
async fn refresh_credential(
    client: &kube::Client,
    secret_name: &str,
    namespace: &str,
    cell: &AdminCredentialCell,
) {
    let api: kube::Api<k8s_openapi::api::core::v1::Secret> =
        kube::Api::namespaced(client.clone(), namespace);

    let loaded = match api.get(secret_name).await {
        Ok(secret) => secret
            .data
            .as_ref()
            .and_then(|d| d.get(AUTH_SECRET_KEY))
            .ok_or(AdminAuthError::MissingKey)
            .and_then(|bytes| parse_admin_credential(&bytes.0)),
        // An apiserver the controller merely could not *reach* says nothing
        // about the credential. Clearing on a transport blip would 503 the admin
        // surface — for correctly-authenticated callers — until the next poll,
        // so the last-good credential is retained instead. Only a definitive
        // answer (gone, forbidden, unauthorized) clears it.
        Err(e) if !is_definitive_secret_failure(&e) => {
            tracing::warn!(
                error = %e,
                secret = %secret_name,
                namespace = %namespace,
                "admin auth: could not reach the apiserver; retaining the current credential"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                secret = %secret_name,
                namespace = %namespace,
                "admin auth: the credential Secret is gone or unreadable; admin surface stays closed"
            );
            cell.store(Arc::new(None));
            return;
        }
    };

    match loaded {
        Ok(credential) => {
            let changed = cell
                .load()
                .as_deref()
                .is_none_or(|current| current.username != credential.username);
            cell.store(Arc::new(Some(Arc::new(credential))));
            if changed {
                tracing::info!(
                    secret = %secret_name,
                    "admin auth: credential loaded; the admin surface now requires Basic auth"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                secret = %secret_name,
                namespace = %namespace,
                "admin auth: credential Secret is unusable; admin surface stays closed"
            );
            cell.store(Arc::new(None));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// bcrypt hash of "s3cret" at the minimum cost, so the tests stay fast.
    /// Generated once by `bcrypt::hash("s3cret", 4)`.
    fn hash_of(password: &str) -> String {
        bcrypt::hash(password, 4).expect("hash test password")
    }

    fn secret_line(user: &str, password: &str) -> String {
        format!("{user}:{}\n", hash_of(password))
    }

    #[test]
    fn parses_a_single_bcrypt_line() {
        let cred = parse_admin_credential(secret_line("admin", "s3cret").as_bytes())
            .expect("a single bcrypt line is the supported shape");
        assert_eq!(cred.username.as_ref(), "admin");
        assert!(matches!(cred.hash, PasswordHash::Bcrypt(_)));
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        let data = format!(
            "# generated by htpasswd\n\n{}\n",
            secret_line("ops", "pw").trim()
        );
        let cred = parse_admin_credential(data.as_bytes()).expect("comments are not credentials");
        assert_eq!(cred.username.as_ref(), "ops");
    }

    #[test]
    fn rejects_an_sha1_hash() {
        // Accepted by the per-route BasicAuth path for legacy tenant files, but
        // never here: unsalted SHA1 guarding cluster-wide manifest reads is
        // worse than no second factor at all.
        let err = parse_admin_credential(b"admin:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n")
            .expect_err("SHA1 must be refused");
        assert!(matches!(err, AdminAuthError::NotBcrypt(u) if u == "admin"));
    }

    #[test]
    fn rejects_a_plaintext_password() {
        let err = parse_admin_credential(b"admin:s3cret\n").expect_err("plaintext must be refused");
        assert!(matches!(err, AdminAuthError::NotBcrypt(_)));
    }

    #[test]
    fn rejects_multiple_credentials() {
        // Two entries would make "which one authenticated?" unanswerable in the
        // audit log, and this surface has no per-user authorization to justify it.
        let data = format!("{}{}", secret_line("a", "pw"), secret_line("b", "pw"));
        let err = parse_admin_credential(data.as_bytes()).expect_err("only one entry is supported");
        assert!(matches!(err, AdminAuthError::NotSingular(2)));
    }

    #[test]
    fn rejects_an_empty_or_comment_only_secret() {
        assert!(matches!(
            parse_admin_credential(b"").expect_err("empty"),
            AdminAuthError::Empty
        ));
        assert!(matches!(
            parse_admin_credential(b"# nothing here\n").expect_err("comments only"),
            AdminAuthError::Empty
        ));
    }

    #[test]
    fn rejects_a_malformed_line() {
        assert!(matches!(
            parse_admin_credential(b"no-colon-here\n").expect_err("no separator"),
            AdminAuthError::Malformed
        ));
        assert!(matches!(
            parse_admin_credential(b":$2y$05$abc\n").expect_err("blank user"),
            AdminAuthError::Malformed
        ));
        assert!(matches!(
            parse_admin_credential(b"admin:\n").expect_err("blank hash"),
            AdminAuthError::Malformed
        ));
    }

    #[test]
    fn rejects_non_utf8() {
        assert!(matches!(
            parse_admin_credential(&[0xff, 0xfe]).expect_err("not utf8"),
            AdminAuthError::NotUtf8
        ));
    }

    fn auth_with(credential: Option<BasicCredential>) -> AdminAuth {
        AdminAuth::new(
            coxswain_core::Shared::from_value(credential.map(Arc::new)),
            "coxswain admin",
        )
    }

    fn basic(user: &str, password: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    }

    #[tokio::test]
    async fn allows_the_configured_credential() {
        let auth = auth_with(Some(
            parse_admin_credential(secret_line("admin", "s3cret").as_bytes()).expect("parse"),
        ));
        assert!(matches!(
            auth.check(Some(&basic("admin", "s3cret"))).await,
            AuthOutcome::Allow
        ));
    }

    #[tokio::test]
    async fn challenges_a_wrong_password() {
        let auth = auth_with(Some(
            parse_admin_credential(secret_line("admin", "s3cret").as_bytes()).expect("parse"),
        ));
        assert!(matches!(
            auth.check(Some(&basic("admin", "wrong"))).await,
            AuthOutcome::Challenge
        ));
    }

    #[tokio::test]
    async fn challenges_a_wrong_username_with_the_right_password() {
        // The username is compared as well as the hash — a correct password
        // under a different name must not authenticate.
        let auth = auth_with(Some(
            parse_admin_credential(secret_line("admin", "s3cret").as_bytes()).expect("parse"),
        ));
        assert!(matches!(
            auth.check(Some(&basic("someone-else", "s3cret"))).await,
            AuthOutcome::Challenge
        ));
    }

    #[tokio::test]
    async fn challenges_a_missing_or_unparseable_header() {
        let auth = auth_with(Some(
            parse_admin_credential(secret_line("admin", "s3cret").as_bytes()).expect("parse"),
        ));
        for header in [None, Some("Bearer token"), Some("Basic !!!not-base64")] {
            assert!(
                matches!(auth.check(header).await, AuthOutcome::Challenge),
                "header {header:?} must not authenticate"
            );
        }
        // Well-formed base64 with no colon is not a credential either.
        let no_colon = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("no-colon")
        );
        assert!(matches!(
            auth.check(Some(&no_colon)).await,
            AuthOutcome::Challenge
        ));
    }

    #[tokio::test]
    async fn fails_closed_when_no_credential_is_loaded() {
        // A configured-but-unreadable Secret must close the surface, not reopen
        // it: otherwise a typo in the Secret name silently disables auth.
        let auth = auth_with(None);
        assert!(matches!(
            auth.check(Some(&basic("admin", "s3cret"))).await,
            AuthOutcome::Unavailable
        ));
    }

    #[test]
    fn challenge_carries_a_www_authenticate_header() {
        let auth = auth_with(None);
        let resp = auth.challenge();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some(r#"Basic realm="coxswain admin""#)
        );
    }
}
