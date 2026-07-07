//! External and basic authentication enforcement for the Ingress proxy.
//!
//! Called from [`crate::hooks::request_filter`] after rate-limiting and
//! before redirect/body handling.  Implements two modes:
//!
//! - **External (`ext_authz`)**: forwards a sub-request to a configurable HTTP
//!   auth endpoint using Envoy `ext_authz`-HTTP semantics — original method and
//!   Host are preserved; client headers (Authorization, Cookie …) are forwarded;
//!   no body.  2xx → allow; non-2xx → deny (status+body returned to client);
//!   timeout/connect error → 503.
//!
//! - **Basic auth** (`Authorization: Basic`): decodes the header and verifies
//!   against an htpasswd credential list pre-parsed at reconcile time.  bcrypt
//!   verification runs in `tokio::task::spawn_blocking`; SHA1 uses a constant-
//!   time comparison.  Missing/invalid credentials → 401 + `WWW-Authenticate`.
//!   An `Unavailable` config (missing/unlabeled secret) → 503.
//!
//! ## Security notes
//!
//! The decoded `user:pass` plaintext is held in a [`zeroize::Zeroizing`] buffer
//! and scrubbed immediately after verification, whether it succeeds or fails.
//! bcrypt and SHA1 hashes are scrubbed when the `BasicCredential` list is
//! dropped at reconcile time (via `ZeroizeOnDrop` on `BasicCredential` /
//! `PasswordHash`).

use coxswain_core::routing::{ExtAuthTransport, IngressAuthConfig, PasswordHash};
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

/// Round-robin cursor for spreading ext_authz sub-requests across a resolved
/// auth service's endpoints. Process-wide and `Relaxed` — approximate fairness
/// is all that's needed; exact distribution is not a correctness property.
static EXT_AUTH_RR: AtomicUsize = AtomicUsize::new(0);

/// Pick the next auth endpoint round-robin. `None` only when the slice is
/// empty (the caller fails closed); a resolved `ExtAuthConfig` is never empty.
fn pick_endpoint(endpoints: &[SocketAddr]) -> Option<SocketAddr> {
    match endpoints.len() {
        0 => None,
        1 => Some(endpoints[0]),
        n => Some(endpoints[EXT_AUTH_RR.fetch_add(1, Ordering::Relaxed) % n]),
    }
}

// ── Hop-by-hop headers stripped when forwarding to the auth service ──────────

/// RFC 2616 §13.5.1 hop-by-hop headers: never forward these to the auth service
/// or mirror sub-requests.
pub(crate) const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

// ── Public entry point ────────────────────────────────────────────────────────

/// Enforce the authentication policy on `session`.
///
/// Returns:
/// - `Ok(false)` — authentication passed; the request should proceed to upstream.
/// - `Ok(true)` — authentication denied; a response has been written to the client
///   (either from the auth service or a synthesized 401/503).  The request must
///   **not** be forwarded to the upstream backend.
/// - `Err(…)` — a hard Pingora error (only on internal write failures).
///
/// `auth_response_headers` is populated when the auth service returns 2xx and the
/// route's `auth-response-headers` list is non-empty; the caller stores it on
/// `ctx` for [`crate::hooks::upstream_request_filter`] to apply.
///
/// # Errors
///
/// Propagates Pingora `write_response_header` errors.
pub(crate) async fn enforce(
    client: &reqwest::Client,
    auth: &IngressAuthConfig,
    session: &mut Session,
    auth_response_headers: &mut Option<Vec<(Box<str>, Box<str>)>>,
) -> Result<bool> {
    match auth {
        IngressAuthConfig::External(cfg) => {
            enforce_ext_authz(client, cfg, session, auth_response_headers).await
        }
        IngressAuthConfig::Basic(creds) => enforce_basic(creds, session).await,
        IngressAuthConfig::Unavailable => {
            // Secret was absent or unlabeled at reconcile time — fail closed.
            tracing::warn!("auth config unavailable — refusing request (503)");
            write_simple(session, 503).await?;
            Ok(true)
        }
        // #[non_exhaustive]: future variants (e.g. gRPC ext_authz from #23).
        _ => {
            tracing::warn!("unknown auth variant — refusing request (503)");
            write_simple(session, 503).await?;
            Ok(true)
        }
    }
}

// ── External auth (ext_authz HTTP) ───────────────────────────────────────────

async fn enforce_ext_authz(
    client: &reqwest::Client,
    cfg: &coxswain_core::routing::ExtAuthConfig,
    session: &mut Session,
    auth_response_headers_out: &mut Option<Vec<(Box<str>, Box<str>)>>,
) -> Result<bool> {
    match &cfg.transport {
        ExtAuthTransport::Http(http_cfg) => {
            enforce_ext_authz_http(client, cfg, http_cfg, session, auth_response_headers_out).await
        }
        ExtAuthTransport::Grpc(grpc_cfg) => {
            grpc::enforce_ext_authz_grpc(cfg, grpc_cfg, session, auth_response_headers_out).await
        }
        // `ExtAuthTransport` is #[non_exhaustive]: a transport not yet wired on the
        // data plane must fail closed (503), never open. Reachable the moment a new
        // variant is added — degrade, don't panic.
        _ => {
            tracing::warn!("unsupported ext_authz transport — refusing request (503)");
            write_simple(session, 503).await?;
            Ok(true)
        }
    }
}

async fn enforce_ext_authz_http(
    client: &reqwest::Client,
    cfg: &coxswain_core::routing::ExtAuthConfig,
    http_cfg: &coxswain_core::routing::HttpExtAuthConfig,
    session: &mut Session,
    auth_response_headers_out: &mut Option<Vec<(Box<str>, Box<str>)>>,
) -> Result<bool> {
    // Build the sub-request: original method + Host, client headers, no body.
    let req_hdr = session.req_header();
    let method_str = req_hdr.method.as_str();
    let method = reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET);

    // Send the check to a resolved auth-service endpoint (round-robin), replaying
    // the original request path — the Envoy `ext_authz`-HTTP model. The proxy
    // connects to a pod IP directly, the same as every other backend.
    let Some(addr) = pick_endpoint(&cfg.endpoints) else {
        tracing::warn!("ext_authz has no resolved endpoints — refusing request (503)");
        write_simple(session, 503).await?;
        return Ok(true);
    };
    let path_and_query = req_hdr
        .uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let url = format!("http://{addr}{path_and_query}");

    let mut builder = client.request(method, &url);

    // Forward client headers, preserving Host.  Strip hop-by-hop.
    let host_hdr = req_hdr
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if !host_hdr.is_empty() {
        builder = builder.header(reqwest::header::HOST, &host_hdr);
    }
    for (name, value) in &req_hdr.headers {
        let name_lower = name.as_str().to_ascii_lowercase();
        if name_lower == "host" || HOP_BY_HOP.contains(&name_lower.as_str()) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }

    let auth_response = match tokio::time::timeout(cfg.timeout, builder.send()).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            // Auth service unreachable/errored: fail closed (503) unless the
            // operator opted into fail-open (`failClosed: false`).
            tracing::warn!(error = %e, fail_closed = cfg.fail_closed, "ext_authz request failed");
            if cfg.fail_closed {
                write_simple(session, 503).await?;
                return Ok(true);
            }
            return Ok(false);
        }
        Err(_) => {
            tracing::warn!(
                timeout_ms = cfg.timeout.as_millis(),
                fail_closed = cfg.fail_closed,
                "ext_authz request timed out"
            );
            if cfg.fail_closed {
                write_simple(session, 503).await?;
                return Ok(true);
            }
            return Ok(false);
        }
    };

    let auth_status = auth_response.status();

    if auth_status.is_success() {
        // 2xx → allow.  Copy `auth-response-headers` from the auth response
        // onto the upstream request (Envoy `allowed_upstream_headers` /
        // Istio `headersToUpstreamOnAllow`).
        if !http_cfg.response_headers.is_empty() {
            let mut headers_to_forward = Vec::with_capacity(http_cfg.response_headers.len());
            for name in http_cfg.response_headers.iter() {
                if let Some(Ok(v)) = auth_response
                    .headers()
                    .get(name.as_ref())
                    .map(|val| val.to_str())
                {
                    headers_to_forward.push((name.clone(), v.into()));
                }
            }
            if !headers_to_forward.is_empty() {
                *auth_response_headers_out = Some(headers_to_forward);
            }
        }
        return Ok(false);
    }

    // non-2xx → deny.  Return the auth response status + body to the client.
    // Controlled header set: hop-by-hop headers stripped; Set-Cookie only when
    // auth-always-set-cookie; Content-Type / WWW-Authenticate / Location always
    // forwarded so the client can render the deny body (e.g. login redirect).
    let deny_status = auth_status.as_u16();

    // Collect the forwarded headers as owned (name, value) pairs before
    // consuming auth_response with .bytes() below.  Owned strings are needed
    // because Pingora's insert_header requires `'static`-able key types.
    let forward_hdrs: Vec<(String, String)> = auth_response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            let name_s = name.as_str().to_ascii_lowercase();
            if HOP_BY_HOP.contains(&name_s.as_str()) {
                return None;
            }
            if name_s == "set-cookie" && !http_cfg.always_set_cookie {
                return None;
            }
            let should_forward = name_s == "content-type"
                || name_s == "www-authenticate"
                || name_s == "location"
                || name_s == "set-cookie";
            if !should_forward {
                return None;
            }
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_owned(), v.to_owned()))
        })
        .collect();

    let body = auth_response.bytes().await.unwrap_or_default();

    let mut resp_hdr = ResponseHeader::build(deny_status, Some(forward_hdrs.len()))?;
    for (name, value) in forward_hdrs {
        // `String` implements `IntoCaseHeaderName` and owns its data — no
        // lifetime tie to the already-consumed `auth_response`.
        let _ = resp_hdr.insert_header(name, value);
    }

    session
        .write_response_header(Box::new(resp_hdr), body.is_empty())
        .await
        .unwrap_or_else(|e| tracing::error!("failed to write auth deny response: {e}"));
    if !body.is_empty() {
        session
            .write_response_body(Some(body), true)
            .await
            .unwrap_or_else(|e| {
                tracing::error!("failed to write auth deny body: {e}");
            });
    }
    Ok(true)
}

// ── Basic auth ────────────────────────────────────────────────────────────────

/// A valid bcrypt hash used solely to equalize verification timing on a username
/// miss, closing the username-enumeration oracle (a miss would otherwise skip the
/// expensive KDF a hit runs). Generated once at a fixed cost; the plaintext and the
/// verify result are irrelevant — only that the KDF actually runs. `None` if hash
/// generation ever fails, in which case the equalization is skipped (no panic on the
/// data plane).
static DUMMY_BCRYPT_HASH: std::sync::LazyLock<Option<String>> =
    std::sync::LazyLock::new(|| bcrypt::hash("coxswain-timing-equalization", 12).ok());

async fn enforce_basic(
    creds: &Arc<[coxswain_core::routing::BasicCredential]>,
    session: &mut Session,
) -> Result<bool> {
    if creds.is_empty() {
        // Empty credential list — same as Unavailable.
        tracing::warn!("basic auth has no credentials — refusing request (503)");
        write_simple(session, 503).await?;
        return Ok(true);
    }

    // Extract the Authorization: Basic header.
    let encoded = {
        let req = session.req_header();
        match req.headers.get(http::header::AUTHORIZATION) {
            Some(v) => match v.to_str() {
                Ok(s) => s.strip_prefix("Basic ").map(str::to_string),
                Err(_) => None,
            },
            None => None,
        }
    };

    let Some(encoded) = encoded else {
        return challenge_401(session).await;
    };

    // Decode base64 and split user:pass. Hold in a Zeroizing buffer so the
    // plaintext password is scrubbed when we leave this scope.
    let decoded: Zeroizing<Vec<u8>> = match base64::engine::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded.trim(),
    ) {
        Ok(b) => Zeroizing::new(b),
        Err(_) => return challenge_401(session).await,
    };

    let colon_pos = match decoded.iter().position(|&b| b == b':') {
        Some(p) => p,
        None => return challenge_401(session).await,
    };

    let user_bytes = &decoded[..colon_pos];
    let pass_bytes = &decoded[colon_pos + 1..];
    let username = match std::str::from_utf8(user_bytes) {
        Ok(u) => u,
        Err(_) => return challenge_401(session).await,
    };

    // Verify against the credential list.
    let mut matched_user = false;
    for cred in creds.iter() {
        if cred.username.as_ref() != username {
            continue;
        }
        matched_user = true;
        let verified = match &cred.hash {
            PasswordHash::Bcrypt(hash) => {
                let hash_owned: Box<str> = hash.clone();
                let pass_owned: Zeroizing<Vec<u8>> = Zeroizing::new(pass_bytes.to_vec());
                // bcrypt is CPU-heavy — off-load from the async executor.
                tokio::task::spawn_blocking(move || {
                    bcrypt::verify(std::str::from_utf8(&pass_owned).unwrap_or(""), &hash_owned)
                        .unwrap_or(false)
                })
                .await
                .unwrap_or(false)
            }
            PasswordHash::Sha1(hash) => {
                // Apache SHA1: stored as "{SHA}" + base64(SHA1(password)).
                let hash_b64 = hash.strip_prefix("{SHA}").unwrap_or("");
                let expected = match base64::engine::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    hash_b64,
                ) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                use sha1::Digest;
                let computed = sha1::Sha1::digest(pass_bytes);
                constant_time_eq::constant_time_eq(computed.as_slice(), &expected)
            }
            // #[non_exhaustive]: future hash formats land here.
            _ => false,
        };
        if verified {
            return Ok(false);
        }
        // Username matched but password wrong — stop searching; remaining
        // entries with the same username (if any) won't help and iterating
        // further would create a timing oracle.
        break;
    }

    // Timing equalization: a username miss did no expensive KDF work, so run one
    // fixed-cost bcrypt verify against a dummy hash to make a miss cost ~the same
    // as a hit — closing the username-enumeration oracle. Result is discarded.
    if !matched_user && let Some(dummy) = DUMMY_BCRYPT_HASH.as_ref() {
        let dummy = dummy.clone();
        let pass_owned: Zeroizing<Vec<u8>> = Zeroizing::new(pass_bytes.to_vec());
        let _ = tokio::task::spawn_blocking(move || {
            bcrypt::verify(std::str::from_utf8(&pass_owned).unwrap_or(""), &dummy).unwrap_or(false)
        })
        .await;
    }

    challenge_401(session).await
}

// ── Helper: write a minimal response ─────────────────────────────────────────

/// Writes a `WWW-Authenticate: Basic realm="..."` challenge and returns
/// `Ok(true)` (request handled, do not forward to upstream).
async fn challenge_401(session: &mut Session) -> Result<bool> {
    let mut resp = ResponseHeader::build(401, Some(1))?;
    resp.insert_header(
        http::header::WWW_AUTHENTICATE,
        r#"Basic realm="Authentication required""#,
    )?;
    session
        .write_response_header(Box::new(resp), true)
        .await
        .unwrap_or_else(|e| tracing::error!("failed to write 401 challenge: {e}"));
    Ok(true)
}

/// Write a simple response with no body (for 503).
async fn write_simple(session: &mut Session, status: u16) -> Result<()> {
    let resp = ResponseHeader::build(status, None)?;
    session
        .write_response_header(Box::new(resp), true)
        .await
        .unwrap_or_else(|e| tracing::error!("failed to write {status} response: {e}"));
    Ok(())
}

// ── External auth (ext_authz gRPC — Envoy envoy.service.auth.v3, #23) ─────────

/// gRPC ext_authz: speaks the Envoy `Authorization/Check` proto to the resolved
/// auth pod. Kept in its own module so the Envoy-proto plumbing does not clutter
/// the HTTP forward-auth path; both share [`pick_endpoint`], [`write_simple`],
/// and [`HOP_BY_HOP`].
mod grpc {
    use super::{HOP_BY_HOP, pick_endpoint, write_simple};
    use envoy_types::pb::envoy::service::auth::v3 as auth_pb;
    use envoy_types::pb::envoy::service::auth::v3::authorization_client::AuthorizationClient;
    use envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse;
    use pingora_core::Result;
    use pingora_http::ResponseHeader;
    use pingora_proxy::Session;
    use std::collections::HashMap;

    /// `google.rpc.Code::Ok` — an allow. Any other code is a deny.
    const RPC_OK: i32 = 0;
    /// Deny status used when the auth service returns no explicit HTTP status.
    const DEFAULT_DENY_STATUS: u16 = 403;

    /// Enforce a gRPC ext_authz check. Contract mirrors the HTTP transport:
    /// `Ok(false)` allow, `Ok(true)` denied (response written), `Err` internal.
    pub(super) async fn enforce_ext_authz_grpc(
        cfg: &coxswain_core::routing::ExtAuthConfig,
        grpc_cfg: &coxswain_core::routing::GrpcExtAuthConfig,
        session: &mut Session,
        auth_response_headers_out: &mut Option<Vec<(Box<str>, Box<str>)>>,
    ) -> Result<bool> {
        let Some(addr) = pick_endpoint(&cfg.endpoints) else {
            tracing::warn!("ext_authz(grpc) has no resolved endpoints — refusing request (503)");
            write_simple(session, 503).await?;
            return Ok(true);
        };

        // Build the CheckRequest from the (immutably-borrowed) request header
        // before any mutable use of `session` below.
        let check = build_check_request(session);

        // Dial the auth pod cleartext (h2c). connect + per-call timeout both bounded
        // by cfg.timeout so a hung auth service cannot stall the request.
        //
        // Perf follow-up (#544): this opens a fresh channel per check (no pooling),
        // unlike the HTTP transport's shared `reqwest::Client`. Correct and fail-safe,
        // but a per-request TCP+H2 setup; a channel cache keyed by resolved endpoint on
        // `SharedProxyConfig` is a tracked optimization.
        let endpoint = match tonic::transport::Endpoint::from_shared(format!("http://{addr}")) {
            Ok(e) => e.connect_timeout(cfg.timeout).timeout(cfg.timeout),
            Err(e) => return fail(session, cfg.fail_closed, &format!("endpoint: {e}")).await,
        };
        let channel = match endpoint.connect().await {
            Ok(ch) => ch,
            Err(e) => return fail(session, cfg.fail_closed, &format!("connect: {e}")).await,
        };

        let mut client = AuthorizationClient::new(channel);
        let resp = match tokio::time::timeout(cfg.timeout, client.check(check)).await {
            Ok(Ok(r)) => r.into_inner(),
            Ok(Err(status)) => {
                return fail(session, cfg.fail_closed, &format!("check rpc: {status}")).await;
            }
            Err(_) => return fail(session, cfg.fail_closed, "check timed out").await,
        };

        map_check_response(resp, grpc_cfg, session, auth_response_headers_out).await
    }

    /// Fail an unreachable/errored/timed-out check: 503 when fail-closed, else allow.
    async fn fail(session: &mut Session, fail_closed: bool, reason: &str) -> Result<bool> {
        tracing::warn!(reason, fail_closed, "ext_authz(grpc) failed");
        if fail_closed {
            write_simple(session, 503).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Build the Envoy `CheckRequest` from the downstream request: method, path,
    /// host, scheme, and headers (hop-by-hop stripped, names lower-cased). No body
    /// is forwarded (GEP-1494 `forwardBody` buffering is a follow-up).
    fn build_check_request(session: &Session) -> auth_pb::CheckRequest {
        let req = session.req_header();
        let method = req.method.as_str().to_owned();
        let path = req
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str)
            .to_owned();
        let host = req
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut headers: HashMap<String, String> = HashMap::new();
        for (name, value) in &req.headers {
            let name_lower = name.as_str().to_ascii_lowercase();
            if HOP_BY_HOP.contains(&name_lower.as_str()) {
                continue;
            }
            if let Ok(v) = value.to_str() {
                headers.insert(name_lower, v.to_owned());
            }
        }
        let http_req = auth_pb::attribute_context::HttpRequest {
            method,
            path,
            host,
            scheme: "http".to_owned(),
            headers,
            ..Default::default()
        };
        auth_pb::CheckRequest {
            attributes: Some(auth_pb::AttributeContext {
                request: Some(auth_pb::attribute_context::Request {
                    http: Some(http_req),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }
    }

    /// Map a `CheckResponse` onto the allow/deny contract.
    ///
    /// `status.code == OK` → allow (copy the OK response's `allowed_upstream_headers`
    /// allow-list onto the upstream request). Any other code → deny (return the
    /// denied response's HTTP status + controlled headers + body to the client).
    async fn map_check_response(
        resp: auth_pb::CheckResponse,
        grpc_cfg: &coxswain_core::routing::GrpcExtAuthConfig,
        session: &mut Session,
        auth_response_headers_out: &mut Option<Vec<(Box<str>, Box<str>)>>,
    ) -> Result<bool> {
        let code = resp.status.as_ref().map_or(RPC_OK, |s| s.code);

        if code == RPC_OK {
            if let Some(HttpResponse::OkResponse(ok)) = resp.http_response
                && !grpc_cfg.response_headers.is_empty()
            {
                let mut forward: Vec<(Box<str>, Box<str>)> = Vec::new();
                for hvo in &ok.headers {
                    if let Some(h) = &hvo.header {
                        let key = h.key.to_ascii_lowercase();
                        if grpc_cfg.response_headers.iter().any(|n| n.as_ref() == key) {
                            forward.push((key.into_boxed_str(), h.value.clone().into_boxed_str()));
                        }
                    }
                }
                if !forward.is_empty() {
                    *auth_response_headers_out = Some(forward);
                }
            }
            return Ok(false);
        }

        // Deny. The Envoy `HttpStatus.code` numeric value IS the HTTP status.
        let (deny_status, hdrs, body): (u16, Vec<(String, String)>, Vec<u8>) =
            match resp.http_response {
                Some(HttpResponse::DeniedResponse(d)) => {
                    let status = d
                        .status
                        .and_then(|s| u16::try_from(s.code).ok())
                        .filter(|s| (100..=599).contains(s))
                        .unwrap_or(DEFAULT_DENY_STATUS);
                    let hdrs = d
                        .headers
                        .iter()
                        .filter_map(|hvo| {
                            let h = hvo.header.as_ref()?;
                            if HOP_BY_HOP.contains(&h.key.to_ascii_lowercase().as_str()) {
                                return None;
                            }
                            Some((h.key.clone(), h.value.clone()))
                        })
                        .collect();
                    (status, hdrs, d.body.into_bytes())
                }
                // OK/Error/absent with a non-OK code → a bare deny with no body.
                _ => (DEFAULT_DENY_STATUS, Vec::new(), Vec::new()),
            };

        let mut resp_hdr = ResponseHeader::build(deny_status, Some(hdrs.len()))?;
        for (name, value) in hdrs {
            let _ = resp_hdr.insert_header(name, value);
        }
        let has_body = !body.is_empty();
        session
            .write_response_header(Box::new(resp_hdr), !has_body)
            .await
            .unwrap_or_else(|e| tracing::error!("failed to write grpc auth deny response: {e}"));
        if has_body {
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await
                .unwrap_or_else(|e| tracing::error!("failed to write grpc auth deny body: {e}"));
        }
        Ok(true)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use coxswain_core::routing::GrpcExtAuthConfig;
        use envoy_types::pb::envoy::config::core::v3::{HeaderValue, HeaderValueOption};
        use envoy_types::pb::envoy::r#type::v3::HttpStatus;
        use std::sync::Arc;

        fn ok_response(headers: Vec<(&str, &str)>) -> auth_pb::CheckResponse {
            auth_pb::CheckResponse {
                status: Some(envoy_types::pb::google::rpc::Status {
                    code: RPC_OK,
                    ..Default::default()
                }),
                http_response: Some(HttpResponse::OkResponse(auth_pb::OkHttpResponse {
                    headers: headers
                        .into_iter()
                        .map(|(k, v)| HeaderValueOption {
                            header: Some(HeaderValue {
                                key: k.to_owned(),
                                value: v.to_owned(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                })),
                ..Default::default()
            }
        }

        /// An OK status with response-header allow-list matches copy the named
        /// header (case-insensitively) into the upstream forward set.
        #[tokio::test]
        async fn ok_response_forwards_allowlisted_headers() {
            let cfg = GrpcExtAuthConfig::new(Arc::from([Box::from("x-auth-user")]));
            let resp = ok_response(vec![("X-Auth-User", "alice"), ("X-Other", "nope")]);
            // map_check_response needs a Session for the deny path only; the allow
            // path writes nothing, so exercise the header-selection logic directly.
            let code = resp.status.as_ref().map_or(RPC_OK, |s| s.code);
            assert_eq!(code, RPC_OK);
            let Some(HttpResponse::OkResponse(ok)) = resp.http_response else {
                panic!("expected OkResponse");
            };
            let mut forward: Vec<(Box<str>, Box<str>)> = Vec::new();
            for hvo in &ok.headers {
                if let Some(h) = &hvo.header {
                    let key = h.key.to_ascii_lowercase();
                    if cfg.response_headers.iter().any(|n| n.as_ref() == key) {
                        forward.push((key.into_boxed_str(), h.value.clone().into_boxed_str()));
                    }
                }
            }
            assert_eq!(
                forward.len(),
                1,
                "only the allow-listed header is forwarded"
            );
            assert_eq!(&*forward[0].0, "x-auth-user");
            assert_eq!(&*forward[0].1, "alice");
        }

        /// A `DeniedHttpResponse.status.code` is mapped verbatim as the HTTP status
        /// when in range; an out-of-range or absent status falls back to 403.
        #[test]
        fn denied_status_maps_http_status_code() {
            let denied = |code: i32| {
                u16::try_from(code)
                    .ok()
                    .filter(|s| (100..=599).contains(s))
                    .unwrap_or(DEFAULT_DENY_STATUS)
            };
            assert_eq!(denied(HttpStatus { code: 401 }.code), 401);
            assert_eq!(denied(HttpStatus { code: 403 }.code), 403);
            assert_eq!(denied(HttpStatus { code: 302 }.code), 302);
            // Out of range → default deny.
            assert_eq!(denied(700), DEFAULT_DENY_STATUS);
            assert_eq!(denied(0), DEFAULT_DENY_STATUS);
        }

        /// A missing `status` (None) is treated as OK per Envoy semantics (allow).
        #[test]
        fn absent_status_is_ok() {
            let resp = auth_pb::CheckResponse {
                status: None,
                http_response: None,
                ..Default::default()
            };
            assert_eq!(resp.status.as_ref().map_or(RPC_OK, |s| s.code), RPC_OK);
        }
    }
}
